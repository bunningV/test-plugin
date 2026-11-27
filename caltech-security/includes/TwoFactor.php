<?php

namespace CaltechSecurity;

if (! defined('ABSPATH')) {
    exit;
}

/**
 * Mandatory two-factor authentication, enforced on the server in three layers.
 *
 * 1. The password step cannot finish a login. A late `authenticate` filter turns a correct password
 *    into a {@see Challenge} and redirects to the verification screen. No auth cookie is issued, so
 *    there is nothing to carry to another URL.
 *
 * 2. A session only counts if it was verified. When verification succeeds the session token — which
 *    WordPress keeps server-side, in user meta — is stamped. On every request a signed-in user whose
 *    session lacks the stamp is treated as signed out. That is what makes the rest of the rules hold:
 *      - a cookie minted by anything else (another plugin calling wp_set_auth_cookie(), a login form on
 *        the front end, an old session from before enforcement) is inert;
 *      - the stamp is not in the cookie, so it cannot be forged or copied by editing the cookie.
 *    Wrong-password-style "alternative endpoints" are closed the same way: XML-RPC and front-end
 *    wp_signon() calls are refused outright. Application passwords never reach a screen that can ask
 *    for a code, so they are off for an account that has set 2FA up, and for every account while the
 *    "require for everyone" switch is on.
 *
 * The switch is not what turns 2FA on for one person. An account that has already paired an
 * authenticator is asked for a code at every later sign-in. The switch adds the accounts that have
 * not: they are walked through setup and cannot finish a login without it.
 *
 * 3. wp-admin checks again. auth_redirect() trusts the auth cookie on its own, so it is hooked too.
 *
 * Trusted single sign-on (the Caltech Connector's signed login) opts in through the
 * `caltech_security_trust_login` filter: it has already authenticated the person with Caltech's own
 * sign-in, and it is the only way to count as verified without a code.
 */
final class TwoFactor
{
    /** Session-token key that marks a session as having passed verification. */
    public const STAMP = 'caltech_2fa';

    /** @var array<int, true> users verified during this request, before their cookie exists */
    private static array $granted = [];

    /** Signed-in user (verified session) this request is acting as; lets a re-issued cookie keep its stamp. */
    private static int $verifiedUser = 0;

    public function __construct(private Plugin $plugin) {}

    public function register(): void
    {
        if ($this->plugin->twoFactorDisabledByConfig()) {
            return;
        }

        add_filter('authenticate', [$this, 'gate'], 100, 3);
        add_filter('attach_session_information', [$this, 'stamp'], 20, 2);
        // Be the final authority after cookie, application-password, JWT, OAuth and other custom
        // authenticators. Priority 99 was not final: a later determine_current_user filter could
        // establish an unstamped user after our guard had already run.
        add_filter('determine_current_user', [$this, 'guard'], PHP_INT_MAX);
        // REST authentication has its own error pipeline. Check there as well so a bearer/JWT plugin
        // cannot authenticate a request without a WordPress session that passed this plugin's 2FA.
        add_filter('rest_authentication_errors', [$this, 'guardRestRequest'], PHP_INT_MAX);
        add_action('auth_redirect', [$this, 'onAuthRedirect']);
        add_action('login_form_caltech_2fa', [$this, 'screen']);
        add_filter('login_message', [$this, 'loginNotice']);
        add_filter('wp_is_application_passwords_available', [$this, 'applicationPasswords']);
        add_filter('wp_is_application_passwords_available_for_user', [$this, 'applicationPasswordsForUser'], 10, 2);
    }

    /** Site-wide enforcement covers every account. Otherwise only accounts that have set 2FA up are covered. */
    private function requiresFactor(int $userId): bool
    {
        return $this->plugin->twoFactorEnforced() || UserFactor::isEnrolled($userId);
    }

    // ── Layer 1: the password step ──────────────────────────────────────────

    /**
     * @param  \WP_User|\WP_Error|null  $user
     * @param  string  $username
     * @param  string  $password
     * @return \WP_User|\WP_Error|null
     */
    public function gate($user, $username = '', $password = '')
    {
        if (! $user instanceof \WP_User) {
            return $user; // not authenticated, or already an error: nothing to gate
        }

        if (! $this->requiresFactor($user->ID)) {
            return $user;
        }

        $hasCredentials = (string) $username !== '' && (string) $password !== '';

        if (! $hasCredentials) {
            // wp_signon() with no credentials re-authenticates from an existing cookie. That is fine for
            // a verified session; it must not turn an unverified one into a login.
            return self::sessionVerified($user->ID)
                ? $user
                : new \WP_Error('caltech_security_2fa', __('Your session needs to be verified. Please sign in again.', 'caltech-security'));
        }

        if (! LoginUrl::isLoginRequest()) {
            // XML-RPC, or a login form some plugin built on the front end: there is no place to ask for a code.
            return new \WP_Error(
                'caltech_security_2fa',
                __('This account requires two-factor authentication. Sign in through the login page.', 'caltech-security')
            );
        }

        if (! Crypto::available()) {
            return new \WP_Error('caltech_security_2fa', __('Two-factor authentication cannot run on this server (no encryption support). Sign-in is refused.', 'caltech-security'));
        }

        $this->beginChallenge($user);

        return $user; // not reached: beginChallenge() redirects and exits
    }

    private function beginChallenge(\WP_User $user): void
    {
        $enrolled = UserFactor::isEnrolled($user->ID);

        $redirect = isset($_REQUEST['redirect_to']) ? (string) wp_validate_redirect(wp_unslash($_REQUEST['redirect_to']), '') : '';

        $data = [
            'user' => $user->ID,
            'mode' => $enrolled ? 'verify' : 'enroll',
            'remember' => ! empty($_POST['rememberme']),
            'redirect' => $redirect,
            'interim' => isset($_REQUEST['interim-login']),
        ];
        if (! $enrolled) {
            $data['secret'] = Crypto::encrypt(Totp::generateSecret());
        }

        Challenge::create($data);

        wp_safe_redirect(LoginUrl::url(['action' => 'caltech_2fa'] + ($data['interim'] ? ['interim-login' => 1] : [])));
        exit;
    }

    // ── The verification screen ─────────────────────────────────────────────

    public function screen(): void
    {
        $held = Challenge::current();

        if (isset($_GET['cancel'])) {
            if ($held !== null) {
                Challenge::destroy($held[0]);
            }
            wp_safe_redirect(LoginUrl::url());
            exit;
        }

        if ($held === null) {
            wp_safe_redirect(LoginUrl::url(['caltech_security' => 'expired']));
            exit;
        }

        [$token, $data] = $held;
        $user = get_userdata((int) $data['user']);
        if (! $user instanceof \WP_User) {
            Challenge::destroy($token);
            wp_safe_redirect(LoginUrl::url());
            exit;
        }

        $error = '';
        if (isset($_SERVER['REQUEST_METHOD']) && $_SERVER['REQUEST_METHOD'] === 'POST') {
            $error = $this->submit($token, $data, $user);
        }

        $this->renderForm($data, $user, $error);
        exit;
    }

    /**
     * @param  array<string, mixed>  $data
     * @return string  an error message to show; a correct code never returns (it signs the user in and redirects)
     */
    private function submit(string $token, array $data, \WP_User $user): string
    {
        if (UserFactor::locked($user->ID)) {
            return __('Too many incorrect codes. Wait a few minutes and try again.', 'caltech-security');
        }

        $code = isset($_POST['caltech_code']) ? trim((string) wp_unslash($_POST['caltech_code'])) : '';
        $digits = preg_replace('/\s+/', '', $code) ?? '';
        $recoveryCodes = null;
        $ok = false;

        if (($data['mode'] ?? '') === 'enroll') {
            $secret = Crypto::decrypt((string) ($data['secret'] ?? ''));
            if ($secret !== null && Totp::verify($secret, $digits, $step)) {
                $recoveryCodes = UserFactor::enroll($user->ID, $secret, (int) $step);
                $ok = true;
            }
        } elseif (preg_match('/^\d{6}$/', $digits)) {
            $ok = UserFactor::verifyTotp($user->ID, $digits);
        } else {
            $ok = UserFactor::consumeRecovery($user->ID, $code);
        }

        if (! $ok) {
            UserFactor::registerFailure($user->ID);
            $data['attempts'] = (int) ($data['attempts'] ?? 0) + 1;

            if ($data['attempts'] >= Challenge::MAX_ATTEMPTS) {
                Challenge::destroy($token);
                wp_safe_redirect(LoginUrl::url(['caltech_security' => 'attempts']));
                exit;
            }

            Challenge::save($token, $data);

            return __('That code is not correct. Try again.', 'caltech-security');
        }

        UserFactor::clearFailures($user->ID);
        $this->complete($token, $data, $user, $recoveryCodes);

        return '';
    }

    /**
     * @param  array<string, mixed>  $data
     * @param  list<string>|null  $recoveryCodes  set when the user has just enrolled; shown once before continuing
     */
    private function complete(string $token, array $data, \WP_User $user, ?array $recoveryCodes): void
    {
        Challenge::destroy($token);

        // From here the session this creates is stamped as verified (see stamp()).
        self::$granted[$user->ID] = true;

        $remember = ! empty($data['remember']);
        $secure = (bool) apply_filters('secure_signon_cookie', Plugin::secureCookies(), ['user_login' => $user->user_login, 'remember' => $remember]);

        wp_set_auth_cookie($user->ID, $remember, $secure);
        wp_set_current_user($user->ID);
        do_action('wp_login', $user->user_login, $user);

        $destination = $this->destination($data, $user);

        if ($recoveryCodes !== null) {
            $this->renderRecoveryCodes($recoveryCodes, $destination);
            exit;
        }

        wp_safe_redirect($destination);
        exit;
    }

    /** @param  array<string, mixed>  $data */
    private function destination(array $data, \WP_User $user): string
    {
        if (! empty($data['interim'])) {
            return LoginUrl::url(['interim-login' => 1]);
        }

        $requested = (string) ($data['redirect'] ?? '');
        $target = $requested !== '' ? $requested : admin_url();

        // Same landing rule as wp-login.php: people who cannot use the dashboard go to their profile.
        if ($requested === '' && ! user_can($user, 'edit_posts')) {
            $target = user_can($user, 'read') ? admin_url('profile.php') : home_url();
        }

        return (string) apply_filters('login_redirect', $target, $requested, $user);
    }

    // ── Rendering ───────────────────────────────────────────────────────────

    /** @param  array<string, mixed>  $data */
    private function renderForm(array $data, \WP_User $user, string $error): void
    {
        $enroll = ($data['mode'] ?? '') === 'enroll';
        $action = LoginUrl::url(['action' => 'caltech_2fa'] + (! empty($data['interim']) ? ['interim-login' => 1] : []));

        $message = '';
        if ($enroll) {
            $secret = (string) Crypto::decrypt((string) ($data['secret'] ?? ''));
            $message = '<p class="message">' . esc_html__('Your administrator requires two-factor authentication. Set it up now to finish signing in.', 'caltech-security') . '</p>';
            $message .= self::setupBlock($secret, $user);
        } else {
            $message = '<p class="message">' . esc_html__('Enter the 6-digit code from your authenticator app. Lost your device? Enter one of your recovery codes instead.', 'caltech-security') . '</p>';
        }

        $errors = $error !== '' ? new \WP_Error('caltech_security_code', $error) : null;
        login_header($enroll ? __('Set up two-factor authentication', 'caltech-security') : __('Verification code', 'caltech-security'), $message, $errors);
        ?>
        <form name="caltech_2fa_form" id="loginform" action="<?php echo esc_url($action); ?>" method="post" autocomplete="off">
            <p>
                <label for="caltech_code"><?php echo $enroll ? esc_html__('Code from your app', 'caltech-security') : esc_html__('Verification or recovery code', 'caltech-security'); ?></label>
                <input type="text" name="caltech_code" id="caltech_code" class="input" value="" size="20"
                       autocomplete="one-time-code" autocapitalize="off" spellcheck="false" <?php echo $enroll ? 'inputmode="numeric"' : ''; ?> />
            </p>
            <p class="submit">
                <input type="submit" class="button button-primary button-large" value="<?php echo $enroll ? esc_attr__('Confirm and sign in', 'caltech-security') : esc_attr__('Verify', 'caltech-security'); ?>" />
            </p>
        </form>
        <p id="nav"><a href="<?php echo esc_url(LoginUrl::url(['action' => 'caltech_2fa', 'cancel' => 1])); ?>"><?php esc_html_e('Cancel and start again', 'caltech-security'); ?></a></p>
        <?php
        echo self::qrScripts();
        login_footer('caltech_code');
    }

    /**
     * @param  list<string>  $codes
     */
    private function renderRecoveryCodes(array $codes, string $continueUrl): void
    {
        $message = '<p class="message">' . esc_html__('Two-factor authentication is on. Save these recovery codes somewhere safe — each works once if you lose your device. They will not be shown again.', 'caltech-security') . '</p>';

        login_header(__('Save your recovery codes', 'caltech-security'), $message);
        echo self::recoveryCodesMarkup($codes);
        ?>
        <p class="submit" style="margin-top:16px"><a class="button button-primary button-large" href="<?php echo esc_url($continueUrl); ?>"><?php esc_html_e('I have saved them — continue', 'caltech-security'); ?></a></p>
        <?php
        login_footer();
    }

    /**
     * Setup instructions: QR code, plus the key to type when scanning is not possible.
     */
    public static function setupBlock(string $secret, \WP_User $user): string
    {
        $issuer = (string) wp_specialchars_decode(get_bloginfo('name'), ENT_QUOTES);
        $issuer = $issuer !== '' ? $issuer : 'WordPress';
        $uri = Totp::otpauthUri($secret, $user->user_login, $issuer);

        return '<div style="background:#fff;padding:16px;border:1px solid #c3c4c7;margin:0 0 16px;text-align:center">'
            . '<p style="margin:0 0 8px">' . esc_html__('1. Scan this code with an authenticator app (Google Authenticator, Authy, 1Password, …).', 'caltech-security') . '</p>'
            . '<div data-caltech-qr="' . esc_attr($uri) . '" style="width:200px;height:200px;margin:0 auto"></div>'
            . '<p style="margin:12px 0 4px">' . esc_html__('Cannot scan? Enter this key instead:', 'caltech-security') . '</p>'
            . '<code style="font-size:14px;word-break:break-all;user-select:all">' . esc_html(Totp::formatSecret($secret)) . '</code>'
            . '<p style="margin:12px 0 0">' . esc_html__('2. Enter the 6-digit code the app shows.', 'caltech-security') . '</p>'
            . '</div>';
    }

    /** @param  list<string>  $codes */
    public static function recoveryCodesMarkup(array $codes): string
    {
        $items = '';
        foreach ($codes as $code) {
            $items .= '<li style="font-family:monospace;font-size:15px;letter-spacing:1px">' . esc_html($code) . '</li>';
        }

        return '<ul style="columns:2;list-style:none;margin:0 0 8px;padding:12px 16px;background:#fff;border:1px solid #c3c4c7;user-select:all">' . $items . '</ul>';
    }

    public static function qrScripts(): string
    {
        $version = rawurlencode(CALTECH_SECURITY_VERSION);

        return '<script src="' . esc_url(CALTECH_SECURITY_URL . 'assets/qrcode.js?ver=' . $version) . '"></script>'
            . '<script src="' . esc_url(CALTECH_SECURITY_URL . 'assets/qr-render.js?ver=' . $version) . '"></script>';
    }

    /**
     * @param  string  $message
     */
    public function loginNotice($message): string
    {
        $flag = isset($_GET['caltech_security']) ? sanitize_key(wp_unslash($_GET['caltech_security'])) : '';
        $text = [
            'expired' => __('Your verification step expired. Sign in again.', 'caltech-security'),
            'attempts' => __('Too many incorrect codes. Sign in again.', 'caltech-security'),
        ][$flag] ?? '';

        if ($text !== '') {
            $message .= '<div id="login_error" class="notice notice-error"><p>' . esc_html($text) . '</p></div>';
        }

        return (string) $message;
    }

    // ── Layer 2: only verified sessions count ───────────────────────────────

    /**
     * Stamp a session as verified when it is created for a user who just passed verification, who is
     * already acting from a verified session (cookie refresh, password change), or whom a trusted
     * integration vouches for.
     *
     * @param  array<string, mixed>  $info
     * @param  int  $userId
     * @return array<string, mixed>
     */
    public function stamp($info, $userId): array
    {
        $info = is_array($info) ? $info : [];
        $userId = (int) $userId;

        $verified = isset(self::$granted[$userId])
            || self::$verifiedUser === $userId
            || (bool) apply_filters('caltech_security_trust_login', false, $userId);

        if ($verified) {
            $info[self::STAMP] = time();
        }

        return $info;
    }

    /**
     * Anyone who is signed in without a verified session is signed out.
     *
     * @param  int|false  $userId
     * @return int|false
     */
    public function guard($userId)
    {
        if (! $userId) {
            return $userId;
        }

        $userId = (int) $userId;

        if (! $this->requiresFactor($userId)) {
            return $userId;
        }

        if (self::sessionVerified($userId)) {
            self::$verifiedUser = $userId;

            return $userId;
        }

        if ((bool) apply_filters('caltech_security_allow_unverified', false, $userId)) {
            return $userId;
        }

        // An unverified session has no further use; do not leave it lying around.
        $token = wp_get_session_token();
        if ($token !== '') {
            \WP_Session_Tokens::get_instance($userId)->destroy($token);
        }

        return false;
    }

    /**
     * REST can be authenticated by plugins that do not create a WordPress cookie session. Mandatory
     * 2FA cannot verify those credentials, so reject them unless an integration explicitly opts into
     * the same trusted-auth boundary used by Caltech SSO.
     *
     * @param  mixed  $result  null/true on success so far, or an existing WP_Error
     * @return mixed
     */
    public function guardRestRequest($result)
    {
        if ($result instanceof \WP_Error) {
            return $result;
        }

        $userId = get_current_user_id();
        if ($userId === 0
            || ! $this->requiresFactor($userId)
            || self::sessionVerified($userId)
            || (bool) apply_filters('caltech_security_allow_unverified', false, $userId)) {
            return $result;
        }

        return new \WP_Error(
            'caltech_security_2fa_required',
            __('This authentication method has not completed two-factor authentication.', 'caltech-security'),
            ['status' => 401]
        );
    }

    public function onAuthRedirect($userId): void
    {
        $userId = (int) $userId;

        if (! $this->requiresFactor($userId) || self::sessionVerified($userId) || (bool) apply_filters('caltech_security_allow_unverified', false, $userId)) {
            return;
        }

        $token = wp_get_session_token();
        if ($token !== '') {
            \WP_Session_Tokens::get_instance($userId)->destroy($token);
        }
        wp_clear_auth_cookie();
        wp_set_current_user(0);

        if ($this->plugin->loginUrlActive()) {
            LoginUrl::notFound();
        }

        wp_safe_redirect(LoginUrl::url());
        exit;
    }

    /** Whether the session behind the request's login cookie carries the verified stamp. */
    public static function sessionVerified(int $userId): bool
    {
        $token = wp_get_session_token();
        if ($token === '') {
            return false;
        }

        $session = \WP_Session_Tokens::get_instance($userId)->get($token);

        return is_array($session) && ! empty($session[self::STAMP]);
    }

    /**
     * @param  bool  $available
     */
    public function applicationPasswords($available): bool
    {
        return $this->plugin->twoFactorEnforced() ? false : (bool) $available;
    }

    /**
     * An account that paired an authenticator cannot sign in with an application password: that
     * password never reaches a screen that can ask for the code. Accounts without 2FA are unchanged
     * until the site-wide switch turns application passwords off for everyone.
     *
     * @param  bool  $available
     * @param  \WP_User  $user
     */
    public function applicationPasswordsForUser($available, $user): bool
    {
        if ($user instanceof \WP_User && UserFactor::isEnrolled($user->ID)) {
            return false;
        }

        return (bool) $available;
    }

    /**
     * Mark the signed-in user's current session as verified. Used when an administrator turns
     * enforcement on from the settings page: they just proved a code to enrol, and should not be
     * thrown out by the switch they flipped.
     */
    public static function stampCurrentSession(int $userId): void
    {
        $token = wp_get_session_token();
        if ($token === '') {
            return;
        }

        $manager = \WP_Session_Tokens::get_instance($userId);
        $session = $manager->get($token);
        if (is_array($session)) {
            $session[self::STAMP] = time();
            $manager->update($token, $session);
        }
    }
}
