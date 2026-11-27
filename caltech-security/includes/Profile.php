<?php

namespace CaltechSecurity;

if (! defined('ABSPATH')) {
    exit;
}

/**
 * A person's own two-factor settings.
 *
 * The profile screen only shows status and links here: its whole body is one <form>, and forms do not
 * nest, so the setup forms live on their own small screen (admin.php?page=caltech-security-2fa),
 * reachable by every signed-in user — not only those who can manage the plugin.
 */
final class Profile
{
    public const PAGE = 'caltech-security-2fa';

    private const CODES_TRANSIENT = 'caltech_sec_codes_';

    public function __construct(private Plugin $plugin) {}

    public function register(): void
    {
        add_action('admin_menu', [$this, 'registerPage']);
        add_action('admin_enqueue_scripts', [$this, 'assets']);
        add_action('show_user_profile', [$this, 'profileSection'], 20);
        add_action('edit_user_profile', [$this, 'profileSection'], 20);

        add_action('admin_post_caltech_security_setup_start', [$this, 'handleSetupStart']);
        add_action('admin_post_caltech_security_setup_confirm', [$this, 'handleSetupConfirm']);
        add_action('admin_post_caltech_security_recovery', [$this, 'handleRecovery']);
        add_action('admin_post_caltech_security_reset', [$this, 'handleReset']);
    }

    public static function pageUrl(array $args = []): string
    {
        return add_query_arg(array_merge(['page' => self::PAGE], $args), admin_url('admin.php'));
    }

    public static function resetUrl(int $userId): string
    {
        return wp_nonce_url(admin_url('admin-post.php?action=caltech_security_reset&user=' . $userId), 'caltech_security_reset_' . $userId);
    }

    public function assets(string $hook): void
    {
        unset($hook);
        $page = isset($_GET['page']) ? sanitize_key(wp_unslash($_GET['page'])) : '';
        if ($page !== self::PAGE) {
            return;
        }

        wp_enqueue_style('caltech-security-admin', CALTECH_SECURITY_URL . 'assets/admin.css', [], CALTECH_SECURITY_VERSION);
    }

    public function registerPage(): void
    {
        // Parent 'options.php' registers the page without putting it in any menu.
        add_submenu_page(
            'options.php',
            __('Two-factor authentication', 'caltech-security'),
            __('Two-factor authentication', 'caltech-security'),
            'read',
            self::PAGE,
            [$this, 'renderPage']
        );
    }

    // ── Profile screen: status only ─────────────────────────────────────────

    /** @param  \WP_User  $user */
    public function profileSection($user): void
    {
        if (! $user instanceof \WP_User) {
            return;
        }

        $own = $user->ID === get_current_user_id();
        $enrolled = UserFactor::isEnrolled($user->ID);
        ?>
        <h2 id="caltech-security-2fa"><?php esc_html_e('Two-factor authentication', 'caltech-security'); ?></h2>
        <table class="form-table" role="presentation">
            <tr>
                <th><?php esc_html_e('Status', 'caltech-security'); ?></th>
                <td>
                    <?php if ($enrolled) : ?>
                        <span style="color:#1a7f37">● <?php esc_html_e('Enabled', 'caltech-security'); ?></span>
                        <span class="description">— <?php
                            /* translators: %d: number of unused recovery codes */
                            echo esc_html(sprintf(_n('%d recovery code left', '%d recovery codes left', UserFactor::recoveryRemaining($user->ID), 'caltech-security'), UserFactor::recoveryRemaining($user->ID)));
                        ?></span>
                    <?php else : ?>
                        <span style="color:#b32d2e">● <?php esc_html_e('Not set up', 'caltech-security'); ?></span>
                    <?php endif; ?>

                    <?php if ($own) : ?>
                        <p><a class="button" href="<?php echo esc_url(self::pageUrl()); ?>"><?php echo $enrolled ? esc_html__('View two-factor authentication', 'caltech-security') : esc_html__('Set up two-factor authentication', 'caltech-security'); ?></a></p>
                    <?php elseif ($enrolled && current_user_can('edit_user', $user->ID)) : ?>
                        <p>
                            <a class="button" href="<?php echo esc_url(self::resetUrl($user->ID)); ?>"
                               onclick="return confirm('<?php echo esc_js(__('Reset two-factor authentication for this user? They will be signed out and asked to set it up again.', 'caltech-security')); ?>');"><?php esc_html_e('Reset two-factor authentication', 'caltech-security'); ?></a>
                        </p>
                    <?php endif; ?>
                </td>
            </tr>
        </table>
        <?php
    }

    // ── The setup screen ────────────────────────────────────────────────────

    public function renderPage(): void
    {
        $user = wp_get_current_user();
        $enrolled = UserFactor::isEnrolled($user->ID);
        $view = isset($_GET['caltech_2fa']) ? sanitize_key(wp_unslash($_GET['caltech_2fa'])) : '';
        $error = isset($_GET['caltech_2fa_error']) ? sanitize_key(wp_unslash($_GET['caltech_2fa_error'])) : '';
        $done = isset($_GET['caltech_2fa_done']) ? sanitize_key(wp_unslash($_GET['caltech_2fa_done'])) : '';

        $messages = [
            'code' => __('That code is not correct.', 'caltech-security'),
            'locked' => __('Too many incorrect codes. Wait a few minutes and try again.', 'caltech-security'),
            'nopending' => __('Setup expired. Start again.', 'caltech-security'),
            'crypto' => __('Two-factor authentication cannot run on this server (no encryption support).', 'caltech-security'),
        ];
        $successes = [
            'reset' => __('Two-factor authentication was reset for that user.', 'caltech-security'),
        ];
        ?>
        <div class="wrap">
            <h1><?php esc_html_e('Two-factor authentication', 'caltech-security'); ?></h1>

            <?php if (isset($messages[$error])) : ?>
                <div class="notice notice-error"><p><?php echo esc_html($messages[$error]); ?></p></div>
            <?php endif; ?>
            <?php if (isset($successes[$done])) : ?>
                <div class="notice notice-success"><p><?php echo esc_html($successes[$done]); ?></p></div>
            <?php endif; ?>

            <?php
            if ($view === 'codes') {
                $this->renderCodes($user->ID);
            } elseif ($view === 'setup' && ($secret = UserFactor::pendingSecret($user->ID)) !== null) {
                $this->renderSetup($user, $secret);
            } elseif ($view === 'manage' && $enrolled) {
                $this->renderManage($user);
            } elseif ($enrolled) {
                $this->renderReady($user);
            } else {
                $this->renderStart();
            }
            ?>
        </div>
        <?php
    }

    private function renderStart(): void
    {
        ?>
        <p><?php esc_html_e('Two-factor authentication adds a code from an authenticator app to your password. It is not set up for your account yet.', 'caltech-security'); ?></p>
        <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
            <?php wp_nonce_field('caltech_security_setup_start'); ?>
            <input type="hidden" name="action" value="caltech_security_setup_start">
            <?php submit_button(__('Set up two-factor authentication', 'caltech-security'), 'primary', 'submit', false); ?>
        </form>
        <?php
    }

    private function renderSetup(\WP_User $user, string $secret): void
    {
        wp_enqueue_script('caltech-security-qrcode', CALTECH_SECURITY_URL . 'assets/qrcode.js', [], CALTECH_SECURITY_VERSION, true);
        wp_enqueue_script('caltech-security-qr', CALTECH_SECURITY_URL . 'assets/qr-render.js', ['caltech-security-qrcode'], CALTECH_SECURITY_VERSION, true);
        ?>
        <div style="max-width:420px">
            <?php echo TwoFactor::setupBlock($secret, $user); // phpcs:ignore WordPress.Security.EscapeOutput -- escaped inside ?>
            <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" autocomplete="off">
                <?php wp_nonce_field('caltech_security_setup_confirm'); ?>
                <input type="hidden" name="action" value="caltech_security_setup_confirm">
                <p>
                    <label for="caltech_code"><strong><?php esc_html_e('Code from your app', 'caltech-security'); ?></strong></label><br>
                    <input type="text" name="caltech_code" id="caltech_code" class="regular-text" inputmode="numeric" autocomplete="one-time-code" required autofocus>
                </p>
                <div class="caltech-sec-actions">
                    <?php submit_button(__('Confirm and turn on', 'caltech-security'), 'primary', 'submit', false); ?>
                    <a class="button" href="<?php echo esc_url(self::pageUrl()); ?>"><?php esc_html_e('Cancel', 'caltech-security'); ?></a>
                </div>
            </form>
        </div>
        <?php
    }

    /** The page someone lands on once setup is finished. Nothing here asks for another code. */
    private function renderReady(\WP_User $user): void
    {
        $remaining = UserFactor::recoveryRemaining($user->ID);
        ?>
        <div class="notice notice-success inline"><p><?php esc_html_e('Two-factor authentication is on. Setup is finished.', 'caltech-security'); ?></p></div>
        <p><?php esc_html_e('The next time you sign in, enter your password and then the 6-digit code from your authenticator app.', 'caltech-security'); ?></p>
        <p><?php
            /* translators: %d: number of unused recovery codes */
            echo esc_html(sprintf(_n('You have %d recovery code left.', 'You have %d recovery codes left.', $remaining, 'caltech-security'), $remaining));
        ?> <?php esc_html_e('Keep the ones you saved. They are not shown again.', 'caltech-security'); ?></p>
        <p>
            <a class="button button-primary" href="<?php echo esc_url(admin_url()); ?>"><?php esc_html_e('Back to the dashboard', 'caltech-security'); ?></a>
        </p>
        <p><a href="<?php echo esc_url(self::pageUrl(['caltech_2fa' => 'manage'])); ?>"><?php esc_html_e('Lost your codes, or moving to a different device?', 'caltech-security'); ?></a></p>
        <?php
        unset($user);
    }

    private function renderManage(\WP_User $user): void
    {
        unset($user);
        ?>
        <p><?php esc_html_e('Your authenticator keeps working. Use one of these only if you need to replace your recovery codes or move to a different app.', 'caltech-security'); ?></p>
        <p><a href="<?php echo esc_url(self::pageUrl()); ?>"><?php esc_html_e('Back', 'caltech-security'); ?></a></p>

        <h2><?php esc_html_e('Replace recovery codes', 'caltech-security'); ?></h2>
        <p><?php esc_html_e('This throws away the codes you have and shows a new set once. Enter the 6-digit code your app shows right now.', 'caltech-security'); ?></p>
        <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" autocomplete="off">
            <?php wp_nonce_field('caltech_security_recovery'); ?>
            <input type="hidden" name="action" value="caltech_security_recovery">
            <label for="caltech_recovery_code" class="screen-reader-text"><?php esc_html_e('Code from your authenticator app', 'caltech-security'); ?></label>
            <input type="text" name="current_code" id="caltech_recovery_code" class="regular-text" inputmode="numeric" autocomplete="one-time-code" required>
            <?php submit_button(__('Generate new recovery codes', 'caltech-security'), 'secondary', 'submit', false); ?>
        </form>

        <h2><?php esc_html_e('Move to a different device', 'caltech-security'); ?></h2>
        <p><?php esc_html_e('The app you use now stops working only after you confirm the new one. Enter the 6-digit code it shows right now to begin.', 'caltech-security'); ?></p>
        <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" autocomplete="off">
            <?php wp_nonce_field('caltech_security_setup_start'); ?>
            <input type="hidden" name="action" value="caltech_security_setup_start">
            <label for="caltech_device_code" class="screen-reader-text"><?php esc_html_e('Code from your authenticator app', 'caltech-security'); ?></label>
            <input type="text" name="current_code" id="caltech_device_code" class="regular-text" inputmode="numeric" autocomplete="one-time-code" required>
            <?php submit_button(__('Set up a new device', 'caltech-security'), 'secondary', 'submit', false); ?>
        </form>
        <?php
    }

    private function renderCodes(int $userId): void
    {
        $stored = get_transient(self::CODES_TRANSIENT . $userId);
        delete_transient(self::CODES_TRANSIENT . $userId); // shown once

        $codes = null;
        if (is_string($stored) && ($json = Crypto::decrypt($stored)) !== null) {
            $decoded = json_decode($json, true);
            $codes = is_array($decoded) ? array_values(array_filter($decoded, 'is_string')) : null;
        }

        if ($codes === null || $codes === []) {
            echo '<p>' . esc_html__('Your recovery codes are only shown once, right after they are created, and that has already happened.', 'caltech-security') . '</p>';
            echo '<p><a class="button" href="' . esc_url(self::pageUrl()) . '">' . esc_html__('Back', 'caltech-security') . '</a></p>';

            return;
        }
        ?>
        <div class="notice notice-warning inline"><p><?php esc_html_e('Save these recovery codes somewhere safe. Each one works once if you lose your device. They will not be shown again.', 'caltech-security'); ?></p></div>
        <div style="max-width:420px"><?php echo TwoFactor::recoveryCodesMarkup($codes); // phpcs:ignore WordPress.Security.EscapeOutput -- escaped inside ?></div>
        <p><a class="button button-primary" href="<?php echo esc_url(self::pageUrl()); ?>"><?php esc_html_e('I have saved them', 'caltech-security'); ?></a></p>
        <?php
    }

    // ── Handlers ────────────────────────────────────────────────────────────

    public function handleSetupStart(): void
    {
        $user = $this->requireOwnAction('caltech_security_setup_start');

        if (! Crypto::available()) {
            $this->back(['caltech_2fa_error' => 'crypto']);
        }

        // Changing the device of an enrolled account needs proof of the current one.
        if (UserFactor::isEnrolled($user->ID) && ! $this->currentCodeAccepted($user->ID)) {
            $this->back(['caltech_2fa' => 'manage', 'caltech_2fa_error' => UserFactor::locked($user->ID) ? 'locked' : 'code']);
        }

        UserFactor::startPending($user->ID);
        $this->back(['caltech_2fa' => 'setup']);
    }

    public function handleSetupConfirm(): void
    {
        $user = $this->requireOwnAction('caltech_security_setup_confirm');

        $secret = UserFactor::pendingSecret($user->ID);
        if ($secret === null) {
            $this->back(['caltech_2fa_error' => 'nopending']);
        }
        if (UserFactor::locked($user->ID)) {
            $this->back(['caltech_2fa' => 'setup', 'caltech_2fa_error' => 'locked']);
        }

        $code = preg_replace('/\s+/', '', isset($_POST['caltech_code']) ? (string) wp_unslash($_POST['caltech_code']) : '') ?? '';
        if (! Totp::verify($secret, $code, $step)) {
            UserFactor::registerFailure($user->ID);
            $this->back(['caltech_2fa' => 'setup', 'caltech_2fa_error' => 'code']);
        }

        $codes = UserFactor::enroll($user->ID, $secret, (int) $step);
        // They proved the code just now. Keep this session; the next sign-in is the one that asks again.
        TwoFactor::stampCurrentSession($user->ID);
        $this->stashCodes($user->ID, $codes);
        $this->back(['caltech_2fa' => 'codes']);
    }

    public function handleRecovery(): void
    {
        $user = $this->requireOwnAction('caltech_security_recovery');

        if (! UserFactor::isEnrolled($user->ID) || ! $this->currentCodeAccepted($user->ID)) {
            $this->back(['caltech_2fa' => 'manage', 'caltech_2fa_error' => UserFactor::locked($user->ID) ? 'locked' : 'code']);
        }

        $this->stashCodes($user->ID, UserFactor::regenerateRecoveryCodes($user->ID));
        $this->back(['caltech_2fa' => 'codes']);
    }

    /** Reset somebody else's second factor: they are signed out and must set it up again at next sign-in. */
    public function handleReset(): void
    {
        $target = isset($_GET['user']) ? absint($_GET['user']) : 0;
        check_admin_referer('caltech_security_reset_' . $target);

        if ($target === 0 || $target === get_current_user_id() || ! current_user_can('edit_user', $target)) {
            wp_die(esc_html__('You are not allowed to do that.', 'caltech-security'), '', ['response' => 403]);
        }

        UserFactor::reset($target);

        $referer = wp_get_referer();
        wp_safe_redirect(add_query_arg('caltech_2fa_done', 'reset', $referer ? remove_query_arg(['caltech_2fa_done', 'caltech_2fa_error'], $referer) : Admin::pageUrl()));
        exit;
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    private function requireOwnAction(string $nonceAction): \WP_User
    {
        if (! is_user_logged_in()) {
            wp_die(esc_html__('You are not allowed to do that.', 'caltech-security'), '', ['response' => 403]);
        }
        check_admin_referer($nonceAction);

        return wp_get_current_user();
    }

    private function currentCodeAccepted(int $userId): bool
    {
        if (UserFactor::locked($userId)) {
            return false;
        }

        $code = preg_replace('/\s+/', '', isset($_POST['current_code']) ? (string) wp_unslash($_POST['current_code']) : '') ?? '';
        if (UserFactor::verifyTotp($userId, $code)) {
            return true;
        }

        UserFactor::registerFailure($userId);

        return false;
    }

    /** @param  list<string>  $codes */
    private function stashCodes(int $userId, array $codes): void
    {
        set_transient(self::CODES_TRANSIENT . $userId, Crypto::encrypt((string) wp_json_encode($codes)), 10 * MINUTE_IN_SECONDS);
    }

    /** @param  array<string, string>  $args */
    private function back(array $args): void
    {
        wp_safe_redirect(self::pageUrl($args));
        exit;
    }
}
