<?php

namespace CaltechSecurity;

if (! defined('ABSPATH')) {
    exit;
}

/**
 * The plugin's settings page: custom login URL, two-factor enforcement, and who has set 2FA up.
 */
final class Admin
{
    public const PAGE = 'caltech-security';

    private const PER_PAGE = 20;

    public function __construct(private Plugin $plugin) {}

    public function register(): void
    {
        add_action('admin_menu', [$this, 'registerMenu']);
        add_action('admin_enqueue_scripts', [$this, 'assets']);
        add_action('admin_post_caltech_security_save', [$this, 'handleSave']);
        add_filter('plugin_action_links_' . plugin_basename(CALTECH_SECURITY_FILE), [$this, 'actionLinks']);
    }

    /** Styles for this screen only. The hook is the one add_menu_page registers. */
    public function assets(string $hook): void
    {
        if ($hook !== 'toplevel_page_' . self::PAGE) {
            return;
        }

        wp_enqueue_style('caltech-security-admin', CALTECH_SECURITY_URL . 'assets/admin.css', [], CALTECH_SECURITY_VERSION);
    }

    public static function pageUrl(array $args = []): string
    {
        return add_query_arg(array_merge(['page' => self::PAGE], $args), admin_url('admin.php'));
    }

    public function registerMenu(): void
    {
        add_menu_page(
            __('Caltech Security', 'caltech-security'),
            __('Caltech Security', 'caltech-security'),
            'manage_options',
            self::PAGE,
            [$this, 'render'],
            'dashicons-lock',
            81
        );
    }

    /**
     * @param  array<int, string>  $links
     * @return array<int, string>
     */
    public function actionLinks($links): array
    {
        array_unshift($links, '<a href="' . esc_url(self::pageUrl()) . '">' . esc_html__('Settings', 'caltech-security') . '</a>');

        return $links;
    }

    // ── Save ────────────────────────────────────────────────────────────────

    public function handleSave(): void
    {
        if (! current_user_can('manage_options')) {
            wp_die(esc_html__('You are not allowed to do that.', 'caltech-security'), '', ['response' => 403]);
        }
        check_admin_referer('caltech_security_save');

        $slug = isset($_POST['login_slug']) ? trim(strtolower(sanitize_text_field(wp_unslash($_POST['login_slug']))), '/') : '';
        $enforce = ! empty($_POST['enforce_2fa']);

        $slugError = $slug !== '' ? $this->slugError($slug) : '';
        if ($slugError !== '') {
            $this->redirect(['caltech_sec_error' => $slugError]);
        }

        $wasEnforced = (bool) get_option(Plugin::OPT_ENFORCE_2FA, false);
        if ($enforce && ! $wasEnforced) {
            if (! Crypto::available()) {
                $this->redirect(['caltech_sec_error' => 'crypto']);
            }
            // The person turning it on must already be able to pass it, or they lock themselves out.
            if (! UserFactor::isEnrolled(get_current_user_id())) {
                $this->redirect(['caltech_sec_error' => 'enroll_first']);
            }
            // They proved a code to enrol; keep their own session valid when everyone else's stops counting.
            TwoFactor::stampCurrentSession(get_current_user_id());
        }

        update_option(Plugin::OPT_LOGIN_SLUG, $slug);
        update_option(Plugin::OPT_ENFORCE_2FA, $enforce ? 1 : 0);

        $this->redirect(['caltech_sec_saved' => '1']);
    }

    /** Why a login path is not acceptable, or '' when it is. */
    private function slugError(string $slug): string
    {
        if (! preg_match('/^[a-z0-9][a-z0-9-]{2,39}$/', $slug)) {
            return 'slug_format';
        }

        if (in_array($slug, Plugin::reservedSlugs(), true)) {
            return 'slug_reserved';
        }

        // A real page, post or file at that address would be hidden behind the login screen.
        if (get_page_by_path($slug, OBJECT, get_post_types(['public' => true])) !== null
            || file_exists(ABSPATH . $slug) || file_exists(ABSPATH . $slug . '.php')) {
            return 'slug_taken';
        }

        return '';
    }

    /** @param  array<string, string>  $args */
    private function redirect(array $args): void
    {
        wp_safe_redirect(self::pageUrl($args));
        exit;
    }

    // ── Page ────────────────────────────────────────────────────────────────

    public function render(): void
    {
        if (! current_user_can('manage_options')) {
            return;
        }

        $me = get_current_user_id();
        $myEnrolled = UserFactor::isEnrolled($me);
        $slug = $this->plugin->loginSlug();
        $enforced = (bool) get_option(Plugin::OPT_ENFORCE_2FA, false);
        $loginUrl = $slug !== '' ? home_url('/' . $slug) : home_url('/wp-login.php');

        $error = isset($_GET['caltech_sec_error']) ? sanitize_key(wp_unslash($_GET['caltech_sec_error'])) : '';
        $errors = [
            'slug_format' => __('The login path must be 3–40 characters: lowercase letters, numbers and dashes, starting with a letter or number.', 'caltech-security'),
            'slug_reserved' => __('That path is reserved by WordPress. Choose another.', 'caltech-security'),
            'slug_taken' => __('A page, post or file already exists at that path. Choose another.', 'caltech-security'),
            'enroll_first' => __('Set up two-factor authentication on your own account before turning it on for everyone, or you would lock yourself out.', 'caltech-security'),
            'crypto' => __('This server has no encryption support (libsodium or OpenSSL), which two-factor authentication needs to store secrets safely.', 'caltech-security'),
        ];
        $home = trailingslashit(home_url());
        ?>
        <div class="wrap caltech-sec">
            <h1><?php esc_html_e('Caltech Security', 'caltech-security'); ?></h1>
            <p class="caltech-sec__intro"><?php esc_html_e('Choose where people sign in, and require an authenticator code for every account.', 'caltech-security'); ?></p>

            <?php if (isset($errors[$error])) : ?>
                <div class="notice notice-error"><p><?php echo esc_html($errors[$error]); ?></p></div>
            <?php endif; ?>
            <?php if (isset($_GET['caltech_sec_saved'])) : ?>
                <div class="notice notice-success is-dismissible"><p>
                    <?php esc_html_e('Settings saved.', 'caltech-security'); ?>
                    <?php if ($this->plugin->loginUrlActive()) : ?>
                        <?php esc_html_e('Your login page is now:', 'caltech-security'); ?> <code><?php echo esc_html($loginUrl); ?></code> —
                        <?php esc_html_e('bookmark it; wp-login.php no longer works.', 'caltech-security'); ?>
                    <?php endif; ?>
                </p></div>
            <?php endif; ?>
            <?php if ($this->plugin->loginUrlDisabledByConfig()) : ?>
                <div class="notice notice-warning"><p><?php esc_html_e('The custom login URL is switched off by CALTECH_SECURITY_DISABLE_LOGIN_URL in wp-config.php.', 'caltech-security'); ?></p></div>
            <?php endif; ?>
            <?php if ($this->plugin->twoFactorDisabledByConfig()) : ?>
                <div class="notice notice-warning"><p><?php esc_html_e('Two-factor authentication is switched off by CALTECH_SECURITY_DISABLE_2FA in wp-config.php.', 'caltech-security'); ?></p></div>
            <?php endif; ?>

            <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                <?php wp_nonce_field('caltech_security_save'); ?>
                <input type="hidden" name="action" value="caltech_security_save">

                <div class="caltech-sec-grid">
                    <section class="caltech-sec-card">
                        <div class="caltech-sec-card__head">
                            <h2><?php esc_html_e('Custom login URL', 'caltech-security'); ?></h2>
                            <?php echo $this->pill($this->plugin->loginUrlActive()); // phpcs:ignore WordPress.Security.EscapeOutput ?>
                        </div>
                        <label class="caltech-sec-field" for="login_slug"><?php esc_html_e('Login path', 'caltech-security'); ?></label>
                        <div class="caltech-sec-url">
                            <span class="caltech-sec-url__base" title="<?php echo esc_attr($home); ?>"><?php echo esc_html($home); ?></span>
                            <input name="login_slug" id="login_slug" type="text" value="<?php echo esc_attr($slug); ?>" placeholder="wp-login88" autocomplete="off" spellcheck="false">
                        </div>
                        <p class="description"><?php esc_html_e('Leave empty to keep the standard login. When set, wp-login.php and the sign-in redirect from wp-admin answer "404 Not Found". Write the new address down: you need it to sign in.', 'caltech-security'); ?></p>
                    </section>

                    <section class="caltech-sec-card">
                        <div class="caltech-sec-card__head">
                            <h2><?php esc_html_e('Two-factor authentication', 'caltech-security'); ?></h2>
                            <?php echo $this->pill($this->plugin->twoFactorEnforced()); // phpcs:ignore WordPress.Security.EscapeOutput ?>
                        </div>
                        <p class="caltech-sec-stat"><?php echo esc_html(sprintf(
                            /* translators: 1: users with 2FA, 2: all users */
                            __('%1$d of %2$d accounts have set it up.', 'caltech-security'),
                            $this->countUsers(true),
                            $this->countUsers(false)
                        )); ?></p>
                        <?php if (! $enforced && ! $myEnrolled) : ?>
                            <div class="caltech-sec-callout">
                                <p><?php esc_html_e('Set up two-factor authentication on your own account before you can require it for everyone.', 'caltech-security'); ?></p>
                                <a class="button button-primary" href="<?php echo esc_url(Profile::pageUrl()); ?>"><?php esc_html_e('Set it up now', 'caltech-security'); ?></a>
                            </div>
                        <?php endif; ?>
                        <label class="caltech-sec-check">
                            <input type="checkbox" name="enforce_2fa" value="1" <?php checked($enforced); ?> <?php disabled(! $enforced && ! $myEnrolled); ?>>
                            <span><?php esc_html_e('Every account must enter an authenticator code after its password, on every role.', 'caltech-security'); ?></span>
                        </label>
                        <p class="description"><?php esc_html_e('Accounts that have set up an authenticator are asked for its code at every sign-in, even while this is off. Turning it on also makes every other account set one up at the next sign-in, and signs everyone else out.', 'caltech-security'); ?></p>
                    </section>
                </div>

                <?php submit_button(__('Save changes', 'caltech-security')); ?>
            </form>

            <?php $this->renderUsers(); ?>
        </div>
        <?php
    }

    private function pill(bool $on): string
    {
        return '<span class="caltech-sec-pill ' . ($on ? 'is-on' : 'is-off') . '">'
            . esc_html($on ? __('On', 'caltech-security') : __('Off', 'caltech-security'))
            . '</span>';
    }

    private function countUsers(bool $enrolledOnly): int
    {
        $args = ['number' => 1, 'fields' => 'ID', 'count_total' => true];
        if ($enrolledOnly) {
            $args['meta_key'] = UserFactor::META_ENROLLED_AT; // phpcs:ignore WordPress.DB.SlowDBQuery
            $args['meta_compare'] = 'EXISTS';
        }

        return (int) (new \WP_User_Query($args))->get_total();
    }

    private function renderUsers(): void
    {
        $search = isset($_GET['s']) ? trim(sanitize_text_field(wp_unslash($_GET['s']))) : '';
        $paged = max(1, isset($_GET['paged']) ? absint($_GET['paged']) : 1);

        $query = new \WP_User_Query([
            'number' => self::PER_PAGE,
            'paged' => $paged,
            'orderby' => 'login',
            'order' => 'ASC',
            'search' => $search !== '' ? '*' . $search . '*' : '',
            'search_columns' => ['user_login', 'user_email', 'display_name'],
            'count_total' => true,
        ]);

        $pages = (int) ceil($query->get_total() / self::PER_PAGE);
        ?>
        <div class="caltech-sec-panel">
        <h2><?php esc_html_e('Accounts', 'caltech-security'); ?></h2>
        <form method="get" class="caltech-sec-search">
            <input type="hidden" name="page" value="<?php echo esc_attr(self::PAGE); ?>">
            <input type="search" name="s" value="<?php echo esc_attr($search); ?>" placeholder="<?php esc_attr_e('Search users', 'caltech-security'); ?>">
            <?php submit_button(__('Search', 'caltech-security'), 'secondary', '', false); ?>
        </form>
        <table class="widefat striped caltech-sec-users">
            <thead>
                <tr>
                    <th><?php esc_html_e('User', 'caltech-security'); ?></th>
                    <th class="column-role"><?php esc_html_e('Role', 'caltech-security'); ?></th>
                    <th class="column-status"><?php esc_html_e('Two-factor', 'caltech-security'); ?></th>
                    <th class="column-actions"></th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($query->get_results() as $user) : ?>
                    <?php $enrolled = UserFactor::isEnrolled($user->ID); ?>
                    <tr>
                        <td class="caltech-sec-user"><strong><?php echo esc_html($user->user_login); ?></strong><span><?php echo esc_html($user->user_email); ?></span></td>
                        <td><?php echo esc_html(implode(', ', array_map('translate_user_role', array_map(static fn ($r) => wp_roles()->role_names[$r] ?? $r, $user->roles)))); ?></td>
                        <td>
                            <?php if ($enrolled) : ?>
                                <span class="caltech-sec-badge is-on"><?php esc_html_e('Set up', 'caltech-security'); ?></span>
                            <?php else : ?>
                                <span class="caltech-sec-badge is-off"><?php esc_html_e('Not set up', 'caltech-security'); ?></span>
                            <?php endif; ?>
                        </td>
                        <td class="column-actions">
                            <?php if ($enrolled && $user->ID !== get_current_user_id() && current_user_can('edit_user', $user->ID)) : ?>
                                <a href="<?php echo esc_url(Profile::resetUrl($user->ID)); ?>"
                                   onclick="return confirm('<?php echo esc_js(__('Reset two-factor authentication for this user? They will be signed out and asked to set it up again.', 'caltech-security')); ?>');"><?php esc_html_e('Reset', 'caltech-security'); ?></a>
                            <?php endif; ?>
                        </td>
                    </tr>
                <?php endforeach; ?>
                <?php if ($query->get_results() === []) : ?>
                    <tr><td colspan="4"><?php esc_html_e('No users found.', 'caltech-security'); ?></td></tr>
                <?php endif; ?>
            </tbody>
        </table>
        <?php if ($pages > 1) : ?>
            <div class="tablenav"><div class="tablenav-pages"><?php
                echo wp_kses_post((string) paginate_links([
                    'base' => add_query_arg('paged', '%#%', self::pageUrl($search !== '' ? ['s' => $search] : [])),
                    'format' => '',
                    'current' => $paged,
                    'total' => $pages,
                ]));
            ?></div></div>
        <?php endif; ?>
        </div>
        <?php
    }
}
