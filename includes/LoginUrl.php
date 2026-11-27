<?php

namespace CaltechSecurity;

if (! defined('ABSPATH')) {
    exit;
}

/**
 * Serves the WordPress login at a custom path and makes the original one disappear.
 *
 * Nothing is rewritten on the web server and no rewrite rules are added. WordPress boots as usual and,
 * once it is loaded (`wp_loaded`), this class looks at the requested path:
 *   - it is the custom path        -> run wp-login.php from here, as if it had been requested;
 *   - it is wp-login.php directly  -> answer 404, a real "not found", not a redirect to the new URL;
 *   - it is wp-admin, signed out   -> answer 404 instead of bouncing to the login screen, which
 *                                     would hand the custom path to anyone who asked.
 * Every URL WordPress builds for its login screen (login, logout, lost password, the links in the
 * password-reset email) is pointed at the custom path.
 *
 * The password-protected-post form posts to wp-login.php?action=postpass. That endpoint never signs
 * anyone in, and blocking it would break password-protected posts, so it is left alone.
 */
final class LoginUrl
{
    private static bool $serving = false;

    public function __construct(private Plugin $plugin) {}

    public function register(): void
    {
        if (! $this->plugin->loginUrlActive()) {
            return;
        }

        add_filter('site_url', [$this, 'filterSiteUrl'], 100, 4);
        add_filter('network_site_url', [$this, 'filterSiteUrl'], 100, 3);
        add_action('wp_loaded', [$this, 'route'], 0);
        // Core sends /login, /admin and /dashboard to the real login screen when nothing else matches.
        // That would reveal the custom path to anyone typing /login.
        add_action('init', static function (): void {
            remove_action('template_redirect', 'wp_redirect_admin_locations', 1000);
        });
    }

    /** True while the login screen is being served from the custom path. */
    public static function serving(): bool
    {
        return self::$serving;
    }

    /** True when this request is the login screen itself, whether native or served from the custom path. */
    public static function isLoginRequest(): bool
    {
        global $pagenow;

        return self::$serving || (isset($pagenow) && $pagenow === 'wp-login.php');
    }

    /**
     * The URL of the login screen with query args, wherever it currently lives.
     *
     * @param  array<string, scalar>  $args
     */
    public static function url(array $args = []): string
    {
        $url = wp_login_url();

        return $args === [] ? $url : add_query_arg($args, $url);
    }

    // ── URL generation ──────────────────────────────────────────────────────

    /**
     * @param  string  $url
     * @param  string  $path
     * @param  string|null  $scheme
     */
    public function filterSiteUrl($url, $path = '', $scheme = null): string
    {
        $path = ltrim((string) $path, '/');

        if (strpos($path, 'wp-login.php') !== 0 || strpos($path, 'action=postpass') !== false) {
            return (string) $url;
        }

        $rest = substr($path, strlen('wp-login.php'));

        return set_url_scheme(home_url('/' . $this->plugin->loginSlug()), $scheme) . $rest;
    }

    // ── Request routing ─────────────────────────────────────────────────────

    public function route(): void
    {
        if (wp_doing_cron() || wp_doing_ajax() || (defined('WP_CLI') && WP_CLI) || wp_installing()) {
            return;
        }

        global $pagenow;

        $path = $this->requestPath();

        if ($path === strtolower($this->plugin->loginSlug())) {
            $this->serveLogin();
        }

        // WordPress answers /wp-register.php (a rewrite rule, not a file) with a redirect to the login
        // screen's register form, which would be the custom path.
        if (in_array(basename($path), ['wp-register.php', 'login.php'], true)) {
            self::notFound();
        }

        if (in_array($pagenow, ['wp-login.php', 'wp-register.php'], true)) {
            if ($this->isPostPass()) {
                return;
            }
            self::notFound();
        }

        if (is_admin() && ! is_user_logged_in() && ! in_array($pagenow, ['admin-ajax.php', 'admin-post.php', 'load-styles.php', 'load-scripts.php'], true)) {
            self::notFound();
        }
    }

    /**
     * Run wp-login.php in place. The globals are the ones its helper functions read; included from a
     * method they would otherwise be locals and those functions would see them unset.
     */
    private function serveLogin(): void
    {
        global $error, $interim_login, $action, $user_login, $pagenow;

        self::$serving = true;
        $pagenow = 'wp-login.php';

        require ABSPATH . 'wp-login.php';
        exit;
    }

    private function isPostPass(): bool
    {
        $action = isset($_REQUEST['action']) ? sanitize_key(wp_unslash($_REQUEST['action'])) : '';

        return $action === 'postpass' && isset($_SERVER['REQUEST_METHOD']) && $_SERVER['REQUEST_METHOD'] === 'POST';
    }

    /** The requested path relative to the site's home path, lowercased, with no surrounding slashes. */
    private function requestPath(): string
    {
        $uri = isset($_SERVER['REQUEST_URI']) ? (string) wp_unslash($_SERVER['REQUEST_URI']) : '';
        $path = (string) wp_parse_url($uri, PHP_URL_PATH);
        $home = untrailingslashit((string) wp_parse_url(home_url(), PHP_URL_PATH));

        if ($home !== '' && stripos($path, $home) === 0) {
            $path = substr($path, strlen($home));
        }

        return strtolower(trim(rawurldecode($path), '/'));
    }

    // ── 404 ─────────────────────────────────────────────────────────────────

    /**
     * Answer as if the page does not exist. Public pages get the theme's own 404 template; anything
     * under wp-admin gets a plain 404, since the theme layer is not set up for admin requests.
     */
    public static function notFound(): void
    {
        status_header(404);
        nocache_headers();

        if (! is_admin()) {
            global $pagenow;

            // Forget the query string so wp-login.php?p=1 cannot resolve to a real post, and point the
            // request at a path that cannot exist so WordPress itself reaches the 404 template.
            $_GET = [];
            $_POST = [];
            $_REQUEST = [];
            $_SERVER['REQUEST_URI'] = '/' . str_repeat('-/', 10);
            $pagenow = 'index.php';

            if (! defined('WP_USE_THEMES')) {
                define('WP_USE_THEMES', true);
            }

            wp();

            // With plain permalinks the path above is ignored and WordPress would resolve the home
            // page; say 404 outright rather than rely on the fake path.
            global $wp_query;
            $wp_query->set_404();
            status_header(404);

            require_once ABSPATH . WPINC . '/template-loader.php';
            exit;
        }

        wp_die(
            esc_html__('The requested page could not be found.', 'caltech-security'),
            esc_html__('Not Found', 'caltech-security'),
            ['response' => 404, 'back_link' => false]
        );
    }
}
