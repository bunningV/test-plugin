<?php

namespace CaltechSecurity;

if (! defined('ABSPATH')) {
    exit;
}

/**
 * Settings access and wiring. The two features live in {@see LoginUrl} and {@see TwoFactor}; the
 * screens in {@see Admin} and {@see Profile}.
 *
 * Emergency off switches, for the day a setting locks the owner out (set in wp-config.php):
 *   define('CALTECH_SECURITY_DISABLE_LOGIN_URL', true);  // wp-login.php works normally again
 *   define('CALTECH_SECURITY_DISABLE_2FA', true);        // no verification code is asked for
 */
final class Plugin
{
    public const OPT_LOGIN_SLUG = 'caltech_security_login_slug';

    public const OPT_ENFORCE_2FA = 'caltech_security_enforce_2fa';

    private static ?Plugin $instance = null;

    public static function instance(): Plugin
    {
        if (self::$instance === null) {
            self::$instance = new self;
        }

        return self::$instance;
    }

    public function boot(): void
    {
        (new LoginUrl($this))->register();
        (new TwoFactor($this))->register();
        (new Profile($this))->register();
        (new Admin($this))->register();
    }

    // ── Settings ────────────────────────────────────────────────────────────

    /** The configured custom login path, or '' when the default wp-login.php is in use. */
    public function loginSlug(): string
    {
        return (string) get_option(self::OPT_LOGIN_SLUG, '');
    }

    public function loginUrlActive(): bool
    {
        if (defined('CALTECH_SECURITY_DISABLE_LOGIN_URL') && CALTECH_SECURITY_DISABLE_LOGIN_URL) {
            return false;
        }

        return $this->loginSlug() !== '';
    }

    public function twoFactorEnforced(): bool
    {
        if (defined('CALTECH_SECURITY_DISABLE_2FA') && CALTECH_SECURITY_DISABLE_2FA) {
            return false;
        }

        return (bool) get_option(self::OPT_ENFORCE_2FA, false);
    }

    public function loginUrlDisabledByConfig(): bool
    {
        return defined('CALTECH_SECURITY_DISABLE_LOGIN_URL') && CALTECH_SECURITY_DISABLE_LOGIN_URL;
    }

    public function twoFactorDisabledByConfig(): bool
    {
        return defined('CALTECH_SECURITY_DISABLE_2FA') && CALTECH_SECURITY_DISABLE_2FA;
    }

    /**
     * Whether cookies issued by this plugin must carry Secure.
     *
     * `is_ssl()` is false on otherwise-correct HTTPS WordPress installs when TLS ends at nginx,
     * Cloudflare, or another reverse proxy whose forwarding headers are not mapped into `HTTPS`.
     * WordPress still knows the public scheme through its configured home/site URL, so use both
     * signals. FORCE_SSL_ADMIN is a third explicit signal from wp-config.php.
     */
    public static function secureCookies(): bool
    {
        if (is_ssl() || (defined('FORCE_SSL_ADMIN') && FORCE_SSL_ADMIN)) {
            return true;
        }

        foreach ([home_url(), site_url()] as $url) {
            if (strtolower((string) wp_parse_url($url, PHP_URL_SCHEME)) === 'https') {
                return true;
            }
        }

        return false;
    }

    /** Names that are WordPress's own, or that would shadow it. A custom login path cannot be one of these. */
    public static function reservedSlugs(): array
    {
        return [
            'wp-admin', 'wp-login', 'wp-login-php', 'wp-register', 'wp-signup', 'wp-activate', 'wp-content', 'wp-includes',
            'wp-json', 'wp-cron', 'wp-load', 'wp-config', 'wp-blog-header', 'wp-comments-post', 'wp-links-opml',
            'wp-mail', 'wp-settings', 'wp-trackback', 'xmlrpc', 'index', 'admin', 'dashboard', 'feed', 'rss', 'rss2',
            'atom', 'rdf', 'robots', 'sitemap', 'embed', 'comments', 'author', 'search', 'page', 'category', 'tag',
        ];
    }
}
