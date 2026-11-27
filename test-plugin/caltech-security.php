<?php
/**
 * Plugin Name:       Caltech WP Security
 * Plugin URI:        https://dash.caltech.it.com
 * Description:       Moves the WordPress login to a custom URL and requires two-factor authentication (authenticator app + recovery codes) for every account, enforced server-side. Managed entirely from its own settings page.
 * Version:           1.0.0
 * Requires at least: 5.8
 * Requires PHP:      8.0
 * Author:            Caltech Hosting
 * Author URI:        https://dash.caltech.it.com
 * License:           GPL-2.0-or-later
 * Text Domain:       caltech-security
 */

if (! defined('ABSPATH')) {
    exit;
}

define('CALTECH_SECURITY_VERSION', '1.0.0');
define('CALTECH_SECURITY_FILE', __FILE__);
define('CALTECH_SECURITY_DIR', plugin_dir_path(__FILE__));
define('CALTECH_SECURITY_URL', plugin_dir_url(__FILE__));

require_once CALTECH_SECURITY_DIR . 'includes/Crypto.php';
require_once CALTECH_SECURITY_DIR . 'includes/Totp.php';
require_once CALTECH_SECURITY_DIR . 'includes/UserFactor.php';
require_once CALTECH_SECURITY_DIR . 'includes/Challenge.php';
require_once CALTECH_SECURITY_DIR . 'includes/Plugin.php';
require_once CALTECH_SECURITY_DIR . 'includes/LoginUrl.php';
require_once CALTECH_SECURITY_DIR . 'includes/TwoFactor.php';
require_once CALTECH_SECURITY_DIR . 'includes/Profile.php';
require_once CALTECH_SECURITY_DIR . 'includes/Admin.php';

// Updates come from the GitHub release attached by .github/workflows/release.yml.
// Guarded so the plugin still loads if vendor/ is missing (e.g. a dev checkout without composer install).
$caltechSecurityAutoload = CALTECH_SECURITY_DIR . 'vendor/autoload.php';
if (file_exists($caltechSecurityAutoload)) {
    require_once $caltechSecurityAutoload;

    $caltechSecurityUpdates = \YahnisElsts\PluginUpdateChecker\v6\PucFactory::buildUpdateChecker(
        'https://github.com/bunningV/test-plugin/',
        CALTECH_SECURITY_FILE,
        'test-plugin'
    );
    $caltechSecurityUpdates->getVcsApi()->enableReleaseAssets('/^test-plugin\.zip$/');
}

// Default new installs to auto-updating. Site admins can still turn auto-updates off per plugin.
add_filter('auto_update_plugin', static function ($update, $item) {
    if (isset($item->plugin) && $item->plugin === plugin_basename(CALTECH_SECURITY_FILE)) {
        return true;
    }

    return $update;
}, 10, 2);

add_action('plugins_loaded', static function (): void {
    \CaltechSecurity\Plugin::instance()->boot();
});
