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

add_action('plugins_loaded', static function (): void {
    \CaltechSecurity\Plugin::instance()->boot();
});
