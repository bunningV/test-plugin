<?php
/**
 * Runs when the plugin is deleted from the Plugins screen: removes its settings and every user's
 * two-factor data. (Deactivating keeps them, so reactivating does not make everyone enrol again.)
 */

if (! defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

foreach (['caltech_security_login_slug', 'caltech_security_enforce_2fa', 'caltech_security_allow_app_passwords', 'caltech_security_autoupdate_default'] as $option) {
    delete_option($option);
}

foreach ([
    'caltech_security_totp_secret',
    'caltech_security_totp_enrolled_at',
    'caltech_security_totp_last_step',
    'caltech_security_recovery_codes',
    'caltech_security_totp_pending',
] as $metaKey) {
    delete_metadata('user', 0, $metaKey, '', true);
}

// Open challenges, failure counters and one-time recovery-code hand-offs live in transients.
global $wpdb;
$wpdb->query(
    $wpdb->prepare(
        "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s",
        $wpdb->esc_like('_transient_caltech_sec_') . '%',
        $wpdb->esc_like('_transient_timeout_caltech_sec_') . '%'
    )
);
