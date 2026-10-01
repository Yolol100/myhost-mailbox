<?php

declare(strict_types=1);

if (! defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

$cleanup = static function (): void {
    delete_transient('webactueel_mailbox_oidc_jwks_v1');
    delete_transient('webactueel_mailbox_controller_sha_v1');
    delete_transient('webactueel_mailbox_executor_sha_v1');
    delete_transient('webactueel_mailbox_jti_cleanup_v1');
    delete_option('webactueel_mailbox_jwks_refresh_after_v1');
    delete_option('webactueel_secret_mailbox_crypto_key_v1');
    if (function_exists('wp_clear_scheduled_hook')) {
        wp_clear_scheduled_hook('webactueel_mailbox_expire_state');
    }

    global $wpdb;
    foreach (array(
        'webactueel_secret_mailbox_request_',
        'webactueel_secret_mailbox_result_',
        'webactueel_secret_mailbox_jti_',
        'webactueel_secret_mailbox_lock_',
    ) as $prefix) {
        $like = $wpdb->esc_like($prefix) . '%';
        $names = $wpdb->get_col($wpdb->prepare(
            "SELECT option_name FROM {$wpdb->options} WHERE option_name LIKE %s",
            $like
        ));
        foreach ((array) $names as $name) {
            if (is_string($name) && 0 === strpos($name, $prefix)) {
                delete_option($name);
            }
        }
    }
};

if (is_multisite() && function_exists('get_sites')) {
    $offset = 0;
    do {
        $siteIds = get_sites(array(
            'fields' => 'ids',
            'number' => 100,
            'offset' => $offset,
            'orderby' => 'id',
            'order' => 'ASC',
        ));
        foreach ((array) $siteIds as $siteId) {
            switch_to_blog((int) $siteId);
            $cleanup();
            restore_current_blog();
        }
        $count = count((array) $siteIds);
        $offset += $count;
    } while (100 === $count);
} else {
    $cleanup();
}
