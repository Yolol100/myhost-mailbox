<?php

declare(strict_types=1);

if (! defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

$cleanup = static function (): void {
    delete_transient('webactueel_mailbox_oidc_jwks_v1');
    delete_transient('webactueel_mailbox_executor_sha_v1');

    global $wpdb;
    foreach (array(
        '_transient_webactueel_mailbox_request_',
        '_transient_timeout_webactueel_mailbox_request_',
        '_transient_webactueel_mailbox_result_',
        '_transient_timeout_webactueel_mailbox_result_',
        '_transient_webactueel_mailbox_oidc_jti_',
        '_transient_timeout_webactueel_mailbox_oidc_jti_',
        'webactueel_mailbox_lock_',
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
