<?php
/**
 * Plugin Name: Webactueel Mailbox Bridge
 * Plugin URI: https://github.com/Yolol100/myhost-mailbox
 * Description: Private request/result bridge between ChatGPT-controlled GitHub workflows and the mijn.host mailbox runtime.
 * Version: 0.1.3
 * Requires at least: 6.4
 * Requires PHP: 7.4
 * Author: Webactueel
 * License: GPL-2.0-or-later
 * Text Domain: webactueel-mailbox-bridge
 */

declare(strict_types=1);

namespace Webactueel\MailboxBridge;

if (! defined('ABSPATH')) {
    exit;
}

define('WEBACTUEEL_MAILBOX_BRIDGE_VERSION', '0.1.3');
define('WEBACTUEEL_MAILBOX_BRIDGE_PATH', plugin_dir_path(__FILE__));

require_once WEBACTUEEL_MAILBOX_BRIDGE_PATH . 'includes/Store.php';
require_once WEBACTUEEL_MAILBOX_BRIDGE_PATH . 'includes/Oidc.php';
require_once WEBACTUEEL_MAILBOX_BRIDGE_PATH . 'includes/Rest.php';

$store = new Store();
$store->register();
$oidc = new Oidc();
(new Rest($store, $oidc))->register();
