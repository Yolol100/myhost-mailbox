<?php

declare(strict_types=1);

$root = dirname(__DIR__);
$GLOBALS['bridge_transients'] = array();
$GLOBALS['bridge_options'] = array();

function set_transient($key, $value, $ttl): bool { $GLOBALS['bridge_transients'][$key] = $value; return true; }
function get_transient($key) { return $GLOBALS['bridge_transients'][$key] ?? false; }
function delete_transient($key): bool { unset($GLOBALS['bridge_transients'][$key]); return true; }
function wp_json_encode($value, $flags = 0) { return json_encode($value, $flags); }
function add_option($key, $value, $deprecated = '', $autoload = false): bool {
    if (array_key_exists($key, $GLOBALS['bridge_options'])) { return false; }
    $GLOBALS['bridge_options'][$key] = $value; return true;
}
function get_option($key, $default = false) { return $GLOBALS['bridge_options'][$key] ?? $default; }
function delete_option($key): bool { unset($GLOBALS['bridge_options'][$key]); return true; }
function update_option($key, $value, $autoload = null): bool { $GLOBALS['bridge_options'][$key] = $value; return true; }
function wp_cache_delete($key, $group = ''): bool { return true; }
function add_action($hook, $callback, $priority = 10, $acceptedArgs = 1): bool { return true; }
function wp_schedule_single_event($timestamp, $hook, $args = array(), $wpError = false): bool { return true; }

final class BridgeWpdb {
    public string $options = 'wp_options';
    public function update($table, $data, $where, $format = null, $whereFormat = null): int {
        $key = (string) ($where['option_name'] ?? '');
        $expected = (string) ($where['option_value'] ?? '');
        if (! isset($GLOBALS['bridge_options'][$key]) || $GLOBALS['bridge_options'][$key] !== $expected) { return 0; }
        $GLOBALS['bridge_options'][$key] = (string) $data['option_value'];
        return 1;
    }
    public function delete($table, $where, $whereFormat = null): int {
        $key = (string) ($where['option_name'] ?? '');
        $expected = (string) ($where['option_value'] ?? '');
        if (! isset($GLOBALS['bridge_options'][$key]) || $GLOBALS['bridge_options'][$key] !== $expected) { return 0; }
        unset($GLOBALS['bridge_options'][$key]);
        return 1;
    }
}
$GLOBALS['wpdb'] = new BridgeWpdb();

require_once $root . '/wordpress-plugin/webactueel-mailbox-bridge/includes/Store.php';

use Webactueel\MailboxBridge\Store;

$store = new Store();
$store->register();
$requestId = 'mailbox-contract-123456';
$first = $store->putRequest($requestId, array('action' => 'list_folders'), 300);
if (empty($first['created']) || ! preg_match('/^[a-f0-9]{64}$/', (string) $first['sha256'])) {
    fwrite(STDERR, "request store failed\n"); exit(1);
}
$replay = $store->putRequest($requestId, array('action' => 'list_folders'), 300);
if (! empty($replay['created'])) {
    fwrite(STDERR, "request idempotency failed\n"); exit(1);
}
try {
    $store->putRequest($requestId, array('action' => 'list_messages'), 300);
    fwrite(STDERR, "request conflict was accepted\n"); exit(1);
} catch (RuntimeException $error) {
}

$claimed = $store->claimRequest($requestId);
if (($claimed['request']['action'] ?? '') !== 'list_folders' || (int) ($claimed['claimed_at'] ?? 0) <= 0) {
    fwrite(STDERR, "request claim failed\n"); exit(1);
}
try {
    $store->claimRequest($requestId);
    fwrite(STDERR, "duplicate request claim was accepted\n"); exit(1);
} catch (RuntimeException $error) {
    if (false === strpos($error->getMessage(), 'already claimed')) { throw $error; }
}
$result = $store->putResult($requestId, array('ok' => true), (string) $first['sha256']);
if (empty($result['created']) || empty($store->getResult($requestId)['ready'])) {
    fwrite(STDERR, "result store/readback failed\n"); exit(1);
}
$GLOBALS['bridge_transients'] = array();
if (empty($store->getResult($requestId)['ready'])) {
    fwrite(STDERR, "durable result disappeared after transient cache flush\n"); exit(1);
}

$lockId = 'mailbox-lock-123456';
$lockFirst = $store->putRequest($lockId, array('action' => 'list_folders'), 300);
$store->claimRequest($lockId);
$lockKey = 'webactueel_secret_mailbox_lock_' . hash('sha256', $lockId);
$GLOBALS['bridge_options'][$lockKey] = json_encode(array('token' => 'other', 'created_at' => time()));
try {
    $store->putResult($lockId, array('ok' => true), (string) $lockFirst['sha256']);
    fwrite(STDERR, "concurrent result write was accepted\n"); exit(1);
} catch (RuntimeException $error) {
    if (false === strpos($error->getMessage(), 'busy')) { throw $error; }
}
unset($GLOBALS['bridge_options'][$lockKey]);

$staleId = 'mailbox-stale-123456';
$old = $store->putRequest($staleId, array('action' => 'list_folders'), 300);
try {
    $store->putResult($staleId, array('ok' => true), (string) $old['sha256']);
    fwrite(STDERR, "unclaimed request accepted a result\n"); exit(1);
} catch (RuntimeException $error) {
    if (false === strpos($error->getMessage(), 'must be claimed')) { throw $error; }
}
try {
    $store->clear($staleId);
    fwrite(STDERR, "unread mailbox state was cleared\n"); exit(1);
} catch (RuntimeException $error) {
    if (false === strpos($error->getMessage(), 'must be read')) { throw $error; }
}
$store->claimRequest($staleId);
$store->putResult($staleId, array('ok' => true), (string) $old['sha256']);
$ready = $store->getResult($staleId);
if (empty($ready['ready'])) {
    fwrite(STDERR, "mailbox result could not be consumed before clear\n"); exit(1);
}
$store->clear($staleId);
if (! empty($store->getResult($staleId)['ready'])) {
    fwrite(STDERR, "cleanup readback failed\n"); exit(1);
}

$oidc = file_get_contents($root . '/wordpress-plugin/webactueel-mailbox-bridge/includes/Oidc.php');
$rest = file_get_contents($root . '/wordpress-plugin/webactueel-mailbox-bridge/includes/Rest.php');
$uninstall = file_get_contents($root . '/wordpress-plugin/webactueel-mailbox-bridge/uninstall.php');
$bootstrap = file_get_contents($root . '/wordpress-plugin/webactueel-mailbox-bridge/webactueel-mailbox-bridge.php');

foreach (array(
    "PRIVATE_REPOSITORY = 'Yolol100/Wordpress'",
    "EXECUTOR_REPOSITORY = 'Yolol100/Leadscanner'",
    'mailbox-private-bridge.yml@refs/heads/main',
    'mailbox-execute.yml@refs/heads/main',
    "'repository_visibility' => 'private'",
    "'repository_visibility' => 'public'",
    "executorMainShaForClaim",
    'assertNotReplayed',
    "JTI_PREFIX = 'webactueel_secret_mailbox_jti_'",
    'claimJwksRefreshWindow',
) as $needle) {
    if (false === strpos((string) $oidc, $needle)) {
        fwrite(STDERR, "missing OIDC boundary: {$needle}\n"); exit(1);
    }
}

foreach (array(
    '/requests/(?P<request_id>',
    '/results/(?P<request_id>',
    '/state/(?P<request_id>',
    'authenticatePrivate',
    'authenticateExecutor',
    'confirm_send=true',
    'confirm=true',
    "get_header('x-webactueel-mailbox-request-sha256')",
    'claimRequest($requestId)',
    'is_object($shape)',
) as $needle) {
    if (false === strpos((string) $rest, $needle)) {
        fwrite(STDERR, "missing REST boundary: {$needle}\n"); exit(1);
    }
}

foreach (array(
    'webactueel_secret_mailbox_request_',
    'webactueel_secret_mailbox_result_',
    'webactueel_secret_mailbox_jti_',
    'webactueel_secret_mailbox_lock_',
    'webactueel_mailbox_expire_state',
) as $needle) {
    if (false === strpos((string) $uninstall, $needle)) {
        fwrite(STDERR, "missing uninstall cleanup: {$needle}\n"); exit(1);
    }
}

if (false === strpos((string) $bootstrap, 'Version: 0.1.3') || false === strpos((string) $bootstrap, '$store->register();')) {
    fwrite(STDERR, "plugin version missing\n"); exit(1);
}
if (preg_match('/(OUTREACH_MAIL_PASSWORD|BEGIN PRIVATE KEY|api[_-]?key\s*=)/i', (string) $oidc . (string) $rest . (string) $bootstrap)) {
    fwrite(STDERR, "secret-like material found in plugin source\n"); exit(1);
}

echo "wordpress mailbox bridge contract OK\n";
