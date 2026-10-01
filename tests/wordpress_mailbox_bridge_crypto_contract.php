<?php

declare(strict_types=1);

$root = dirname(__DIR__);
$GLOBALS['bridge_crypto_options'] = array();

function get_option($key, $default = false) { return $GLOBALS['bridge_crypto_options'][$key] ?? $default; }
function add_option($key, $value, $deprecated = '', $autoload = false): bool {
    if (array_key_exists($key, $GLOBALS['bridge_crypto_options'])) { return false; }
    $GLOBALS['bridge_crypto_options'][$key] = $value;
    return true;
}
function wp_json_encode($value, $flags = 0) { return json_encode($value, $flags); }

require_once $root . '/wordpress-plugin/webactueel-mailbox-bridge/includes/Crypto.php';

use Webactueel\MailboxBridge\Crypto;

if (! function_exists('openssl_pkey_new') || ! function_exists('openssl_encrypt')) {
    fwrite(STDERR, "OpenSSL is required for mailbox crypto contract.\n");
    exit(1);
}

$b64url = static function (string $value): string {
    return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
};
$b64decode = static function (string $value): string {
    $pad = strlen($value) % 4;
    $raw = strtr($value, '-_', '+/');
    if ($pad > 0) { $raw .= str_repeat('=', 4 - $pad); }
    $decoded = base64_decode($raw, true);
    if (false === $decoded) { throw new RuntimeException('base64url decode failed'); }
    return $decoded;
};

$crypto = new Crypto();
$server = $crypto->publicKeyPayload();
if (($server['version'] ?? null) !== 1 || ($server['algorithm'] ?? '') !== 'rsa-oaep-aes-256-gcm-v1') {
    fwrite(STDERR, "server crypto descriptor invalid\n"); exit(1);
}
if (! preg_match('/^[a-f0-9]{64}$/D', (string) ($server['key_id'] ?? ''))) {
    fwrite(STDERR, "server crypto key id invalid\n"); exit(1);
}
$serverAgain = $crypto->publicKeyPayload();
if (! hash_equals((string) $server['key_id'], (string) $serverAgain['key_id'])) {
    fwrite(STDERR, "server crypto key was not durable\n"); exit(1);
}

$clientKey = openssl_pkey_new(array('private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA));
if (false === $clientKey) { fwrite(STDERR, "client RSA key generation failed\n"); exit(1); }
$clientDetails = openssl_pkey_get_details($clientKey);
if (! is_array($clientDetails) || empty($clientDetails['key'])) { fwrite(STDERR, "client public key unavailable\n"); exit(1); }
$clientPublic = (string) $clientDetails['key'];

$plaintext = array(
    'request_id' => 'mailbox-crypto-123456',
    'request' => array('action' => 'search', 'query' => 'factuur café 🚀'),
    'ttl' => 3600,
    'response_public_key_pem' => $clientPublic,
);
$plainJson = json_encode($plaintext, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
$aes = random_bytes(32);
$iv = random_bytes(12);
$tag = '';
$cipher = openssl_encrypt($plainJson, 'aes-256-gcm', $aes, OPENSSL_RAW_DATA, $iv, $tag, 'webactueel-mailbox-request-v1', 16);
if (! is_string($cipher)) { fwrite(STDERR, "request encryption failed\n"); exit(1); }
$serverKey = openssl_pkey_get_public((string) $server['public_key_pem']);
if (false === $serverKey) { fwrite(STDERR, "server public key could not be loaded\n"); exit(1); }
$wrapped = '';
if (! openssl_public_encrypt($aes, $wrapped, $serverKey, OPENSSL_PKCS1_OAEP_PADDING)) {
    fwrite(STDERR, "request key wrapping failed\n"); exit(1);
}
$envelope = array(
    'version' => 1,
    'algorithm' => 'rsa-oaep-aes-256-gcm-v1',
    'key_id' => $server['key_id'],
    'wrapped_key' => $b64url($wrapped),
    'iv' => $b64url($iv),
    'tag' => $b64url($tag),
    'ciphertext' => $b64url($cipher),
);
$decoded = $crypto->decryptRequestEnvelope($envelope);
if ($decoded !== $plaintext) {
    fwrite(STDERR, "request crypto roundtrip mismatch\n"); exit(1);
}

$tampered = $envelope;
$tampered['tag'] = $b64url(random_bytes(16));
try {
    $crypto->decryptRequestEnvelope($tampered);
    fwrite(STDERR, "tampered request envelope was accepted\n"); exit(1);
} catch (RuntimeException $error) {
}

$result = array(
    'request_id' => 'mailbox-crypto-123456',
    'ready' => true,
    'result' => array('ok' => true, 'subject' => 'Unicode café 🚀', 'body' => 'private mailbox body'),
);
$response = $crypto->encryptResultEnvelope($result, $clientPublic);
if (($response['algorithm'] ?? '') !== 'rsa-oaep-aes-256-gcm-v1') {
    fwrite(STDERR, "result crypto descriptor invalid\n"); exit(1);
}

$responseAes = '';
if (! openssl_private_decrypt(
    $b64decode((string) $response['wrapped_key']),
    $responseAes,
    $clientKey,
    OPENSSL_PKCS1_OAEP_PADDING
) || 32 !== strlen($responseAes)) {
    fwrite(STDERR, "result key unwrap failed\n"); exit(1);
}
$responsePlain = openssl_decrypt(
    $b64decode((string) $response['ciphertext']),
    'aes-256-gcm',
    $responseAes,
    OPENSSL_RAW_DATA,
    $b64decode((string) $response['iv']),
    $b64decode((string) $response['tag']),
    'webactueel-mailbox-result-v1'
);
if (! is_string($responsePlain) || json_decode($responsePlain, true, 32, JSON_THROW_ON_ERROR) !== $result) {
    fwrite(STDERR, "result crypto roundtrip mismatch\n"); exit(1);
}

$stored = $GLOBALS['bridge_crypto_options']['webactueel_secret_mailbox_crypto_key_v1'] ?? array();
if (! is_array($stored) || empty($stored['private_key_pem'])) {
    fwrite(STDERR, "server private key was not stored\n"); exit(1);
}
if (false !== strpos(json_encode($server), 'PRIVATE KEY')) {
    fwrite(STDERR, "public key descriptor leaked private key material\n"); exit(1);
}

echo "wordpress mailbox bridge crypto contract OK\n";
