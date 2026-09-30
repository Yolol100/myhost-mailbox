<?php

declare(strict_types=1);

define('ABSPATH', __DIR__ . '/');
define('HOUR_IN_SECONDS', 3600);
$GLOBALS['bridge_oidc_transients'] = array();
$GLOBALS['bridge_oidc_jwks'] = array();
$GLOBALS['bridge_executor_main_sha'] = '11965800c666e00191f0c143585e84017e66cb01';

class WP_REST_Request
{
    private array $headers;
    public function __construct(array $headers) { $this->headers = $headers; }
    public function get_header($name) { return $this->headers[strtolower((string) $name)] ?? ''; }
}

function rest_url($path = ''): string { return 'https://example.com/wp-json/' . ltrim((string) $path, '/'); }
function get_transient($key) { return $GLOBALS['bridge_oidc_transients'][$key] ?? false; }
function set_transient($key, $value, $ttl): bool { $GLOBALS['bridge_oidc_transients'][$key] = $value; return true; }
function wp_safe_remote_get($url, $args = array()) {
    if (false !== strpos((string) $url, '/Leadscanner/commits/main')) {
        return array('response' => array('code' => 200), 'body' => json_encode(array('sha' => $GLOBALS['bridge_executor_main_sha'])));
    }
    return array('response' => array('code' => 200), 'body' => json_encode(array('keys' => $GLOBALS['bridge_oidc_jwks'])));
}
function is_wp_error($value): bool { return false; }
function wp_remote_retrieve_response_code($response): int { return (int) ($response['response']['code'] ?? 0); }
function wp_remote_retrieve_body($response): string { return (string) ($response['body'] ?? ''); }

require_once dirname(__DIR__) . '/wordpress-plugin/webactueel-mailbox-bridge/includes/Oidc.php';

use Webactueel\MailboxBridge\Oidc;

if (! function_exists('openssl_pkey_new')) {
    echo "wordpress mailbox bridge oidc contract skipped: OpenSSL unavailable\n";
    exit(0);
}

$key = openssl_pkey_new(array('private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA));
if (false === $key) { fwrite(STDERR, "RSA test key creation failed\n"); exit(1); }
$details = openssl_pkey_get_details($key);
if (! is_array($details) || ! isset($details['rsa']['n'], $details['rsa']['e'])) {
    fwrite(STDERR, "RSA test key details unavailable\n"); exit(1);
}

$b64url = static function (string $value): string {
    return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
};

$GLOBALS['bridge_oidc_jwks'] = array(array(
    'kty' => 'RSA',
    'alg' => 'RS256',
    'use' => 'sig',
    'kid' => 'test-key',
    'n' => $b64url($details['rsa']['n']),
    'e' => $b64url($details['rsa']['e']),
));

$token = static function (array $claims) use ($key, $b64url): string {
    $header = array('alg' => 'RS256', 'typ' => 'JWT', 'kid' => 'test-key');
    $segments = array(
        $b64url(json_encode($header, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR)),
        $b64url(json_encode($claims, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR)),
    );
    $input = implode('.', $segments);
    if (! openssl_sign($input, $signature, $key, OPENSSL_ALGO_SHA256)) {
        throw new RuntimeException('Could not sign test token.');
    }
    return $input . '.' . $b64url($signature);
};

$baseClaims = static function (): array {
    $now = time();
    return array(
        'iss' => 'https://token.actions.githubusercontent.com',
        'aud' => 'https://example.com/wp-json/webactueel-mailbox-bridge/v1',
        'exp' => $now + 300,
        'iat' => $now,
        'nbf' => $now - 1,
        'jti' => bin2hex(random_bytes(16)),
        'repository_owner_id' => '22932777',
        'actor_id' => '22932777',
        'ref' => 'refs/heads/main',
        'event_name' => 'issues',
        'runner_environment' => 'github-hosted',
    );
};

$privateClaims = array_merge($baseClaims(), array(
    'repository' => 'Yolol100/wordpressconnector',
    'repository_id' => '1341990468',
    'repository_visibility' => 'private',
    'workflow_ref' => 'Yolol100/wordpressconnector/.github/workflows/mailbox-private-bridge.yml@refs/heads/main',
));

$executorClaims = array_merge($baseClaims(), array(
    'repository' => 'Yolol100/Leadscanner',
    'repository_id' => '1334704263',
    'repository_visibility' => 'public',
    'workflow_ref' => 'Yolol100/Leadscanner/.github/workflows/mailbox-execute.yml@refs/heads/main',
    'sha' => $GLOBALS['bridge_executor_main_sha'],
));

$auth = new Oidc();

$privateJwt = $token($privateClaims);
if (! $auth->authenticatePrivate(new WP_REST_Request(array('x-webactueel-github-oidc' => $privateJwt)))) {
    fwrite(STDERR, "valid private workflow token rejected\n"); exit(1);
}
try {
    $auth->authenticatePrivate(new WP_REST_Request(array('x-webactueel-github-oidc' => $privateJwt)));
    fwrite(STDERR, "replayed private token accepted\n"); exit(1);
} catch (RuntimeException $error) {
    if (false === strpos($error->getMessage(), 'already used')) { throw $error; }
}

$executorJwt = $token($executorClaims);
if (! $auth->authenticateExecutor(new WP_REST_Request(array('x-webactueel-github-oidc' => $executorJwt)))) {
    fwrite(STDERR, "valid executor token rejected\n"); exit(1);
}

try {
    $bad = array_merge($executorClaims, array('jti' => bin2hex(random_bytes(16)), 'sha' => str_repeat('1', 40)));
    $auth->authenticateExecutor(new WP_REST_Request(array('x-webactueel-github-oidc' => $token($bad))));
    fwrite(STDERR, "stale executor SHA accepted\n"); exit(1);
} catch (RuntimeException $error) {
    if (false === strpos($error->getMessage(), 'sha')) { throw $error; }
}

try {
    $bad = array_merge($executorClaims, array(
        'jti' => bin2hex(random_bytes(16)),
        'workflow_ref' => 'Yolol100/Leadscanner/.github/workflows/other.yml@refs/heads/main',
    ));
    $auth->authenticateExecutor(new WP_REST_Request(array('x-webactueel-github-oidc' => $token($bad))));
    fwrite(STDERR, "wrong executor workflow accepted\n"); exit(1);
} catch (RuntimeException $error) {
    if (false === strpos($error->getMessage(), 'workflow_ref')) { throw $error; }
}

try {
    $cross = array_merge($privateClaims, array('jti' => bin2hex(random_bytes(16))));
    $auth->authenticateExecutor(new WP_REST_Request(array('x-webactueel-github-oidc' => $token($cross))));
    fwrite(STDERR, "private workflow gained executor access\n"); exit(1);
} catch (RuntimeException $error) {
    if (false === strpos($error->getMessage(), 'repository')) { throw $error; }
}

echo "wordpress mailbox bridge oidc contract OK\n";
