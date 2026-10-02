<?php

declare(strict_types=1);

define('ABSPATH', __DIR__ . '/');
define('HOUR_IN_SECONDS', 3600);

$GLOBALS['bridge_oidc_transients'] = array();
$GLOBALS['bridge_oidc_options'] = array();
$GLOBALS['bridge_oidc_jwks'] = array();
$GLOBALS['bridge_executor_main_sha'] = '11965800c666e00191f0c143585e84017e66cb01';
$GLOBALS['bridge_remote_jwks_calls'] = 0;
$GLOBALS['bridge_remote_executor_calls'] = 0;

class WP_REST_Request
{
    private array $headers;
    public function __construct(array $headers) { $this->headers = $headers; }
    public function get_header($name) { return $this->headers[strtolower((string) $name)] ?? ''; }
}

final class BridgeOidcWpdb
{
    public string $options = 'wp_options';

    public function update($table, $data, $where, $format = null, $whereFormat = null): int
    {
        $key = (string) ($where['option_name'] ?? '');
        $expected = (string) ($where['option_value'] ?? '');
        if (! array_key_exists($key, $GLOBALS['bridge_oidc_options'])) {
            return 0;
        }
        if ((string) $GLOBALS['bridge_oidc_options'][$key] !== $expected) {
            return 0;
        }
        $GLOBALS['bridge_oidc_options'][$key] = (string) $data['option_value'];
        return 1;
    }

    public function esc_like($value): string { return (string) $value; }
    public function prepare($query, ...$args): string { return (string) $query; }

    public function get_results($query): array
    {
        $rows = array();
        foreach ($GLOBALS['bridge_oidc_options'] as $name => $value) {
            if (0 !== strpos((string) $name, 'webactueel_secret_mailbox_jti_')) {
                continue;
            }
            $row = new stdClass();
            $row->option_name = (string) $name;
            $row->option_value = (string) $value;
            $rows[] = $row;
        }
        return $rows;
    }
}
$GLOBALS['wpdb'] = new BridgeOidcWpdb();

function rest_url($path = ''): string { return 'https://example.com/wp-json/' . ltrim((string) $path, '/'); }
function get_transient($key) { return $GLOBALS['bridge_oidc_transients'][$key] ?? false; }
function set_transient($key, $value, $ttl): bool { $GLOBALS['bridge_oidc_transients'][$key] = $value; return true; }
function delete_transient($key): bool { unset($GLOBALS['bridge_oidc_transients'][$key]); return true; }
function add_option($key, $value, $deprecated = '', $autoload = false): bool {
    if (array_key_exists($key, $GLOBALS['bridge_oidc_options'])) { return false; }
    $GLOBALS['bridge_oidc_options'][$key] = $value;
    return true;
}
function get_option($key, $default = false) { return $GLOBALS['bridge_oidc_options'][$key] ?? $default; }
function delete_option($key): bool { unset($GLOBALS['bridge_oidc_options'][$key]); return true; }
function wp_cache_delete($key, $group = ''): bool { return true; }

function wp_safe_remote_get($url, $args = array()) {
    if (false !== strpos((string) $url, '/Leadscanner/commits/main')) {
        ++$GLOBALS['bridge_remote_executor_calls'];
        return array(
            'response' => array('code' => 200),
            'body' => json_encode(array('sha' => $GLOBALS['bridge_executor_main_sha'])),
        );
    }
    ++$GLOBALS['bridge_remote_jwks_calls'];
    return array(
        'response' => array('code' => 200),
        'body' => json_encode(array('keys' => $GLOBALS['bridge_oidc_jwks'])),
    );
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

$token = static function (array $claims, string $kid = 'test-key') use ($key, $b64url): string {
    $header = array('alg' => 'RS256', 'typ' => 'JWT', 'kid' => $kid);
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

$privateClaims = static function () use ($baseClaims): array {
    return array_merge($baseClaims(), array(
        'repository' => 'Yolol100/Wordpress',
        'repository_id' => '933904076',
        'repository_visibility' => 'private',
        'workflow_ref' => 'Yolol100/Wordpress/.github/workflows/mailbox-private-bridge.yml@refs/heads/main',
    ));
};

$executorClaims = static function () use ($baseClaims): array {
    return array_merge($baseClaims(), array(
        'repository' => 'Yolol100/Leadscanner',
        'repository_id' => '1334704263',
        'repository_visibility' => 'public',
        'workflow_ref' => 'Yolol100/Leadscanner/.github/workflows/mailbox-execute.yml@refs/heads/main',
        'sha' => $GLOBALS['bridge_executor_main_sha'],
    ));
};

$auth = new Oidc();

$before = $GLOBALS['bridge_remote_jwks_calls'] + $GLOBALS['bridge_remote_executor_calls'];
if ($auth->authenticateExecutor(new WP_REST_Request(array()))) {
    fwrite(STDERR, "missing executor token was accepted\n"); exit(1);
}
$after = $GLOBALS['bridge_remote_jwks_calls'] + $GLOBALS['bridge_remote_executor_calls'];
if ($after !== $before) {
    fwrite(STDERR, "missing executor token triggered remote lookup\n"); exit(1);
}

$private = $privateClaims();
$privateJwt = $token($private);
if (! $auth->authenticatePrivate(new WP_REST_Request(array('x-webactueel-github-oidc' => $privateJwt)))) {
    fwrite(STDERR, "valid private workflow token rejected\n"); exit(1);
}
if (1 !== $GLOBALS['bridge_remote_jwks_calls']) {
    fwrite(STDERR, "initial OIDC authentication did not perform exactly one JWKS fetch\n"); exit(1);
}

try {
    $auth->authenticatePrivate(new WP_REST_Request(array('x-webactueel-github-oidc' => $privateJwt)));
    fwrite(STDERR, "replayed private token accepted\n"); exit(1);
} catch (RuntimeException $error) {
    if (false === strpos($error->getMessage(), 'already used')) { throw $error; }
}

$unknownKidClaims = $privateClaims();
try {
    $auth->authenticatePrivate(new WP_REST_Request(array(
        'x-webactueel-github-oidc' => $token($unknownKidClaims, 'unknown-key'),
    )));
    fwrite(STDERR, "unknown signing key was accepted\n"); exit(1);
} catch (RuntimeException $error) {
    if (
        false === strpos($error->getMessage(), 'rate-limited')
        && false === strpos($error->getMessage(), 'unavailable')
    ) {
        throw $error;
    }
}
if (1 !== $GLOBALS['bridge_remote_jwks_calls']) {
    fwrite(STDERR, "unknown kid bypassed JWKS refresh rate limit\n"); exit(1);
}

$executor = $executorClaims();
$executorJwt = $token($executor);
if (! $auth->authenticateExecutor(new WP_REST_Request(array('x-webactueel-github-oidc' => $executorJwt)))) {
    fwrite(STDERR, "valid executor token rejected\n"); exit(1);
}
if (1 !== $GLOBALS['bridge_remote_executor_calls']) {
    fwrite(STDERR, "executor revision lookup count mismatch\n"); exit(1);
}

$GLOBALS['bridge_executor_main_sha'] = '22965800c666e00191f0c143585e84017e66cb02';
$rotated = $executorClaims();
if (! $auth->authenticateExecutor(new WP_REST_Request(array(
    'x-webactueel-github-oidc' => $token($rotated),
)))) {
    fwrite(STDERR, "fresh executor SHA was rejected after cached main changed\n"); exit(1);
}
if (2 !== $GLOBALS['bridge_remote_executor_calls']) {
    fwrite(STDERR, "cached executor SHA mismatch did not force exactly one main refresh\n"); exit(1);
}

try {
    $bad = $executorClaims();
    $bad['sha'] = str_repeat('1', 40);
    $auth->authenticateExecutor(new WP_REST_Request(array('x-webactueel-github-oidc' => $token($bad))));
    fwrite(STDERR, "stale executor SHA accepted\n"); exit(1);
} catch (RuntimeException $error) {
    if (false === strpos($error->getMessage(), 'sha')) { throw $error; }
}

try {
    $bad = $executorClaims();
    $bad['workflow_ref'] = 'Yolol100/Leadscanner/.github/workflows/other.yml@refs/heads/main';
    $auth->authenticateExecutor(new WP_REST_Request(array('x-webactueel-github-oidc' => $token($bad))));
    fwrite(STDERR, "wrong executor workflow accepted\n"); exit(1);
} catch (RuntimeException $error) {
    if (false === strpos($error->getMessage(), 'workflow_ref')) { throw $error; }
}

try {
    $cross = $privateClaims();
    $auth->authenticateExecutor(new WP_REST_Request(array('x-webactueel-github-oidc' => $token($cross))));
    fwrite(STDERR, "private workflow gained executor access\n"); exit(1);
} catch (RuntimeException $error) {
    if (false === strpos($error->getMessage(), 'repository')) { throw $error; }
}

$jtiKeys = array_filter(
    array_keys($GLOBALS['bridge_oidc_options']),
    static function ($name): bool {
        return 0 === strpos((string) $name, 'webactueel_secret_mailbox_jti_');
    }
);
if (count($jtiKeys) < 2) {
    fwrite(STDERR, "atomic OIDC replay reservations were not persisted\n"); exit(1);
}

echo "wordpress mailbox bridge oidc contract OK\n";
