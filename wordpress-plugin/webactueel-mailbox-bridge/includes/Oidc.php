<?php

declare(strict_types=1);

namespace Webactueel\MailboxBridge;

use RuntimeException;

final class Oidc
{
    private const HEADER = 'x-webactueel-github-oidc';
    private const ISSUER = 'https://token.actions.githubusercontent.com';
    private const JWKS_URL = 'https://token.actions.githubusercontent.com/.well-known/jwks';
    private const OWNER_ID = '22932777';

    private const PRIVATE_REPOSITORY = 'Yolol100/wordpressconnector';
    private const PRIVATE_REPOSITORY_ID = '1341990468';
    private const PRIVATE_WORKFLOW_REF = 'Yolol100/wordpressconnector/.github/workflows/mailbox-private-bridge.yml@refs/heads/main';

    private const EXECUTOR_REPOSITORY = 'Yolol100/Leadscanner';
    private const EXECUTOR_REPOSITORY_ID = '1334704263';
    private const EXECUTOR_WORKFLOW_REF = 'Yolol100/Leadscanner/.github/workflows/mailbox-execute.yml@refs/heads/main';

    private const CLOCK_SKEW = 60;
    private const MAX_TOKEN_AGE = 600;
    private const JWKS_TRANSIENT = 'webactueel_mailbox_oidc_jwks_v1';
    private const JWKS_REFRESH_OPTION = 'webactueel_mailbox_jwks_refresh_after_v1';
    private const JTI_PREFIX = 'webactueel_secret_mailbox_jti_';
    private const JTI_CLEANUP_TRANSIENT = 'webactueel_mailbox_jti_cleanup_v1';
    private const CONTROLLER_SHA_TRANSIENT = 'webactueel_mailbox_controller_sha_v1';
    private const EXECUTOR_SHA_TRANSIENT = 'webactueel_mailbox_executor_sha_v1';

    public function authenticatePrivate(\WP_REST_Request $request): bool
    {
        return $this->authenticateExpected(
            $request,
            array(
                'repository' => self::PRIVATE_REPOSITORY,
                'repository_id' => self::PRIVATE_REPOSITORY_ID,
                'repository_owner_id' => self::OWNER_ID,
                'actor_id' => self::OWNER_ID,
                'repository_visibility' => 'public',
                'ref' => 'refs/heads/main',
                'workflow_ref' => self::PRIVATE_WORKFLOW_REF,
                'event_name' => 'issues',
                'runner_environment' => 'github-hosted',
            ),
            function (): array {
                return array('sha' => $this->controllerMainSha());
            }
        );
    }

    public function authenticateExecutor(\WP_REST_Request $request): bool
    {
        return $this->authenticateExpected(
            $request,
            array(
                'repository' => self::EXECUTOR_REPOSITORY,
                'repository_id' => self::EXECUTOR_REPOSITORY_ID,
                'repository_owner_id' => self::OWNER_ID,
                'actor_id' => self::OWNER_ID,
                'repository_visibility' => 'public',
                'ref' => 'refs/heads/main',
                'workflow_ref' => self::EXECUTOR_WORKFLOW_REF,
                'event_name' => 'issues',
                'runner_environment' => 'github-hosted',
            ),
            function (): array {
                return array('sha' => $this->executorMainSha());
            }
        );
    }

    public static function expectedAudience(): string
    {
        return rtrim((string) rest_url('webactueel-mailbox-bridge/v1'), '/');
    }

    private function authenticateExpected(\WP_REST_Request $request, array $expected, ?callable $lateExpected = null): bool
    {
        $token = (string) $request->get_header(self::HEADER);
        if ('' === $token) {
            return false;
        }
        if (! function_exists('openssl_verify')) {
            throw new RuntimeException('GitHub OIDC requires PHP OpenSSL.');
        }

        $parts = explode('.', $token);
        if (3 !== count($parts)) {
            throw new RuntimeException('GitHub OIDC token is malformed.');
        }

        $header = $this->decodeJsonSegment($parts[0], 'header');
        $claims = $this->decodeJsonSegment($parts[1], 'claims');
        $signature = $this->decodeBase64Url($parts[2], 'signature');

        if ('RS256' !== ($header['alg'] ?? null)) {
            throw new RuntimeException('GitHub OIDC token must use RS256.');
        }
        $kid = isset($header['kid']) && is_string($header['kid']) ? $header['kid'] : '';
        if ('' === $kid || strlen($kid) > 200) {
            throw new RuntimeException('GitHub OIDC key id is invalid.');
        }

        $this->assertClaims($claims, $expected);
        $publicKey = $this->publicKey($kid);
        $verified = openssl_verify($parts[0] . '.' . $parts[1], $signature, $publicKey, OPENSSL_ALGO_SHA256);
        if (1 !== $verified) {
            throw new RuntimeException('GitHub OIDC signature verification failed.');
        }

        if (null !== $lateExpected) {
            $this->assertExpectedClaims($claims, $lateExpected());
        }
        $this->assertNotReplayed($claims);
        return true;
    }

    private function assertClaims(array $claims, array $expected): void
    {
        $now = time();
        if (self::ISSUER !== ($claims['iss'] ?? null)) {
            throw new RuntimeException('GitHub OIDC issuer is invalid.');
        }
        if (! $this->audienceMatches($claims['aud'] ?? null, self::expectedAudience())) {
            throw new RuntimeException('GitHub OIDC audience is invalid.');
        }

        $exp = $this->integerClaim($claims, 'exp');
        $iat = $this->integerClaim($claims, 'iat');
        $nbf = array_key_exists('nbf', $claims) ? $this->integerClaim($claims, 'nbf') : $iat;
        if ($exp < $now - self::CLOCK_SKEW || $nbf > $now + self::CLOCK_SKEW || $iat > $now + self::CLOCK_SKEW) {
            throw new RuntimeException('GitHub OIDC token is outside its valid time window.');
        }
        if ($iat < $now - self::MAX_TOKEN_AGE || $exp <= $iat) {
            throw new RuntimeException('GitHub OIDC token is stale or invalid.');
        }

        $this->assertExpectedClaims($claims, $expected);

        if (! isset($claims['jti']) || ! is_string($claims['jti']) || '' === $claims['jti'] || strlen($claims['jti']) > 200) {
            throw new RuntimeException('GitHub OIDC token identifier is invalid.');
        }
    }

    private function assertExpectedClaims(array $claims, array $expected): void
    {
        foreach ($expected as $name => $value) {
            if (! isset($claims[$name]) || ! is_scalar($claims[$name]) || ! hash_equals((string) $value, (string) $claims[$name])) {
                throw new RuntimeException('GitHub OIDC claim is not trusted: ' . $name . '.');
            }
        }
    }

    private function assertNotReplayed(array $claims): void
    {
        $key = self::JTI_PREFIX . hash('sha256', (string) $claims['jti']);
        $ttl = max(60, min(self::MAX_TOKEN_AGE + self::CLOCK_SKEW, ((int) $claims['exp']) - time() + self::CLOCK_SKEW));
        $expiresAt = time() + $ttl;

        if (! add_option($key, $expiresAt, '', false)) {
            throw new RuntimeException('GitHub OIDC token was already used.');
        }

        $this->cleanupExpiredJtis();
    }

    private function cleanupExpiredJtis(): void
    {
        if (false !== get_transient(self::JTI_CLEANUP_TRANSIENT)) {
            return;
        }
        if (! set_transient(self::JTI_CLEANUP_TRANSIENT, '1', 60)) {
            return;
        }

        global $wpdb;
        if (! isset($wpdb->options) || ! is_string($wpdb->options)) {
            return;
        }
        $like = $wpdb->esc_like(self::JTI_PREFIX) . '%';
        $rows = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT option_name, option_value FROM {$wpdb->options} WHERE option_name LIKE %s LIMIT 200",
                $like
            )
        );
        $now = time();
        foreach ((array) $rows as $row) {
            $name = isset($row->option_name) ? (string) $row->option_name : '';
            $expiresAt = isset($row->option_value) ? (int) $row->option_value : 0;
            if ('' !== $name && 0 === strpos($name, self::JTI_PREFIX) && $expiresAt > 0 && $expiresAt < $now) {
                delete_option($name);
            }
        }
    }

    private function controllerMainSha(): string
    {
        $cached = get_transient(self::CONTROLLER_SHA_TRANSIENT);
        if (is_string($cached) && preg_match('/^[a-f0-9]{40}\z/', $cached)) {
            return $cached;
        }

        $response = wp_safe_remote_get('https://api.github.com/repos/Yolol100/wordpressconnector/commits/main', array(
            'timeout' => 5,
            'redirection' => 0,
            'sslverify' => true,
            'headers' => array(
                'Accept' => 'application/vnd.github+json',
                'User-Agent' => 'Webactueel-Mailbox-Bridge',
                'X-GitHub-Api-Version' => '2026-03-10',
            ),
        ));
        if (is_wp_error($response) || 200 !== (int) wp_remote_retrieve_response_code($response)) {
            throw new RuntimeException('Trusted mailbox controller revision could not be fetched.');
        }
        $body = (string) wp_remote_retrieve_body($response);
        if ('' === $body || strlen($body) > 262144) {
            throw new RuntimeException('Trusted mailbox controller revision response is invalid.');
        }
        try {
            $decoded = json_decode($body, true, 32, JSON_THROW_ON_ERROR);
        } catch (\JsonException $error) {
            throw new RuntimeException('Trusted mailbox controller revision response is invalid JSON.');
        }
        $sha = isset($decoded['sha']) && is_string($decoded['sha']) ? strtolower($decoded['sha']) : '';
        if (! preg_match('/^[a-f0-9]{40}\z/', $sha)) {
            throw new RuntimeException('Trusted mailbox controller revision is invalid.');
        }
        set_transient(self::CONTROLLER_SHA_TRANSIENT, $sha, 60);
        return $sha;
    }

    private function executorMainSha(): string
    {
        $cached = get_transient(self::EXECUTOR_SHA_TRANSIENT);
        if (is_string($cached) && preg_match('/^[a-f0-9]{40}\z/', $cached)) {
            return $cached;
        }

        $response = wp_safe_remote_get('https://api.github.com/repos/Yolol100/Leadscanner/commits/main', array(
            'timeout' => 5,
            'redirection' => 0,
            'sslverify' => true,
            'headers' => array(
                'Accept' => 'application/vnd.github+json',
                'User-Agent' => 'Webactueel-Mailbox-Bridge',
                'X-GitHub-Api-Version' => '2026-03-10',
            ),
        ));
        if (is_wp_error($response) || 200 !== (int) wp_remote_retrieve_response_code($response)) {
            throw new RuntimeException('Trusted executor revision could not be fetched.');
        }
        $body = (string) wp_remote_retrieve_body($response);
        if ('' === $body || strlen($body) > 262144) {
            throw new RuntimeException('Trusted executor revision response is invalid.');
        }
        try {
            $decoded = json_decode($body, true, 32, JSON_THROW_ON_ERROR);
        } catch (\JsonException $error) {
            throw new RuntimeException('Trusted executor revision response is invalid JSON.');
        }
        $sha = isset($decoded['sha']) && is_string($decoded['sha']) ? strtolower($decoded['sha']) : '';
        if (! preg_match('/^[a-f0-9]{40}\z/', $sha)) {
            throw new RuntimeException('Trusted executor revision is invalid.');
        }
        set_transient(self::EXECUTOR_SHA_TRANSIENT, $sha, 60);
        return $sha;
    }

    private function publicKey(string $kid)
    {
        $keys = $this->jwks(false);
        $key = $this->findKey($keys, $kid);
        if (null === $key) {
            $keys = $this->jwks(true);
            $key = $this->findKey($keys, $kid);
        }
        if (null === $key || 'RSA' !== ($key['kty'] ?? null) || 'RS256' !== ($key['alg'] ?? null)) {
            throw new RuntimeException('GitHub OIDC signing key is unavailable.');
        }

        $pem = $this->keyPem($key);
        $publicKey = openssl_pkey_get_public($pem);
        if (false === $publicKey) {
            throw new RuntimeException('GitHub OIDC public key could not be loaded.');
        }
        return $publicKey;
    }

    private function jwks(bool $forceRefresh): array
    {
        if (! $forceRefresh) {
            $cached = get_transient(self::JWKS_TRANSIENT);
            if (is_array($cached) && isset($cached['keys']) && is_array($cached['keys'])) {
                return $cached['keys'];
            }
        }

        if (! $this->claimJwksRefreshWindow()) {
            throw new RuntimeException('GitHub OIDC signing-key refresh is temporarily rate-limited.');
        }

        $response = wp_safe_remote_get(self::JWKS_URL, array(
            'timeout' => 5,
            'redirection' => 0,
            'sslverify' => true,
            'headers' => array('Accept' => 'application/json'),
        ));
        if (is_wp_error($response) || 200 !== (int) wp_remote_retrieve_response_code($response)) {
            throw new RuntimeException('GitHub OIDC signing keys could not be fetched.');
        }
        $body = (string) wp_remote_retrieve_body($response);
        if ('' === $body || strlen($body) > 262144) {
            throw new RuntimeException('GitHub OIDC signing-key response is invalid.');
        }
        try {
            $decoded = json_decode($body, true, 32, JSON_THROW_ON_ERROR);
        } catch (\JsonException $error) {
            throw new RuntimeException('GitHub OIDC signing-key response is invalid JSON.');
        }
        if (! is_array($decoded) || ! isset($decoded['keys']) || ! is_array($decoded['keys']) || count($decoded['keys']) > 20) {
            throw new RuntimeException('GitHub OIDC signing-key response has an invalid shape.');
        }
        set_transient(self::JWKS_TRANSIENT, $decoded, 6 * HOUR_IN_SECONDS);
        return $decoded['keys'];
    }

    private function claimJwksRefreshWindow(): bool
    {
        $now = time();
        $until = $now + 60;
        if (add_option(self::JWKS_REFRESH_OPTION, $until, '', false)) {
            return true;
        }

        $existing = get_option(self::JWKS_REFRESH_OPTION, 0);
        if ((int) $existing > $now) {
            return false;
        }

        global $wpdb;
        if (! isset($wpdb->options) || ! is_string($wpdb->options)) {
            return false;
        }
        $updated = $wpdb->update(
            $wpdb->options,
            array('option_value' => (string) $until),
            array('option_name' => self::JWKS_REFRESH_OPTION, 'option_value' => (string) $existing),
            array('%s'),
            array('%s', '%s')
        );
        if (1 !== $updated) {
            return false;
        }
        wp_cache_delete(self::JWKS_REFRESH_OPTION, 'options');
        return true;
    }

    private function findKey(array $keys, string $kid): ?array
    {
        foreach ($keys as $key) {
            if (is_array($key) && isset($key['kid']) && is_string($key['kid']) && hash_equals($kid, $key['kid'])) {
                return $key;
            }
        }
        return null;
    }

    private function keyPem(array $key): string
    {
        if (isset($key['x5c'][0]) && is_string($key['x5c'][0]) && '' !== $key['x5c'][0]) {
            return "-----BEGIN CERTIFICATE-----\n" . chunk_split($key['x5c'][0], 64, "\n") . "-----END CERTIFICATE-----\n";
        }
        if (! isset($key['n'], $key['e']) || ! is_string($key['n']) || ! is_string($key['e'])) {
            throw new RuntimeException('GitHub OIDC RSA key is incomplete.');
        }
        $modulus = $this->decodeBase64Url($key['n'], 'RSA modulus');
        $exponent = $this->decodeBase64Url($key['e'], 'RSA exponent');
        $rsa = $this->asn1Sequence($this->asn1Integer($modulus) . $this->asn1Integer($exponent));
        $algorithm = hex2bin('300d06092a864886f70d0101010500');
        if (false === $algorithm) {
            throw new RuntimeException('Could not construct RSA algorithm identifier.');
        }
        $bitString = "\x03" . $this->asn1Length(strlen($rsa) + 1) . "\x00" . $rsa;
        $spki = $this->asn1Sequence($algorithm . $bitString);
        return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($spki), 64, "\n") . "-----END PUBLIC KEY-----\n";
    }

    private function asn1Integer(string $bytes): string
    {
        $bytes = ltrim($bytes, "\x00");
        if ('' === $bytes) {
            $bytes = "\x00";
        }
        if ((ord($bytes[0]) & 0x80) !== 0) {
            $bytes = "\x00" . $bytes;
        }
        return "\x02" . $this->asn1Length(strlen($bytes)) . $bytes;
    }

    private function asn1Sequence(string $bytes): string
    {
        return "\x30" . $this->asn1Length(strlen($bytes)) . $bytes;
    }

    private function asn1Length(int $length): string
    {
        if ($length < 0x80) {
            return chr($length);
        }
        $encoded = '';
        while ($length > 0) {
            $encoded = chr($length & 0xff) . $encoded;
            $length >>= 8;
        }
        return chr(0x80 | strlen($encoded)) . $encoded;
    }

    private function decodeJsonSegment(string $segment, string $label): array
    {
        $json = $this->decodeBase64Url($segment, $label);
        try {
            $decoded = json_decode($json, true, 32, JSON_THROW_ON_ERROR);
        } catch (\JsonException $error) {
            throw new RuntimeException('GitHub OIDC ' . $label . ' is invalid JSON.');
        }
        if (! is_array($decoded)) {
            throw new RuntimeException('GitHub OIDC ' . $label . ' must be an object.');
        }
        return $decoded;
    }

    private function decodeBase64Url(string $value, string $label): string
    {
        if ('' === $value || false !== strpos($value, '=') || ! preg_match('/^[A-Za-z0-9_-]+\z/', $value)) {
            throw new RuntimeException('GitHub OIDC ' . $label . ' is not valid base64url.');
        }
        $remainder = strlen($value) % 4;
        if (1 === $remainder) {
            throw new RuntimeException('GitHub OIDC ' . $label . ' has invalid base64url length.');
        }
        $padded = strtr($value, '-_', '+/');
        if ($remainder > 0) {
            $padded .= str_repeat('=', 4 - $remainder);
        }
        $decoded = base64_decode($padded, true);
        if (false === $decoded) {
            throw new RuntimeException('GitHub OIDC ' . $label . ' could not be decoded.');
        }
        return $decoded;
    }

    private function audienceMatches($audience, string $expected): bool
    {
        if (is_string($audience)) {
            return hash_equals($expected, $audience);
        }
        if (! is_array($audience)) {
            return false;
        }
        foreach ($audience as $candidate) {
            if (is_string($candidate) && hash_equals($expected, $candidate)) {
                return true;
            }
        }
        return false;
    }

    private function integerClaim(array $claims, string $name): int
    {
        if (! array_key_exists($name, $claims) || (! is_int($claims[$name]) && ! ctype_digit((string) $claims[$name]))) {
            throw new RuntimeException('GitHub OIDC time claim is invalid: ' . $name . '.');
        }
        return (int) $claims[$name];
    }
}
