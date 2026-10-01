<?php

declare(strict_types=1);

namespace Webactueel\MailboxBridge;

use RuntimeException;

final class Crypto
{
    private const KEY_OPTION = 'webactueel_secret_mailbox_crypto_key_v1';
    private const ALGORITHM = 'rsa-oaep-aes-256-gcm-v1';
    private const REQUEST_AAD = 'webactueel-mailbox-request-v1';
    private const RESULT_AAD = 'webactueel-mailbox-result-v1';
    private const RSA_BITS = 3072;
    private const MAX_REQUEST_PLAINTEXT_BYTES = 300000;
    private const MAX_RESULT_PLAINTEXT_BYTES = 4194304;

    public function publicKeyPayload(): array
    {
        $record = $this->keyRecord();
        return array(
            'version' => 1,
            'algorithm' => self::ALGORITHM,
            'key_id' => (string) $record['key_id'],
            'public_key_pem' => (string) $record['public_key_pem'],
        );
    }

    public function decryptRequestEnvelope(array $envelope): array
    {
        $allowed = array('version', 'algorithm', 'key_id', 'wrapped_key', 'iv', 'tag', 'ciphertext');
        $this->assertExactKeys($envelope, $allowed, 'Encrypted mailbox request envelope');

        if (1 !== ($envelope['version'] ?? null) || self::ALGORITHM !== ($envelope['algorithm'] ?? null)) {
            throw new RuntimeException('Encrypted mailbox request envelope version or algorithm is invalid.');
        }

        $record = $this->keyRecord();
        $keyId = isset($envelope['key_id']) && is_string($envelope['key_id']) ? $envelope['key_id'] : '';
        if ('' === $keyId || ! hash_equals((string) $record['key_id'], $keyId)) {
            throw new RuntimeException('Encrypted mailbox request key id is stale or invalid.');
        }

        $wrapped = $this->decodeBase64Url((string) ($envelope['wrapped_key'] ?? ''), 'wrapped_key', 8192);
        $iv = $this->decodeBase64Url((string) ($envelope['iv'] ?? ''), 'iv', 64);
        $tag = $this->decodeBase64Url((string) ($envelope['tag'] ?? ''), 'tag', 64);
        $ciphertext = $this->decodeBase64Url(
            (string) ($envelope['ciphertext'] ?? ''),
            'ciphertext',
            self::MAX_REQUEST_PLAINTEXT_BYTES + 1024
        );

        if (12 !== strlen($iv) || 16 !== strlen($tag) || '' === $ciphertext) {
            throw new RuntimeException('Encrypted mailbox request nonce, tag or ciphertext has an invalid size.');
        }

        $privateKey = openssl_pkey_get_private((string) $record['private_key_pem']);
        if (false === $privateKey) {
            throw new RuntimeException('Mailbox transport private key could not be loaded.');
        }

        $aesKey = '';
        if (! openssl_private_decrypt($wrapped, $aesKey, $privateKey, OPENSSL_PKCS1_OAEP_PADDING) || 32 !== strlen($aesKey)) {
            throw new RuntimeException('Encrypted mailbox request key unwrap failed.');
        }

        $plaintext = openssl_decrypt(
            $ciphertext,
            'aes-256-gcm',
            $aesKey,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            self::REQUEST_AAD
        );
        $aesKey = str_repeat("\0", strlen($aesKey));

        if (! is_string($plaintext) || '' === $plaintext || strlen($plaintext) > self::MAX_REQUEST_PLAINTEXT_BYTES) {
            throw new RuntimeException('Encrypted mailbox request could not be authenticated or exceeds the size limit.');
        }

        try {
            $decoded = json_decode($plaintext, true, 32, JSON_THROW_ON_ERROR);
        } catch (\JsonException $error) {
            throw new RuntimeException('Encrypted mailbox request plaintext is invalid JSON.');
        }
        if (! is_array($decoded)) {
            throw new RuntimeException('Encrypted mailbox request plaintext must be a JSON object.');
        }
        return $decoded;
    }

    public function normalizeClientPublicKey(string $pem): string
    {
        if ('' === $pem || strlen($pem) > 8192) {
            throw new RuntimeException('Mailbox response public key is missing or too large.');
        }
        $key = openssl_pkey_get_public($pem);
        if (false === $key) {
            throw new RuntimeException('Mailbox response public key is invalid.');
        }
        $details = openssl_pkey_get_details($key);
        if (! is_array($details) || OPENSSL_KEYTYPE_RSA !== ($details['type'] ?? null)) {
            throw new RuntimeException('Mailbox response public key must be RSA.');
        }
        $bits = isset($details['bits']) ? (int) $details['bits'] : 0;
        if ($bits < 2048 || $bits > 4096 || empty($details['key']) || ! is_string($details['key'])) {
            throw new RuntimeException('Mailbox response RSA key size is outside the allowed range.');
        }
        return (string) $details['key'];
    }

    public function encryptResultEnvelope(array $result, string $clientPublicKey): array
    {
        $clientPublicKey = $this->normalizeClientPublicKey($clientPublicKey);
        $plaintext = wp_json_encode($result, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if (! is_string($plaintext) || strlen($plaintext) > self::MAX_RESULT_PLAINTEXT_BYTES) {
            throw new RuntimeException('Mailbox result exceeds the encrypted transport size limit.');
        }

        $aesKey = random_bytes(32);
        $iv = random_bytes(12);
        $tag = '';
        $ciphertext = openssl_encrypt(
            $plaintext,
            'aes-256-gcm',
            $aesKey,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            self::RESULT_AAD,
            16
        );
        if (! is_string($ciphertext) || 16 !== strlen($tag)) {
            throw new RuntimeException('Mailbox result encryption failed.');
        }

        $publicKey = openssl_pkey_get_public($clientPublicKey);
        if (false === $publicKey) {
            throw new RuntimeException('Mailbox response public key could not be loaded.');
        }
        $wrapped = '';
        if (! openssl_public_encrypt($aesKey, $wrapped, $publicKey, OPENSSL_PKCS1_OAEP_PADDING)) {
            throw new RuntimeException('Mailbox result key wrapping failed.');
        }
        $aesKey = str_repeat("\0", strlen($aesKey));

        return array(
            'version' => 1,
            'algorithm' => self::ALGORITHM,
            'response_key_id' => hash('sha256', $clientPublicKey),
            'wrapped_key' => $this->encodeBase64Url($wrapped),
            'iv' => $this->encodeBase64Url($iv),
            'tag' => $this->encodeBase64Url($tag),
            'ciphertext' => $this->encodeBase64Url($ciphertext),
        );
    }

    private function keyRecord(): array
    {
        $existing = get_option(self::KEY_OPTION, false);
        if (is_array($existing) && $this->validKeyRecord($existing)) {
            return $existing;
        }

        if (! function_exists('openssl_pkey_new') || ! function_exists('openssl_encrypt')) {
            throw new RuntimeException('Mailbox encrypted transport requires the PHP OpenSSL extension.');
        }

        $key = openssl_pkey_new(array(
            'private_key_bits' => self::RSA_BITS,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ));
        if (false === $key) {
            throw new RuntimeException('Mailbox transport RSA key generation failed.');
        }

        $privatePem = '';
        if (! openssl_pkey_export($key, $privatePem) || '' === $privatePem) {
            throw new RuntimeException('Mailbox transport RSA private key export failed.');
        }
        $details = openssl_pkey_get_details($key);
        if (! is_array($details) || empty($details['key']) || ! is_string($details['key'])) {
            throw new RuntimeException('Mailbox transport RSA public key export failed.');
        }

        $record = array(
            'version' => 1,
            'algorithm' => self::ALGORITHM,
            'key_id' => hash('sha256', (string) $details['key']),
            'public_key_pem' => (string) $details['key'],
            'private_key_pem' => $privatePem,
            'created_at' => time(),
        );

        if (add_option(self::KEY_OPTION, $record, '', false)) {
            return $record;
        }

        $stored = get_option(self::KEY_OPTION, false);
        if (! is_array($stored) || ! $this->validKeyRecord($stored)) {
            throw new RuntimeException('Mailbox transport RSA key state could not be persisted.');
        }
        return $stored;
    }

    private function validKeyRecord(array $record): bool
    {
        if (1 !== ($record['version'] ?? null) || self::ALGORITHM !== ($record['algorithm'] ?? null)) {
            return false;
        }
        $public = isset($record['public_key_pem']) && is_string($record['public_key_pem']) ? $record['public_key_pem'] : '';
        $private = isset($record['private_key_pem']) && is_string($record['private_key_pem']) ? $record['private_key_pem'] : '';
        $keyId = isset($record['key_id']) && is_string($record['key_id']) ? $record['key_id'] : '';
        if ('' === $public || '' === $private || ! preg_match('/^[a-f0-9]{64}\z/', $keyId)) {
            return false;
        }
        if (! hash_equals(hash('sha256', $public), $keyId)) {
            return false;
        }
        return false !== openssl_pkey_get_private($private) && false !== openssl_pkey_get_public($public);
    }

    private function assertExactKeys(array $value, array $allowed, string $label): void
    {
        $actual = array_keys($value);
        sort($actual);
        sort($allowed);
        if ($actual !== $allowed) {
            throw new RuntimeException($label . ' has an invalid shape.');
        }
    }

    private function encodeBase64Url(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }

    private function decodeBase64Url(string $value, string $label, int $maxBytes): string
    {
        if ('' === $value || false !== strpos($value, '=') || ! preg_match('/^[A-Za-z0-9_-]+\z/', $value)) {
            throw new RuntimeException('Encrypted mailbox ' . $label . ' is not valid base64url.');
        }
        $remainder = strlen($value) % 4;
        if (1 === $remainder) {
            throw new RuntimeException('Encrypted mailbox ' . $label . ' has invalid base64url length.');
        }
        $padded = strtr($value, '-_', '+/');
        if ($remainder > 0) {
            $padded .= str_repeat('=', 4 - $remainder);
        }
        $decoded = base64_decode($padded, true);
        if (false === $decoded || strlen($decoded) > $maxBytes) {
            throw new RuntimeException('Encrypted mailbox ' . $label . ' is invalid or too large.');
        }
        return $decoded;
    }
}
