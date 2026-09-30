<?php

declare(strict_types=1);

namespace Webactueel\MailboxBridge;

use RuntimeException;

final class Store
{
    private const REQUEST_PREFIX = 'webactueel_mailbox_request_';
    private const RESULT_PREFIX = 'webactueel_mailbox_result_';
    private const LOCK_PREFIX = 'webactueel_mailbox_lock_';
    private const DEFAULT_TTL = 3600;
    private const MAX_TTL = 86400;
    private const LOCK_TTL = 60;
    private const MAX_REQUEST_BYTES = 262144;
    private const MAX_RESULT_BYTES = 4194304;

    public function putRequest(string $requestId, array $request, int $ttl = self::DEFAULT_TTL): array
    {
        $this->assertRequestId($requestId);
        $encoded = $this->encodeBounded($request, self::MAX_REQUEST_BYTES, 'Mailbox request');
        $ttl = max(60, min(self::MAX_TTL, $ttl));
        $token = $this->acquireLock($requestId);
        if ('' === $token) {
            throw new RuntimeException('Mailbox request state is busy. Retry later.');
        }

        try {
            $key = $this->key(self::REQUEST_PREFIX, $requestId);
            $hash = hash('sha256', $encoded);
            $existing = get_transient($key);
            if (is_array($existing)) {
                $existingHash = isset($existing['sha256']) ? (string) $existing['sha256'] : '';
                if (! hash_equals($hash, $existingHash)) {
                    throw new RuntimeException('Mailbox request_id already exists with different content.');
                }
                return $this->publicState($existing, false);
            }

            $now = time();
            $record = array(
                'request_id' => $requestId,
                'request' => $request,
                'sha256' => $hash,
                'created_at' => $now,
                'expires_at' => $now + $ttl,
            );
            if (! set_transient($key, $record, $ttl)) {
                throw new RuntimeException('Mailbox request could not be stored.');
            }
            delete_transient($this->key(self::RESULT_PREFIX, $requestId));
            return $this->publicState($record, true);
        } finally {
            $this->releaseLock($requestId, $token);
        }
    }

    public function getRequest(string $requestId): array
    {
        $this->assertRequestId($requestId);
        $record = get_transient($this->key(self::REQUEST_PREFIX, $requestId));
        if (! is_array($record) || ! isset($record['request']) || ! is_array($record['request'])) {
            throw new RuntimeException('Mailbox request was not found or expired.');
        }
        return $record;
    }

    public function putResult(string $requestId, array $result, string $expectedRequestHash): array
    {
        $this->assertRequestId($requestId);
        if (! preg_match('/^[a-f0-9]{64}\z/', $expectedRequestHash)) {
            throw new RuntimeException('Mailbox request hash is invalid.');
        }
        $encoded = $this->encodeBounded($result, self::MAX_RESULT_BYTES, 'Mailbox result');
        $token = $this->acquireLock($requestId);
        if ('' === $token) {
            throw new RuntimeException('Mailbox request state is busy. Retry later.');
        }

        try {
            $request = $this->getRequest($requestId);
            $currentHash = isset($request['sha256']) ? (string) $request['sha256'] : '';
            if (! hash_equals($currentHash, $expectedRequestHash)) {
                throw new RuntimeException('Mailbox request changed before result storage.');
            }

            $key = $this->key(self::RESULT_PREFIX, $requestId);
            $hash = hash('sha256', $encoded);
            $existing = get_transient($key);
            if (is_array($existing)) {
                $existingHash = isset($existing['sha256']) ? (string) $existing['sha256'] : '';
                if (! hash_equals($hash, $existingHash)) {
                    throw new RuntimeException('Mailbox result already exists with different content.');
                }
                return $this->publicState($existing, false);
            }

            $now = time();
            $expiresAt = max($now + 60, (int) ($request['expires_at'] ?? ($now + self::DEFAULT_TTL)));
            $ttl = min(self::MAX_TTL, max(60, $expiresAt - $now));
            $record = array(
                'request_id' => $requestId,
                'result' => $result,
                'sha256' => $hash,
                'created_at' => $now,
                'expires_at' => $now + $ttl,
            );
            if (! set_transient($key, $record, $ttl)) {
                throw new RuntimeException('Mailbox result could not be stored.');
            }
            return $this->publicState($record, true);
        } finally {
            $this->releaseLock($requestId, $token);
        }
    }

    public function getResult(string $requestId): array
    {
        $this->assertRequestId($requestId);
        $record = get_transient($this->key(self::RESULT_PREFIX, $requestId));
        if (! is_array($record) || ! isset($record['result']) || ! is_array($record['result'])) {
            return array('request_id' => $requestId, 'ready' => false);
        }
        return array(
            'request_id' => $requestId,
            'ready' => true,
            'sha256' => (string) ($record['sha256'] ?? ''),
            'created_at' => (int) ($record['created_at'] ?? 0),
            'expires_at' => (int) ($record['expires_at'] ?? 0),
            'result' => $record['result'],
        );
    }

    public function clear(string $requestId): void
    {
        $this->assertRequestId($requestId);
        $token = $this->acquireLock($requestId);
        if ('' === $token) {
            throw new RuntimeException('Mailbox request state is busy. Retry later.');
        }
        try {
            $requestKey = $this->key(self::REQUEST_PREFIX, $requestId);
            $resultKey = $this->key(self::RESULT_PREFIX, $requestId);
            delete_transient($requestKey);
            delete_transient($resultKey);
            if (false !== get_transient($requestKey) || false !== get_transient($resultKey)) {
                throw new RuntimeException('Mailbox bridge cleanup could not be verified.');
            }
        } finally {
            $this->releaseLock($requestId, $token);
        }
    }

    private function publicState(array $record, bool $created): array
    {
        return array(
            'request_id' => (string) $record['request_id'],
            'created' => $created,
            'sha256' => (string) $record['sha256'],
            'expires_at' => (int) $record['expires_at'],
        );
    }

    private function encodeBounded(array $value, int $maxBytes, string $label): string
    {
        $encoded = wp_json_encode($value, JSON_UNESCAPED_SLASHES);
        if (! is_string($encoded)) {
            throw new RuntimeException($label . ' could not be encoded.');
        }
        if (strlen($encoded) > $maxBytes) {
            throw new RuntimeException($label . ' exceeds the bounded size limit.');
        }
        return $encoded;
    }

    private function assertRequestId(string $requestId): void
    {
        if (! preg_match('/^[A-Za-z0-9][A-Za-z0-9._-]{7,99}\z/', $requestId)) {
            throw new RuntimeException('Mailbox request_id is invalid.');
        }
    }

    private function acquireLock(string $requestId): string
    {
        $key = self::LOCK_PREFIX . hash('sha256', $requestId);
        $token = function_exists('wp_generate_uuid4') ? wp_generate_uuid4() : bin2hex(random_bytes(16));
        $value = wp_json_encode(array('token' => $token, 'created_at' => time()));
        if (! is_string($value)) {
            return '';
        }
        if (add_option($key, $value, '', false)) {
            return $token;
        }

        $existing = get_option($key, '');
        $data = is_string($existing) ? json_decode($existing, true) : null;
        if (! is_string($existing) || ! is_array($data) || time() - (int) ($data['created_at'] ?? time()) <= self::LOCK_TTL) {
            return '';
        }

        global $wpdb;
        $updated = $wpdb->update(
            $wpdb->options,
            array('option_value' => $value),
            array('option_name' => $key, 'option_value' => $existing),
            array('%s'),
            array('%s', '%s')
        );
        if (1 !== $updated) {
            return '';
        }
        wp_cache_delete($key, 'options');
        return $token;
    }

    private function releaseLock(string $requestId, string $token): void
    {
        $key = self::LOCK_PREFIX . hash('sha256', $requestId);
        $existing = get_option($key, '');
        $data = is_string($existing) ? json_decode($existing, true) : null;
        if (! is_string($existing) || ! is_array($data) || ! hash_equals((string) ($data['token'] ?? ''), $token)) {
            return;
        }

        global $wpdb;
        $deleted = $wpdb->delete(
            $wpdb->options,
            array('option_name' => $key, 'option_value' => $existing),
            array('%s', '%s')
        );
        if (1 === $deleted) {
            wp_cache_delete($key, 'options');
        }
    }

    private function key(string $prefix, string $requestId): string
    {
        return $prefix . hash('sha256', $requestId);
    }
}
