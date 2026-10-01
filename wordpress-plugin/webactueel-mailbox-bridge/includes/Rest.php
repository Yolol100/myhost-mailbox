<?php

declare(strict_types=1);

namespace Webactueel\MailboxBridge;

use RuntimeException;
use Throwable;

final class Rest
{
    private const NAMESPACE = 'webactueel-mailbox-bridge/v1';
    private const MAX_REQUEST_BODY_BYTES = 400000;
    private const MAX_RESULT_BODY_BYTES = 4194304;

    private const ACTIONS = array(
        'list_folders','list_messages','search','read','read_attachment','read_attachment_chunk',
        'read_body_chunk','thread','create_folder','rename_folder','delete_folder','mark_read',
        'mark_unread','flag','unflag','copy','move','archive','trash','junk','delete',
        'create_draft','replace_draft','send','reply','reply_all','forward','send_draft'
    );
    private const SEND_ACTIONS = array('send','reply','reply_all','forward','send_draft');
    private const DESTRUCTIVE_ACTIONS = array('delete','delete_folder','replace_draft');

    private Store $store;
    private Oidc $oidc;
    private Crypto $crypto;

    public function __construct(Store $store, Oidc $oidc, Crypto $crypto)
    {
        $this->store = $store;
        $this->oidc = $oidc;
        $this->crypto = $crypto;
    }

    public function register(): void
    {
        add_action('rest_api_init', array($this, 'registerRoutes'));
    }

    public function registerRoutes(): void
    {
        register_rest_route(self::NAMESPACE, '/crypto-key', array(
            'methods' => \WP_REST_Server::READABLE,
            'callback' => array($this, 'publicKey'),
            'permission_callback' => array($this, 'allowPublicKey'),
        ));

        register_rest_route(self::NAMESPACE, '/requests/(?P<request_id>[A-Za-z0-9][A-Za-z0-9._-]{7,99})', array(
            array(
                'methods' => \WP_REST_Server::CREATABLE,
                'callback' => array($this, 'storeRequest'),
                'permission_callback' => array($this, 'authorizePrivate'),
            ),
            array(
                'methods' => \WP_REST_Server::READABLE,
                'callback' => array($this, 'readRequestForExecutor'),
                'permission_callback' => array($this, 'authorizeExecutor'),
            ),
        ));

        register_rest_route(self::NAMESPACE, '/results/(?P<request_id>[A-Za-z0-9][A-Za-z0-9._-]{7,99})', array(
            array(
                'methods' => \WP_REST_Server::CREATABLE,
                'callback' => array($this, 'storeResult'),
                'permission_callback' => array($this, 'authorizeExecutor'),
            ),
            array(
                'methods' => \WP_REST_Server::READABLE,
                'callback' => array($this, 'readResult'),
                'permission_callback' => array($this, 'authorizePrivate'),
            ),
        ));

        register_rest_route(self::NAMESPACE, '/state/(?P<request_id>[A-Za-z0-9][A-Za-z0-9._-]{7,99})', array(
            'methods' => \WP_REST_Server::DELETABLE,
            'callback' => array($this, 'clearState'),
            'permission_callback' => array($this, 'authorizePrivate'),
        ));
    }

    public function authorizePrivate(\WP_REST_Request $request)
    {
        return $this->authorize($request, 'private');
    }

    public function authorizeExecutor(\WP_REST_Request $request)
    {
        return $this->authorize($request, 'executor');
    }

    public function allowPublicKey(\WP_REST_Request $request)
    {
        if (! is_ssl()) {
            return new \WP_Error('mailbox_https_required', 'Mailbox bridge requires HTTPS.', array('status' => 403));
        }
        return true;
    }

    public function publicKey(\WP_REST_Request $request): \WP_REST_Response
    {
        return new \WP_REST_Response($this->crypto->publicKeyPayload(), 200);
    }

    public function storeRequest(\WP_REST_Request $request)
    {
        $body = (string) $request->get_body();
        if ('' === $body || strlen($body) > self::MAX_REQUEST_BODY_BYTES) {
            return new \WP_Error('mailbox_request_size', 'Encrypted mailbox request is empty or too large.', array('status' => 413));
        }

        $envelope = $request->get_json_params();
        if (! is_array($envelope)) {
            return new \WP_Error('mailbox_request_json', 'Encrypted mailbox request must be a JSON object.', array('status' => 400));
        }

        try {
            $data = $this->crypto->decryptRequestEnvelope($envelope);
            $allowed = array('request_id', 'request', 'ttl', 'response_public_key_pem');
            foreach (array_keys($data) as $key) {
                if (! in_array((string) $key, $allowed, true)) {
                    throw new RuntimeException('Encrypted mailbox request plaintext contains an unsupported key.');
                }
            }
            foreach ($allowed as $required) {
                if (! array_key_exists($required, $data)) {
                    throw new RuntimeException('Encrypted mailbox request plaintext is incomplete.');
                }
            }

            $requestId = (string) $request->get_param('request_id');
            if (! isset($data['request_id']) || ! is_string($data['request_id']) || ! hash_equals($requestId, $data['request_id'])) {
                throw new RuntimeException('Encrypted mailbox request_id does not match the route.');
            }
            if (! isset($data['request']) || ! is_array($data['request'])) {
                throw new RuntimeException('Encrypted mailbox request payload is invalid.');
            }
            if (is_bool($data['ttl']) || ! is_int($data['ttl']) || $data['ttl'] < 60 || $data['ttl'] > 86400) {
                throw new RuntimeException('Encrypted mailbox request ttl must be an integer from 60 to 86400.');
            }
            if (! isset($data['response_public_key_pem']) || ! is_string($data['response_public_key_pem'])) {
                throw new RuntimeException('Encrypted mailbox response public key is missing.');
            }

            $mailRequest = $data['request'];
            $this->assertMailboxRequest($mailRequest);
            $responsePublicKey = $this->crypto->normalizeClientPublicKey($data['response_public_key_pem']);
            $stored = $this->store->putRequest($requestId, $mailRequest, $data['ttl'], $responsePublicKey);
            return new \WP_REST_Response(array('ok' => true, 'stored' => $stored), 201);
        } catch (Throwable $error) {
            return new \WP_Error('mailbox_request_rejected', 'Encrypted mailbox request was rejected.', array('status' => 400));
        }
    }

    public function readRequestForExecutor(\WP_REST_Request $request)
    {
        try {
            $requestId = (string) $request->get_param('request_id');
            $record = $this->store->getRequest($requestId);
            return new \WP_REST_Response(array(
                'request_id' => $requestId,
                'request' => $record['request'],
                'sha256' => $record['sha256'],
                'expires_at' => $record['expires_at'],
            ), 200);
        } catch (Throwable $error) {
            return new \WP_Error('mailbox_request_unavailable', 'Mailbox request was not found or expired.', array('status' => 404));
        }
    }

    public function storeResult(\WP_REST_Request $request)
    {
        $body = (string) $request->get_body();
        if ('' === $body || strlen($body) > self::MAX_RESULT_BODY_BYTES) {
            return new \WP_Error('mailbox_result_size', 'Mailbox result is empty or too large.', array('status' => 413));
        }

        try {
            $shape = json_decode($body, false, 32, JSON_THROW_ON_ERROR);
        } catch (\JsonException $error) {
            return new \WP_Error('mailbox_result_json', 'Mailbox result must be valid JSON.', array('status' => 400));
        }
        if (! is_object($shape)) {
            return new \WP_Error('mailbox_result_json', 'Mailbox result must be a JSON object.', array('status' => 400));
        }

        $data = $request->get_json_params();
        if (! is_array($data)) {
            return new \WP_Error('mailbox_result_json', 'Mailbox result must be a JSON object.', array('status' => 400));
        }

        try {
            $requestId = (string) $request->get_param('request_id');
            $requestHash = strtolower((string) $request->get_header('x-webactueel-mailbox-request-sha256'));
            $stored = $this->store->putResult($requestId, $data, $requestHash);
            return new \WP_REST_Response(array('ok' => true, 'stored' => $stored), 201);
        } catch (Throwable $error) {
            return new \WP_Error('mailbox_result_rejected', $error->getMessage(), array('status' => 400));
        }
    }

    public function readResult(\WP_REST_Request $request)
    {
        try {
            $requestId = (string) $request->get_param('request_id');
            $result = $this->store->getResult($requestId);
            if (empty($result['ready'])) {
                return new \WP_Error('mailbox_result_unavailable', 'Mailbox result is unavailable.', array('status' => 404));
            }
            $responsePublicKey = $this->store->getResponsePublicKey($requestId);
            return new \WP_REST_Response(array(
                'request_id' => $requestId,
                'encrypted' => true,
                'envelope' => $this->crypto->encryptResultEnvelope($result, $responsePublicKey),
            ), 200);
        } catch (Throwable $error) {
            return new \WP_Error('mailbox_result_unavailable', 'Mailbox result is unavailable.', array('status' => 404));
        }
    }

    public function clearState(\WP_REST_Request $request)
    {
        try {
            $requestId = (string) $request->get_param('request_id');
            $this->store->clear($requestId);
            return new \WP_REST_Response(array('ok' => true, 'request_id' => $requestId, 'cleared' => true), 200);
        } catch (Throwable $error) {
            return new \WP_Error('mailbox_clear_failed', $error->getMessage(), array('status' => 400));
        }
    }

    private function authorize(\WP_REST_Request $request, string $profile)
    {
        if (! is_ssl()) {
            return new \WP_Error('mailbox_https_required', 'Mailbox bridge requires HTTPS.', array('status' => 403));
        }

        try {
            $ok = 'executor' === $profile
                ? $this->oidc->authenticateExecutor($request)
                : $this->oidc->authenticatePrivate($request);
        } catch (RuntimeException $error) {
            return new \WP_Error('mailbox_oidc_rejected', 'Mailbox bridge authentication was rejected.', array('status' => 401));
        }

        if (! $ok) {
            return new \WP_Error('mailbox_auth_required', 'Mailbox bridge authentication is required.', array('status' => 401));
        }
        return true;
    }

    private function assertMailboxRequest(array $request): void
    {
        $action = isset($request['action']) && is_string($request['action']) ? $request['action'] : '';
        if (! in_array($action, self::ACTIONS, true)) {
            throw new RuntimeException('Mailbox action is not allowed.');
        }
        if (in_array($action, self::SEND_ACTIONS, true) && true !== ($request['confirm_send'] ?? false)) {
            throw new RuntimeException('Send-like mailbox actions require confirm_send=true.');
        }
        if (in_array($action, self::DESTRUCTIVE_ACTIONS, true) && true !== ($request['confirm'] ?? false)) {
            throw new RuntimeException('Destructive mailbox actions require confirm=true.');
        }
    }
}
