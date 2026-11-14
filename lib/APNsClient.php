<?php
declare(strict_types=1);

/**
 * APNs HTTP/2 client using token-based (.p8 / JWT ES256) authentication.
 *
 * Provider tokens are cached in the database rather than in memory. PHP builds
 * a fresh client on every request, so an in-memory cache would mint a new JWT
 * per request. Apple rejects tokens refreshed more often than every 20 minutes
 * (429 TooManyProviderTokenUpdates) and expires them after 60, so the token is
 * reused for 50 minutes.
 */
final class APNsClient
{
    public const HOST_PRODUCTION = 'api.push.apple.com';
    public const HOST_SANDBOX = 'api.sandbox.push.apple.com';

    /** Maximum APNs payload size for alert notifications, in bytes. */
    public const MAX_PAYLOAD_BYTES = 4096;

    private const TOKEN_TTL_SECONDS = 50 * 60;
    private const TOKEN_CACHE_KEY = 'apns_provider_token';

    /** @var resource|\CurlHandle|null */
    private $curl = null;
    private ?string $token = null;

    public function __construct(
        private string $keyId,
        private string $teamId,
        private string $keyPath,
        private string $bundleId,
        private bool $production,
        private ProviderTokenCache $cache,
        private string $hostOverride = ''
    ) {
    }

    public static function supportsHttp2(): bool
    {
        if (!function_exists('curl_version') || !defined('CURL_VERSION_HTTP2')) {
            return false;
        }
        $info = curl_version();
        return is_array($info) && (($info['features'] ?? 0) & CURL_VERSION_HTTP2) !== 0;
    }

    public function host(): string
    {
        if ($this->hostOverride !== '') {
            return $this->hostOverride;
        }
        return $this->production ? self::HOST_PRODUCTION : self::HOST_SANDBOX;
    }

    // ------------------------------------------------------------------
    // Sending
    // ------------------------------------------------------------------

    /**
     * Send one notification.
     *
     * @param array $payload  Full APNs payload including the "aps" dictionary.
     * @param array $options  apns-* header options: priority (int), expiration
     *                        (unix time), collapse_id (string).
     * @return array{success: bool, status: int, apns_id: ?string, reason: ?string, error: ?string}
     */
    public function send(string $deviceToken, array $payload, array $options = []): array
    {
        if (!preg_match('/^[0-9a-fA-F]{64,200}$/', $deviceToken)) {
            return self::result(false, 0, null, 'BadDeviceToken', 'Malformed device token');
        }

        $json = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if ($json === false) {
            return self::result(false, 0, null, null, 'Could not encode payload: ' . json_last_error_msg());
        }
        if (strlen($json) > self::MAX_PAYLOAD_BYTES) {
            return self::result(false, 0, null, 'PayloadTooLarge', 'Payload exceeds 4096 bytes');
        }

        try {
            $token = $this->providerToken();
        } catch (Throwable $e) {
            error_log('APNs provider token error: ' . $e->getMessage());
            return self::result(false, 0, null, null, 'Server could not create APNs credentials');
        }

        $headers = [
            'authorization: bearer ' . $token,
            'apns-topic: ' . $this->bundleId,
            'apns-push-type: alert',
            'apns-priority: ' . (int)($options['priority'] ?? 10),
            'content-type: application/json',
        ];
        if (isset($options['expiration'])) {
            $headers[] = 'apns-expiration: ' . (int)$options['expiration'];
        }
        if (!empty($options['collapse_id'])) {
            $headers[] = 'apns-collapse-id: ' . $options['collapse_id'];
        }

        $url = 'https://' . $this->host() . '/3/device/' . $deviceToken;

        // One retry for transport errors and Apple-side 500/503s.
        $attempts = 0;
        do {
            $attempts++;
            $result = $this->post($url, $headers, $json);
            $retry = $attempts < 2 && ($result['status'] === 0 || in_array($result['status'], [500, 503], true));
            if ($retry) {
                usleep(250000);
            }
        } while ($retry);

        $prefix = substr($deviceToken, 0, 8) . '...';
        if ($result['success']) {
            error_log("Push sent to $prefix (apns-id: {$result['apns_id']})");
            return $result;
        }

        error_log("Push failed for $prefix: {$result['error']}");

        if ($result['status'] === 403 && $result['reason'] === 'ExpiredProviderToken') {
            $this->cache->deleteMeta(self::TOKEN_CACHE_KEY);
            $this->token = null;
        } elseif ($result['status'] === 403 && $result['reason'] === 'InvalidProviderToken') {
            error_log('APNs rejected the provider token: check APNS_KEY_ID, APNS_TEAM_ID and the .p8 key');
        } elseif ($result['reason'] === 'BadDeviceToken') {
            error_log('BadDeviceToken can mean a sandbox/production mismatch: APNS_PRODUCTION is '
                . ($this->production ? 'true' : 'false'));
        }

        return $result;
    }

    private function post(string $url, array $headers, string $body): array
    {
        if ($this->curl === null) {
            $this->curl = curl_init();
        }
        // Reusing the handle keeps the HTTP/2 connection open across devices.
        curl_setopt_array($this->curl, [
            CURLOPT_URL => $url,
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $body,
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER => true,
            CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_2_0,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_TIMEOUT => 10,
        ]);

        $response = curl_exec($this->curl);
        if ($response === false) {
            return self::result(false, 0, null, null, 'cURL error: ' . curl_error($this->curl));
        }

        $status = (int)curl_getinfo($this->curl, CURLINFO_HTTP_CODE);
        $headerSize = (int)curl_getinfo($this->curl, CURLINFO_HEADER_SIZE);
        $rawHeaders = substr((string)$response, 0, $headerSize);
        $rawBody = substr((string)$response, $headerSize);

        $apnsId = null;
        if (preg_match('/^apns-id:\s*([A-Za-z0-9-]+)/mi', $rawHeaders, $m)) {
            $apnsId = $m[1];
        }

        if ($status === 200) {
            return self::result(true, 200, $apnsId, null, null);
        }

        $decoded = json_decode($rawBody, true);
        $reason = is_array($decoded) && isset($decoded['reason']) ? (string)$decoded['reason'] : 'Unknown';
        return self::result(false, $status, $apnsId, $reason, "$status: $reason");
    }

    private static function result(bool $success, int $status, ?string $apnsId, ?string $reason, ?string $error): array
    {
        return [
            'success' => $success,
            'status' => $status,
            'apns_id' => $apnsId,
            'reason' => $reason,
            'error' => $error,
        ];
    }

    // ------------------------------------------------------------------
    // Provider token (JWT)
    // ------------------------------------------------------------------

    private function providerToken(): string
    {
        if ($this->token !== null) {
            return $this->token;
        }

        $now = time();
        $fingerprint = hash('sha256', $this->keyId . '|' . $this->teamId);

        $cached = $this->cache->getMeta(self::TOKEN_CACHE_KEY);
        if ($cached !== null) {
            $entry = json_decode($cached, true);
            if (
                is_array($entry)
                && ($entry['fp'] ?? null) === $fingerprint
                && is_int($entry['iat'] ?? null)
                && $now - $entry['iat'] < self::TOKEN_TTL_SECONDS
                && $now >= $entry['iat']
                && is_string($entry['token'] ?? null)
            ) {
                return $this->token = $entry['token'];
            }
        }

        $token = self::createJwt($this->keyId, $this->teamId, $this->loadPrivateKey(), $now);
        $this->cache->setMeta(self::TOKEN_CACHE_KEY, (string)json_encode([
            'token' => $token,
            'iat' => $now,
            'fp' => $fingerprint,
        ]));
        error_log('Generated new APNs provider token');
        return $this->token = $token;
    }

    /**
     * @return OpenSSLAsymmetricKey|resource
     */
    private function loadPrivateKey()
    {
        if (!is_file($this->keyPath) || !is_readable($this->keyPath)) {
            throw new RuntimeException('APNs .p8 key not found or unreadable at APNS_KEY_PATH');
        }
        $pem = (string)file_get_contents($this->keyPath);
        $key = openssl_pkey_get_private($pem);
        if ($key === false) {
            throw new RuntimeException('Could not parse APNs .p8 key: ' . (string)openssl_error_string());
        }
        $details = openssl_pkey_get_details($key);
        if (!is_array($details) || ($details['type'] ?? null) !== OPENSSL_KEYTYPE_EC) {
            throw new RuntimeException('APNs key is not an EC (P-256) key');
        }
        return $key;
    }

    /**
     * Build an ES256-signed JWT.
     *
     * @param OpenSSLAsymmetricKey|resource $privateKey
     */
    public static function createJwt(string $keyId, string $teamId, $privateKey, int $issuedAt): string
    {
        $header = self::base64Url((string)json_encode(['alg' => 'ES256', 'kid' => $keyId]));
        $claims = self::base64Url((string)json_encode(['iss' => $teamId, 'iat' => $issuedAt]));
        $signingInput = $header . '.' . $claims;

        $der = '';
        if (!openssl_sign($signingInput, $der, $privateKey, OPENSSL_ALGO_SHA256)) {
            throw new RuntimeException('Failed to sign JWT: ' . (string)openssl_error_string());
        }

        return $signingInput . '.' . self::base64Url(self::derToRaw($der));
    }

    /**
     * Convert an ASN.1 DER ECDSA signature to the 64-byte r||s form JWS uses.
     */
    public static function derToRaw(string $der): string
    {
        $len = strlen($der);
        $pos = 0;

        if ($len < 8 || ord($der[$pos++]) !== 0x30) {
            throw new RuntimeException('Invalid DER signature: expected SEQUENCE');
        }
        $seqLen = ord($der[$pos++]);
        if ($seqLen & 0x80) {
            $pos += $seqLen & 0x7F;
        }

        $out = '';
        for ($i = 0; $i < 2; $i++) {
            if ($pos + 2 > $len || ord($der[$pos++]) !== 0x02) {
                throw new RuntimeException('Invalid DER signature: expected INTEGER');
            }
            $intLen = ord($der[$pos++]);
            if ($pos + $intLen > $len) {
                throw new RuntimeException('Invalid DER signature: truncated INTEGER');
            }
            $int = ltrim(substr($der, $pos, $intLen), "\x00");
            $pos += $intLen;
            if (strlen($int) > 32) {
                throw new RuntimeException('Invalid DER signature: INTEGER longer than 32 bytes');
            }
            $out .= str_pad($int, 32, "\x00", STR_PAD_LEFT);
        }
        return $out;
    }

    private static function base64Url(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }
}
