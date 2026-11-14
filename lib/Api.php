<?php
declare(strict_types=1);

/**
 * Endpoint handlers and request validation.
 */
final class Api
{
    public const VERSION = '2.0.0';

    private const INTERRUPTION_LEVELS = ['passive', 'active', 'time-sensitive'];

    private ?APNsClient $apns = null;

    public function __construct(private Config $config, private Database $db)
    {
    }

    /**
     * Dispatch a request. Auth is checked before the method so unauthenticated
     * callers learn nothing about which methods an endpoint accepts.
     */
    public function dispatch(string $method, string $path): void
    {
        switch ($path) {
            case '/':
            case '/health':
                $this->requireMethod($method, ['GET', 'HEAD']);
                $this->health();
                return;
            case '/register':
                $this->requireAuth();
                $this->requireMethod($method, ['POST']);
                $this->register();
                return;
            case '/alert':
                $this->requireAuth();
                $this->requireMethod($method, ['POST']);
                $this->alert();
                return;
            case '/test':
                $this->requireAuth();
                $this->requireMethod($method, ['POST']);
                $this->test();
                return;
            case '/devices':
                $this->requireAuth();
                $this->requireMethod($method, ['GET']);
                $this->devices();
                return;
            case '/cleanup':
                $this->requireAuth();
                $this->requireMethod($method, ['POST']);
                $this->cleanup();
                return;
        }
        Http::error('Not found', 404);
    }

    // ------------------------------------------------------------------
    // Auth
    // ------------------------------------------------------------------

    public function isAuthenticated(): bool
    {
        $presented = '';
        $auth = Http::authorizationHeader();
        if ($auth !== '' && stripos($auth, 'Bearer ') === 0) {
            $presented = trim(substr($auth, 7));
        } elseif (Http::apiKeyHeader() !== '') {
            $presented = Http::apiKeyHeader();
        }
        return $presented !== '' && hash_equals($this->config->apiKey, $presented);
    }

    private function requireAuth(): void
    {
        if (Http::authorizationHeader() === '' && Http::apiKeyHeader() === '') {
            Http::error('Missing Authorization header', 401);
        }
        if (!$this->isAuthenticated()) {
            Http::error('Invalid API key', 403);
        }
    }

    private function requireMethod(string $method, array $allowed): void
    {
        if (!in_array($method, $allowed, true)) {
            if (!headers_sent()) {
                header('Allow: ' . implode(', ', $allowed));
            }
            Http::error('Method not allowed', 405);
        }
    }

    // ------------------------------------------------------------------
    // Endpoints
    // ------------------------------------------------------------------

    private function health(): void
    {
        $response = [
            'status' => 'healthy',
            'version' => self::VERSION,
            'timestamp' => Database::now(),
        ];

        // Device counts and environment are only shown to authenticated
        // callers unless PUBLIC_HEALTH_DETAILS is enabled.
        if ($this->config->publicHealthDetails || $this->isAuthenticated()) {
            $response['environment'] = $this->config->production ? 'production' : 'sandbox';
            $response['active_devices'] = $this->db->countActiveDevices();
            $response['http2'] = APNsClient::supportsHttp2();
            $response['apns_key_readable'] = is_readable($this->config->keyPath);
            $response['schema_version'] = $this->db->schemaVersion();
        }

        Http::json($response);
    }

    private function register(): void
    {
        $data = Http::jsonBody();

        $token = $this->deviceToken($data, true);
        $appVersion = $this->optionalString($data, 'app_version', 64);
        $deviceName = $this->optionalString($data, 'device_name', 128);

        $this->db->registerDevice($token, $appVersion, $deviceName);
        error_log('Registered device ' . substr($token, 0, 8) . '...');

        Http::json(['success' => true, 'message' => 'Device registered successfully']);
    }

    private function alert(): void
    {
        $data = Http::jsonBody();

        $title = $this->optionalString($data, 'title', 256) ?? $this->config->defaultAlertTitle;
        $body = $this->optionalString($data, 'body', 2048);
        if ($body === null || $body === '') {
            Http::error('Missing alert body', 400);
        }
        $subtitle = $this->optionalString($data, 'subtitle', 256);
        $sound = $this->optionalString($data, 'sound', 64) ?? 'default';
        $badge = $this->optionalBadge($data);

        $alertType = $this->optionalString($data, 'alert_type', 64) ?? 'general';
        $severity = $this->optionalString($data, 'severity', 32) ?? 'info';
        $hostname = $this->optionalString($data, 'hostname', 255);
        $shortcutName = $this->optionalString($data, 'shortcut_name', 255);
        $extra = $this->optionalData($data);

        $level = $this->optionalString($data, 'interruption_level', 32);
        if ($level !== null && !in_array($level, self::INTERRUPTION_LEVELS, true)) {
            Http::error('interruption_level must be one of: ' . implode(', ', self::INTERRUPTION_LEVELS), 400);
        }
        $threadId = $this->optionalString($data, 'thread_id', 64);
        $collapseId = $this->optionalString($data, 'collapse_id', 64);
        if ($collapseId !== null && strlen($collapseId) > 64) {
            Http::error('collapse_id must be at most 64 bytes', 400);
        }

        // Target one device or every active device.
        $targetToken = $this->deviceToken($data, false);
        if ($targetToken !== null) {
            $device = $this->db->getActiveDevice($targetToken);
            $devices = $device ? [$device] : [];
        } else {
            $devices = $this->db->getActiveDevices();
        }
        if (!$devices) {
            Http::error('No active devices found', 404);
        }

        $alert = ['title' => $title, 'body' => $body];
        if ($subtitle !== null && $subtitle !== '') {
            $alert['subtitle'] = $subtitle;
        }
        $aps = ['alert' => $alert, 'sound' => $sound];
        if ($badge !== null) {
            $aps['badge'] = $badge;
        }
        if ($level !== null) {
            $aps['interruption-level'] = $level;
        }
        if ($threadId !== null && $threadId !== '') {
            $aps['thread-id'] = $threadId;
        }

        $custom = ['alert_type' => $alertType, 'severity' => $severity];
        if ($hostname !== null && $hostname !== '') {
            $custom['hostname'] = $hostname;
        }
        if ($shortcutName !== null && $shortcutName !== '') {
            $custom['shortcut_name'] = $shortcutName;
        }
        if ($extra) {
            $custom['data'] = $extra;
        }

        $payload = self::fitPayload(array_merge(['aps' => $aps], $custom));
        $options = ['priority' => $level === 'passive' ? 5 : 10, 'collapse_id' => $collapseId];

        $historyPayload = substr((string)json_encode($data, JSON_UNESCAPED_SLASHES), 0, 8192);

        $results = [];
        $successCount = 0;
        foreach ($devices as $device) {
            $token = (string)$device['device_token'];
            $result = $this->apns()->send($token, $payload, $options);

            $deactivated = false;
            if ($result['success']) {
                $this->db->recordPushSuccess($token);
                $successCount++;
            } elseif ($result['status'] === 410 || $result['reason'] === 'BadDeviceToken') {
                // Only answers about this token count against the device.
                // Transport errors, provider-token and other server-side
                // problems would otherwise deactivate every device at once.
                $deactivated = $this->db->recordPushFailure(
                    $token,
                    (string)$result['error'],
                    $result['status'] === 410,
                    $result['reason'] === 'BadDeviceToken'
                );
            }

            $this->db->logPushHistory(
                $token,
                $alertType,
                $historyPayload,
                $result['success'] ? 'sent' : 'failed',
                $result['apns_id'],
                $result['error']
            );

            $entry = [
                'device_token' => substr($token, 0, 8) . '...',
                'success' => $result['success'],
                'apns_id' => $result['apns_id'],
                'error' => $result['error'],
            ];
            if ($deactivated) {
                $entry['deactivated'] = true;
            }
            $results[] = $entry;
        }

        Http::json([
            'success' => true,
            'devices_notified' => $successCount,
            'total_devices' => count($results),
            'results' => $results,
        ]);
    }

    private function test(): void
    {
        $data = Http::jsonBody();
        $token = $this->deviceToken($data, true);

        $result = $this->apns()->send($token, [
            'aps' => [
                'alert' => [
                    'title' => 'Test Notification',
                    'body' => 'Push notifications are working.',
                ],
                'sound' => 'default',
            ],
            'alert_type' => 'test',
        ]);

        if ($result['success']) {
            Http::json([
                'success' => true,
                'apns_id' => $result['apns_id'],
                'message' => 'Test notification sent successfully',
            ]);
        }
        Http::json(['success' => false, 'error' => $result['error']], 502);
    }

    private function devices(): void
    {
        $devices = $this->db->getAllDevices();
        Http::json(['total' => count($devices), 'devices' => $devices]);
    }

    private function cleanup(): void
    {
        $data = Http::jsonBody();
        $days = 90;
        if (array_key_exists('days', $data)) {
            if (!is_int($data['days']) || $data['days'] < 1 || $data['days'] > 3650) {
                Http::error('days must be an integer between 1 and 3650', 400);
            }
            $days = $data['days'];
        }

        $deleted = $this->db->cleanupInactiveDevices($days);
        $historyDeleted = $this->db->pruneHistory($this->config->historyRetentionDays);
        error_log("Cleanup removed $deleted inactive device(s) and $historyDeleted history row(s)");

        Http::json([
            'success' => true,
            'deleted_count' => $deleted,
            'history_deleted_count' => $historyDeleted,
        ]);
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    /**
     * The APNs client is created on first use so /health and /register keep
     * working even when the .p8 key is missing or broken.
     */
    private function apns(): APNsClient
    {
        if ($this->apns === null) {
            if (!APNsClient::supportsHttp2()) {
                error_log('PHP cURL was built without HTTP/2 support; APNs requires HTTP/2');
            }
            $this->apns = new APNsClient(
                $this->config->keyId,
                $this->config->teamId,
                $this->config->keyPath,
                $this->config->bundleId,
                $this->config->production,
                $this->db,
                $this->config->apnsHostOverride
            );
        }
        return $this->apns;
    }

    /**
     * Normalise and validate a device token: hex, case-insensitive, and
     * tolerant of the "<abcd ef01 ...>" form Data.description used to print.
     */
    private function deviceToken(array $data, bool $required): ?string
    {
        $value = $data['device_token'] ?? null;
        if ($value === null || $value === '') {
            if ($required) {
                Http::error('Missing device_token', 400);
            }
            return null;
        }
        if (!is_string($value)) {
            Http::error('device_token must be a string', 400);
        }
        $token = strtolower(str_replace([' ', '<', '>'], '', $value));
        if (!preg_match('/^[0-9a-f]{64,200}$/', $token)) {
            Http::error('device_token must be a hexadecimal APNs token', 400);
        }
        return $token;
    }

    private function optionalString(array $data, string $key, int $maxChars): ?string
    {
        if (!array_key_exists($key, $data) || $data[$key] === null) {
            return null;
        }
        $value = $data[$key];
        if (is_int($value) || is_float($value)) {
            $value = (string)$value;
        }
        if (!is_string($value)) {
            Http::error("$key must be a string", 400);
        }
        if (!mb_check_encoding_compat($value)) {
            Http::error("$key must be valid UTF-8", 400);
        }
        if (strlen_chars($value) > $maxChars) {
            Http::error("$key must be at most $maxChars characters", 400);
        }
        return $value;
    }

    private function optionalBadge(array $data): ?int
    {
        if (!array_key_exists('badge', $data) || $data['badge'] === null) {
            return null;
        }
        $badge = $data['badge'];
        if (is_string($badge) && ctype_digit($badge)) {
            $badge = (int)$badge;
        }
        if (!is_int($badge) || $badge < 0 || $badge > 99999) {
            Http::error('badge must be a non-negative integer', 400);
        }
        return $badge;
    }

    /**
     * Free-form "data" object: up to 20 keys of scalar values, passed through
     * to the app under the "data" payload key.
     */
    private function optionalData(array $data): array
    {
        if (!isset($data['data'])) {
            return [];
        }
        $value = $data['data'];
        if (!is_array($value) || ($value !== [] && array_is_list_compat($value))) {
            Http::error('data must be a JSON object', 400);
        }
        if (count($value) > 20) {
            Http::error('data may have at most 20 keys', 400);
        }
        $clean = [];
        foreach ($value as $k => $v) {
            $k = (string)$k;
            if ($k === '' || strlen($k) > 64) {
                Http::error('data keys must be 1-64 characters', 400);
            }
            if ($v !== null && !is_scalar($v)) {
                Http::error("data.$k must be a string, number, boolean or null", 400);
            }
            if (is_string($v) && strlen_chars($v) > 512) {
                Http::error("data.$k must be at most 512 characters", 400);
            }
            $clean[$k] = $v;
        }
        return $clean;
    }

    /**
     * Shorten the alert body so the encoded payload fits within APNs' 4 KB
     * limit. Alerts are more useful truncated than rejected.
     */
    public static function fitPayload(array $payload): array
    {
        $limit = APNsClient::MAX_PAYLOAD_BYTES;
        for ($i = 0; $i < 8; $i++) {
            $size = strlen((string)json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
            if ($size <= $limit) {
                return $payload;
            }
            $body = (string)($payload['aps']['alert']['body'] ?? '');
            if ($body === '') {
                break;
            }
            $keep = max(0, strlen($body) - ($size - $limit) - 16);
            $payload['aps']['alert']['body'] = utf8_truncate($body, $keep) . '…';
        }
        return $payload; // Still too large; APNsClient will report PayloadTooLarge.
    }
}

function mb_check_encoding_compat(string $s): bool
{
    if (function_exists('mb_check_encoding')) {
        return mb_check_encoding($s, 'UTF-8');
    }
    return preg_match('//u', $s) === 1;
}

function strlen_chars(string $s): int
{
    if (function_exists('mb_strlen')) {
        return mb_strlen($s, 'UTF-8');
    }
    return (int)preg_match_all('/./us', $s);
}

/**
 * Cut a UTF-8 string to at most $bytes bytes without splitting a character.
 */
function utf8_truncate(string $s, int $bytes): string
{
    if (strlen($s) <= $bytes) {
        return $s;
    }
    if (function_exists('mb_strcut')) {
        return mb_strcut($s, 0, $bytes, 'UTF-8');
    }
    $cut = substr($s, 0, $bytes);
    // Drop a trailing partial multi-byte sequence.
    return (string)preg_replace('/[\xC0-\xFF][\x80-\xBF]*$/', '', $cut);
}
