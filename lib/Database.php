<?php
declare(strict_types=1);

interface ProviderTokenCache
{
    public function getMeta(string $key): ?string;

    public function setMeta(string $key, string $value): void;

    public function deleteMeta(string $key): void;
}

/**
 * SQLite storage for device tokens, push history and small key/value state.
 *
 * Schema versions are tracked with PRAGMA user_version:
 *   0 - original layout (devices, push_history), no version recorded
 *   1 - adds devices.last_error / failure_count / deactivated_at, meta table,
 *       devices(is_active) index
 */
final class Database implements ProviderTokenCache
{
    public const SCHEMA_VERSION = 1;

    /** Consecutive BadDeviceToken responses before a device is deactivated. */
    public const BAD_TOKEN_THRESHOLD = 3;

    private PDO $pdo;

    public function __construct(string $path)
    {
        $dir = dirname($path);
        if (!is_dir($dir)) {
            throw new RuntimeException("Database directory does not exist: $dir");
        }
        if (!is_writable($dir)) {
            // SQLite writes a journal file next to the database.
            throw new RuntimeException("Database directory is not writable: $dir");
        }

        $this->pdo = new PDO('sqlite:' . $path, null, null, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        ]);
        // Concurrent requests wait for the write lock instead of failing.
        $this->pdo->exec('PRAGMA busy_timeout = 5000');

        if (is_file($path)) {
            @chmod($path, 0600);
        }

        $this->migrate();
    }

    public static function now(): string
    {
        return gmdate('Y-m-d\TH:i:s\Z');
    }

    // ------------------------------------------------------------------
    // Schema
    // ------------------------------------------------------------------

    public function schemaVersion(): int
    {
        return (int)$this->pdo->query('PRAGMA user_version')->fetchColumn();
    }

    private function migrate(): void
    {
        $version = $this->schemaVersion();
        if ($version === self::SCHEMA_VERSION) {
            return;
        }
        if ($version > self::SCHEMA_VERSION) {
            throw new RuntimeException(
                "Database schema v$version is newer than this server supports (v" . self::SCHEMA_VERSION . ')'
            );
        }

        // IMMEDIATE takes the write lock up front, so two requests can't both
        // run the migration; the second re-reads the version once it gets in.
        $this->pdo->exec('BEGIN IMMEDIATE');
        try {
            $version = $this->schemaVersion();

            if ($version < 1) {
                $this->pdo->exec('
                    CREATE TABLE IF NOT EXISTS devices (
                        device_token TEXT PRIMARY KEY,
                        registered_at TEXT NOT NULL,
                        last_push_at TEXT,
                        push_count INTEGER DEFAULT 0,
                        app_version TEXT,
                        device_name TEXT,
                        is_active INTEGER DEFAULT 1
                    )
                ');
                $this->pdo->exec('
                    CREATE TABLE IF NOT EXISTS push_history (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        device_token TEXT NOT NULL,
                        alert_type TEXT NOT NULL,
                        payload TEXT NOT NULL,
                        status TEXT NOT NULL,
                        apns_id TEXT,
                        sent_at TEXT NOT NULL,
                        error_message TEXT
                    )
                ');
                $this->pdo->exec('CREATE INDEX IF NOT EXISTS idx_push_history_device ON push_history(device_token)');
                $this->pdo->exec('CREATE INDEX IF NOT EXISTS idx_push_history_sent_at ON push_history(sent_at)');

                $this->addColumnIfMissing('devices', 'last_error', 'TEXT');
                $this->addColumnIfMissing('devices', 'failure_count', 'INTEGER NOT NULL DEFAULT 0');
                $this->addColumnIfMissing('devices', 'deactivated_at', 'TEXT');
                $this->pdo->exec('CREATE INDEX IF NOT EXISTS idx_devices_active ON devices(is_active)');

                $this->pdo->exec('
                    CREATE TABLE IF NOT EXISTS meta (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL
                    )
                ');
            }

            $this->pdo->exec('PRAGMA user_version = ' . self::SCHEMA_VERSION);
            $this->pdo->exec('COMMIT');
            error_log('Database migrated from schema v' . $version . ' to v' . self::SCHEMA_VERSION);
        } catch (Throwable $e) {
            $this->pdo->exec('ROLLBACK');
            throw $e;
        }
    }

    private function addColumnIfMissing(string $table, string $column, string $definition): void
    {
        foreach ($this->pdo->query("PRAGMA table_info($table)")->fetchAll() as $col) {
            if ($col['name'] === $column) {
                return;
            }
        }
        $this->pdo->exec("ALTER TABLE $table ADD COLUMN $column $definition");
    }

    // ------------------------------------------------------------------
    // Devices
    // ------------------------------------------------------------------

    /**
     * Register or refresh a device. Re-registering reactivates a device that
     * was previously deactivated.
     */
    public function registerDevice(string $token, ?string $appVersion, ?string $deviceName): void
    {
        $stmt = $this->pdo->prepare('
            INSERT INTO devices (device_token, registered_at, app_version, device_name, is_active)
            VALUES (:token, :now, :app_version, :device_name, 1)
            ON CONFLICT(device_token) DO UPDATE SET
                registered_at = excluded.registered_at,
                app_version = excluded.app_version,
                device_name = excluded.device_name,
                is_active = 1,
                failure_count = 0,
                last_error = NULL,
                deactivated_at = NULL
        ');
        $stmt->execute([
            ':token' => $token,
            ':now' => self::now(),
            ':app_version' => $appVersion,
            ':device_name' => $deviceName,
        ]);
    }

    public function getActiveDevice(string $token): ?array
    {
        $stmt = $this->pdo->prepare('SELECT * FROM devices WHERE lower(device_token) = :token AND is_active = 1');
        $stmt->execute([':token' => $token]);
        $row = $stmt->fetch();
        return $row ?: null;
    }

    public function getActiveDevices(): array
    {
        return $this->pdo->query('SELECT * FROM devices WHERE is_active = 1')->fetchAll();
    }

    public function getAllDevices(): array
    {
        return $this->pdo->query('
            SELECT device_token, registered_at, last_push_at, push_count, app_version,
                   device_name, is_active, failure_count, last_error, deactivated_at
            FROM devices
            ORDER BY registered_at DESC
        ')->fetchAll();
    }

    public function countActiveDevices(): int
    {
        return (int)$this->pdo->query('SELECT COUNT(*) FROM devices WHERE is_active = 1')->fetchColumn();
    }

    public function recordPushSuccess(string $token): void
    {
        $stmt = $this->pdo->prepare('
            UPDATE devices
            SET last_push_at = :now, push_count = push_count + 1, failure_count = 0, last_error = NULL
            WHERE device_token = :token
        ');
        $stmt->execute([':now' => self::now(), ':token' => $token]);
    }

    /**
     * Record a delivery failure. Returns true if the device was deactivated.
     *
     * @param bool $permanent  APNs said the token is gone (410 Unregistered).
     * @param bool $badToken   APNs rejected the token (400 BadDeviceToken). This
     *                         also happens when sandbox/production is mismatched,
     *                         so the device is only deactivated after several in
     *                         a row rather than on the first one.
     */
    public function recordPushFailure(string $token, string $reason, bool $permanent, bool $badToken): bool
    {
        $stmt = $this->pdo->prepare('
            UPDATE devices
            SET failure_count = failure_count + 1, last_error = :reason
            WHERE device_token = :token
        ');
        $stmt->execute([':reason' => $reason, ':token' => $token]);

        $deactivate = $permanent;
        if (!$deactivate && $badToken) {
            $stmt = $this->pdo->prepare('SELECT failure_count FROM devices WHERE device_token = :token');
            $stmt->execute([':token' => $token]);
            $deactivate = (int)$stmt->fetchColumn() >= self::BAD_TOKEN_THRESHOLD;
        }

        if ($deactivate) {
            $stmt = $this->pdo->prepare('
                UPDATE devices SET is_active = 0, deactivated_at = :now WHERE device_token = :token
            ');
            $stmt->execute([':now' => self::now(), ':token' => $token]);
        }
        return $deactivate;
    }

    /**
     * Delete devices with no push (or registration, if never pushed) in $days,
     * plus their history. Returns the number of devices deleted.
     */
    public function cleanupInactiveDevices(int $days): int
    {
        $cutoff = gmdate('Y-m-d\TH:i:s\Z', time() - $days * 86400);

        $this->pdo->exec('BEGIN IMMEDIATE');
        try {
            $stmt = $this->pdo->prepare('
                DELETE FROM devices
                WHERE COALESCE(last_push_at, registered_at) < :cutoff
                   OR (is_active = 0 AND COALESCE(deactivated_at, registered_at) < :cutoff)
            ');
            $stmt->execute([':cutoff' => $cutoff]);
            $deleted = $stmt->rowCount();

            $this->pdo->exec('
                DELETE FROM push_history
                WHERE device_token NOT IN (SELECT device_token FROM devices)
            ');
            $this->pdo->exec('COMMIT');
            return $deleted;
        } catch (Throwable $e) {
            $this->pdo->exec('ROLLBACK');
            throw $e;
        }
    }

    // ------------------------------------------------------------------
    // History
    // ------------------------------------------------------------------

    public function logPushHistory(
        string $token,
        string $alertType,
        string $payload,
        string $status,
        ?string $apnsId,
        ?string $error
    ): void {
        $stmt = $this->pdo->prepare('
            INSERT INTO push_history
                (device_token, alert_type, payload, status, apns_id, sent_at, error_message)
            VALUES (:token, :alert_type, :payload, :status, :apns_id, :now, :error)
        ');
        $stmt->execute([
            ':token' => $token,
            ':alert_type' => $alertType,
            ':payload' => $payload,
            ':status' => $status,
            ':apns_id' => $apnsId,
            ':now' => self::now(),
            ':error' => $error,
        ]);
    }

    /**
     * Delete history rows older than $days. Returns the number removed.
     */
    public function pruneHistory(int $days): int
    {
        $cutoff = gmdate('Y-m-d\TH:i:s\Z', time() - $days * 86400);
        $stmt = $this->pdo->prepare('DELETE FROM push_history WHERE sent_at < :cutoff');
        $stmt->execute([':cutoff' => $cutoff]);
        return $stmt->rowCount();
    }

    // ------------------------------------------------------------------
    // Key/value metadata (provider token cache)
    // ------------------------------------------------------------------

    public function getMeta(string $key): ?string
    {
        $stmt = $this->pdo->prepare('SELECT value FROM meta WHERE key = :key');
        $stmt->execute([':key' => $key]);
        $value = $stmt->fetchColumn();
        return $value === false ? null : (string)$value;
    }

    public function setMeta(string $key, string $value): void
    {
        $stmt = $this->pdo->prepare('
            INSERT INTO meta (key, value) VALUES (:key, :value)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
        ');
        $stmt->execute([':key' => $key, ':value' => $value]);
    }

    public function deleteMeta(string $key): void
    {
        $stmt = $this->pdo->prepare('DELETE FROM meta WHERE key = :key');
        $stmt->execute([':key' => $key]);
    }
}
