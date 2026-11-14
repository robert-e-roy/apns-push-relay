<?php
declare(strict_types=1);

final class ConfigException extends RuntimeException
{
}

/**
 * Loads and validates settings from config.php and/or environment variables.
 *
 * config.php defines constants (see config.example.php); any setting it
 * leaves out is read from an environment variable of the same name. Required values
 * are checked up front so a typo produces one clear log line instead of a
 * fatal error halfway through a request.
 */
final class Config
{
    public string $keyId;
    public string $teamId;
    public string $keyPath;
    public string $bundleId;
    public bool $production;
    public string $apiKey;
    public string $dbPath;
    public string $corsAllowOrigin;
    public string $defaultAlertTitle;
    public int $historyRetentionDays;
    public bool $publicHealthDetails;
    /** Host override for tests only (e.g. "127.0.0.1:9"). Empty in production. */
    public string $apnsHostOverride;

    private const PLACEHOLDER_MARKERS = ['your_', 'change_me', 'changeme', 'example'];

    /**
     * Where to find the config file: $APNS_RELAY_CONFIG if set (lets you keep
     * it outside the web root), otherwise config.php next to index.php.
     */
    public static function locate(string $appDir): string
    {
        $env = getenv('APNS_RELAY_CONFIG');
        if (is_string($env) && $env !== '') {
            return $env;
        }
        return $appDir . '/config.php';
    }

    /**
     * A setting from a config.php constant, falling back to an environment
     * variable of the same name. Returns null if neither is set.
     */
    private static function setting(string $name): ?string
    {
        if (defined($name)) {
            $value = constant($name);
            return is_bool($value) ? ($value ? '1' : '0') : (string)$value;
        }
        $env = getenv($name);
        return is_string($env) ? $env : null;
    }

    private static function flag(string $name, bool $default): bool
    {
        $v = self::setting($name);
        if ($v === null || trim($v) === '') {
            return $default;
        }
        return in_array(strtolower(trim($v)), ['1', 'true', 'yes', 'on'], true);
    }

    /**
     * Load settings from config.php if it exists, with environment variables
     * filling in anything it doesn't define. Either source alone is enough.
     */
    public static function load(string $path): self
    {
        $explicit = is_string(getenv('APNS_RELAY_CONFIG')) && getenv('APNS_RELAY_CONFIG') !== '';
        if (is_file($path)) {
            if (!is_readable($path)) {
                throw new ConfigException("Config file is not readable: $path");
            }
            require_once $path;
        } elseif ($explicit) {
            throw new ConfigException("APNS_RELAY_CONFIG points to a missing file: $path");
        }

        // All timestamps are written with gmdate(); pin UTC so an invalid
        // timezone in an older config.php can't emit notices.
        date_default_timezone_set('UTC');

        $missing = [];
        foreach (['APNS_KEY_ID', 'APNS_TEAM_ID', 'APNS_KEY_PATH', 'APNS_BUNDLE_ID', 'API_KEY', 'DB_PATH'] as $name) {
            if (self::setting($name) === null) {
                $missing[] = $name;
            }
        }
        if ($missing) {
            throw new ConfigException(
                'Missing required setting(s): ' . implode(', ', $missing)
                . ' (define them in config.php or as environment variables)'
            );
        }

        $c = new self();
        $c->keyId = trim((string)self::setting('APNS_KEY_ID'));
        $c->teamId = trim((string)self::setting('APNS_TEAM_ID'));
        $c->keyPath = (string)self::setting('APNS_KEY_PATH');
        $c->bundleId = trim((string)self::setting('APNS_BUNDLE_ID'));
        $c->apiKey = (string)self::setting('API_KEY');
        $c->dbPath = (string)self::setting('DB_PATH');
        $c->production = self::flag('APNS_PRODUCTION', false);
        $c->corsAllowOrigin = trim((string)(self::setting('CORS_ALLOW_ORIGIN') ?? ''));
        $c->defaultAlertTitle = self::setting('DEFAULT_ALERT_TITLE') ?? 'Alert';
        $c->historyRetentionDays = (int)(self::setting('HISTORY_RETENTION_DAYS') ?? 30);
        $c->publicHealthDetails = self::flag('PUBLIC_HEALTH_DETAILS', false);
        $c->apnsHostOverride = trim((string)(self::setting('APNS_HOST_OVERRIDE') ?? ''));

        $c->validate();
        return $c;
    }

    private function validate(): void
    {
        $errors = [];

        if (!preg_match('/^[A-Z0-9]{10}$/', $this->keyId)) {
            $errors[] = 'APNS_KEY_ID must be the 10-character key ID from the Apple Developer portal';
        }
        if (!preg_match('/^[A-Z0-9]{10}$/', $this->teamId)) {
            $errors[] = 'APNS_TEAM_ID must be your 10-character Apple Team ID';
        }
        if ($this->keyPath === '') {
            $errors[] = 'APNS_KEY_PATH is empty';
        }
        if (!preg_match('/^[A-Za-z0-9\-]+(\.[A-Za-z0-9\-]+)+$/', $this->bundleId)) {
            $errors[] = 'APNS_BUNDLE_ID must be a reverse-DNS bundle identifier';
        }
        if (strlen($this->apiKey) < 32) {
            $errors[] = 'API_KEY must be at least 32 characters (generate one with: openssl rand -hex 32)';
        }
        foreach (self::PLACEHOLDER_MARKERS as $marker) {
            if (stripos($this->apiKey, $marker) !== false) {
                $errors[] = 'API_KEY still contains the placeholder from config.php.example';
                break;
            }
        }
        if ($this->dbPath === '') {
            $errors[] = 'DB_PATH is empty';
        }
        if ($this->historyRetentionDays < 1) {
            $errors[] = 'HISTORY_RETENTION_DAYS must be at least 1';
        }
        if ($this->apnsHostOverride !== '' && !preg_match('/^[A-Za-z0-9.\-]+(:\d+)?$/', $this->apnsHostOverride)) {
            $errors[] = 'APNS_HOST_OVERRIDE must be host or host:port';
        }

        if ($errors) {
            throw new ConfigException(implode('; ', $errors));
        }
    }
}
