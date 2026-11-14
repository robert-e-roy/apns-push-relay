<?php
declare(strict_types=1);

/**
 * APNs Push Relay
 *
 * A small, dependency-free PHP service that stores APNs device tokens and
 * relays alert notifications to them. Designed for ordinary shared hosting:
 * PHP 8.0+, SQLite, cURL with HTTP/2, no Composer.
 */

if (PHP_SAPI === 'cli') {
    fwrite(STDERR, "index.php is the web entry point; serve it with a web server (or php -S for testing).\n");
    exit(1);
}

error_reporting(E_ALL);
ini_set('display_errors', '0');
ini_set('log_errors', '1');
if (getenv('APNS_RELAY_ERROR_LOG') === false) {
    ini_set('error_log', __DIR__ . '/error.log');
}

require __DIR__ . '/lib/Http.php';
require __DIR__ . '/lib/Config.php';
require __DIR__ . '/lib/Database.php';
require __DIR__ . '/lib/APNsClient.php';
require __DIR__ . '/lib/Api.php';

// Never echo internal details (file paths, SQL errors) to clients.
set_exception_handler(static function (Throwable $e): void {
    error_log('Unhandled ' . get_class($e) . ': ' . $e->getMessage() . ' at ' . $e->getFile() . ':' . $e->getLine());
    Http::error('Internal server error', 500);
});

try {
    $config = Config::load(Config::locate(__DIR__));
} catch (ConfigException $e) {
    error_log('Configuration error: ' . $e->getMessage());
    Http::error('Server is not configured', 500);
    exit;
}

// CORS is off by default: native apps and server agents don't need it.
if ($config->corsAllowOrigin !== '') {
    header('Access-Control-Allow-Origin: ' . $config->corsAllowOrigin);
    header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type, Authorization, X-API-Key');
    header('Vary: Origin');
}
if (Http::method() === 'OPTIONS') {
    http_response_code(204);
    exit;
}

try {
    $db = new Database($config->dbPath);
} catch (Throwable $e) {
    error_log('Database unavailable: ' . $e->getMessage());
    Http::json(['status' => 'unhealthy', 'error' => 'Database unavailable'], 503);
    exit;
}

(new Api($config, $db))->dispatch(Http::method(), Http::routePath());
