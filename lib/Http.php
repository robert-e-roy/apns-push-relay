<?php
declare(strict_types=1);

/**
 * Minimal HTTP helpers: JSON responses, request body parsing, header access.
 */
final class Http
{
    /** Largest request body accepted, in bytes. */
    public const MAX_BODY_BYTES = 65536;

    /**
     * Send a JSON response and stop the request.
     */
    public static function json(array $data, int $status = 200): void
    {
        if (!headers_sent()) {
            http_response_code($status);
            header('Content-Type: application/json; charset=utf-8');
            header('Cache-Control: no-store');
            header('X-Content-Type-Options: nosniff');
        }
        echo json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
        exit;
    }

    public static function error(string $message, int $status): void
    {
        self::json(['error' => $message], $status);
    }

    public static function method(): string
    {
        return strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? 'GET'));
    }

    /**
     * Resolve the route path relative to the directory the server is installed in.
     *
     * Handles "/push/health", "/push/index.php/health" and, under the PHP
     * built-in server, "/health".
     */
    public static function routePath(): string
    {
        $path = parse_url((string)($_SERVER['REQUEST_URI'] ?? '/'), PHP_URL_PATH);
        $path = is_string($path) ? $path : '/';

        $script = str_replace('\\', '/', (string)($_SERVER['SCRIPT_NAME'] ?? ''));
        $base = rtrim(str_replace('\\', '/', dirname($script)), '/');

        if ($base !== '' && $base !== '.' && strncmp($path, $base . '/', strlen($base) + 1) === 0) {
            $path = substr($path, strlen($base));
        } elseif ($base !== '' && $path === $base) {
            $path = '/';
        }

        if (strncmp($path, '/index.php', 10) === 0) {
            $path = substr($path, 10);
        }

        $path = '/' . trim($path, '/');
        return $path;
    }

    /**
     * Read the Authorization header across Apache/CGI/FPM configurations.
     */
    public static function authorizationHeader(): string
    {
        foreach (['HTTP_AUTHORIZATION', 'REDIRECT_HTTP_AUTHORIZATION'] as $key) {
            if (!empty($_SERVER[$key])) {
                return trim((string)$_SERVER[$key]);
            }
        }
        if (function_exists('getallheaders')) {
            foreach ((array)getallheaders() as $name => $value) {
                if (strcasecmp((string)$name, 'Authorization') === 0) {
                    return trim((string)$value);
                }
            }
        }
        return '';
    }

    /**
     * Read the alternative X-API-Key header.
     */
    public static function apiKeyHeader(): string
    {
        return trim((string)($_SERVER['HTTP_X_API_KEY'] ?? ''));
    }

    /**
     * Decode a JSON object request body. An empty body is treated as {}.
     */
    public static function jsonBody(): array
    {
        $raw = file_get_contents('php://input', false, null, 0, self::MAX_BODY_BYTES + 1);
        if ($raw === false) {
            self::error('Could not read request body', 400);
        }
        if (strlen($raw) > self::MAX_BODY_BYTES) {
            self::error('Request body too large', 413);
        }
        if (trim($raw) === '') {
            return [];
        }

        $data = json_decode($raw, true, 16);
        if (json_last_error() !== JSON_ERROR_NONE) {
            self::error('Invalid JSON: ' . json_last_error_msg(), 400);
        }
        if (!is_array($data) || ($data !== [] && array_is_list_compat($data))) {
            self::error('Request body must be a JSON object', 400);
        }
        return $data;
    }
}

/**
 * array_is_list() exists from PHP 8.1; this keeps PHP 8.0 working.
 */
function array_is_list_compat(array $a): bool
{
    if (function_exists('array_is_list')) {
        return array_is_list($a);
    }
    $i = 0;
    foreach ($a as $k => $_) {
        if ($k !== $i++) {
            return false;
        }
    }
    return true;
}
