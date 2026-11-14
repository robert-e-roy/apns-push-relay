<?php
declare(strict_types=1);

/**
 * Dependency-free unit tests. Run: php tests/unit.php
 */

error_reporting(E_ALL);
ini_set('display_errors', '1');
set_error_handler(static function (int $no, string $msg, string $file, int $line): bool {
    throw new ErrorException($msg, 0, $no, $file, $line);
});

$root = dirname(__DIR__);
require $root . '/lib/Http.php';
require $root . '/lib/Database.php';
require $root . '/lib/APNsClient.php';
require $root . '/lib/Config.php';
require $root . '/lib/Api.php';

ini_set('error_log', '/dev/null'); // keep library logging out of test output

$failures = 0;
$count = 0;
function check(string $name, bool $ok, string $detail = ''): void
{
    global $failures, $count;
    $count++;
    if ($ok) {
        echo "  ok   $name\n";
    } else {
        $failures++;
        echo "  FAIL $name" . ($detail !== '' ? " -- $detail" : '') . "\n";
    }
}

function rawToDer(string $raw): string
{
    $enc = static function (string $int): string {
        $int = ltrim($int, "\x00");
        if ($int === '' || (ord($int[0]) & 0x80)) {
            $int = "\x00" . $int;
        }
        return "\x02" . chr(strlen($int)) . $int;
    };
    $seq = $enc(substr($raw, 0, 32)) . $enc(substr($raw, 32, 32));
    return "\x30" . chr(strlen($seq)) . $seq;
}

function b64UrlDecode(string $s): string
{
    return base64_decode(strtr($s, '-_', '+/') . str_repeat('=', (4 - strlen($s) % 4) % 4));
}

$tmp = sys_get_temp_dir() . '/apns-relay-unit-' . bin2hex(random_bytes(4));
mkdir($tmp, 0700);

// ---------------------------------------------------------------------------
echo "JWT\n";
$key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
$pub = openssl_pkey_get_details($key)['key'];

$allValid = true;
for ($i = 0; $i < 50; $i++) { // many runs exercise short r/s values
    $jwt = APNsClient::createJwt('ABCDE12345', 'FGHIJ67890', $key, 1700000000 + $i);
    [$h, $c, $s] = explode('.', $jwt);
    $raw = b64UrlDecode($s);
    if (strlen($raw) !== 64 || openssl_verify("$h.$c", rawToDer($raw), $pub, OPENSSL_ALGO_SHA256) !== 1) {
        $allValid = false;
        break;
    }
}
check('ES256 signatures verify and are 64 bytes', $allValid);
$header = json_decode(b64UrlDecode(explode('.', $jwt)[0]), true);
$claims = json_decode(b64UrlDecode(explode('.', $jwt)[1]), true);
check('header has alg/kid', $header === ['alg' => 'ES256', 'kid' => 'ABCDE12345']);
check('claims have iss/iat', $claims['iss'] === 'FGHIJ67890' && is_int($claims['iat']));

$threw = false;
try {
    APNsClient::derToRaw("\x30\x02\x05\x00");
} catch (RuntimeException $e) {
    $threw = true;
}
check('malformed DER rejected', $threw);

// ---------------------------------------------------------------------------
echo "Payload fitting\n";
$big = ['aps' => ['alert' => ['title' => 't', 'body' => str_repeat('é', 5000)]]];
$fitted = Api::fitPayload($big);
$size = strlen(json_encode($fitted, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
check('oversized body truncated to fit 4096 bytes', $size <= 4096, "size $size");
check('truncated body is valid UTF-8', preg_match('//u', $fitted['aps']['alert']['body']) === 1);
$small = ['aps' => ['alert' => ['title' => 't', 'body' => 'hi']]];
check('small payload untouched', Api::fitPayload($small) === $small);

// ---------------------------------------------------------------------------
echo "Database migration from legacy schema\n";
$legacyPath = "$tmp/legacy.db";
$legacy = new PDO('sqlite:' . $legacyPath);
$legacy->exec('CREATE TABLE devices (device_token TEXT PRIMARY KEY, registered_at TEXT NOT NULL,
    last_push_at TEXT, push_count INTEGER DEFAULT 0, app_version TEXT, device_name TEXT, is_active INTEGER DEFAULT 1)');
$legacy->exec('CREATE TABLE push_history (id INTEGER PRIMARY KEY AUTOINCREMENT, device_token TEXT NOT NULL,
    alert_type TEXT NOT NULL, payload TEXT NOT NULL, status TEXT NOT NULL, apns_id TEXT, sent_at TEXT NOT NULL,
    error_message TEXT, FOREIGN KEY (device_token) REFERENCES devices(device_token))');
$tokenA = str_repeat('a', 64);
$legacy->exec("INSERT INTO devices (device_token, registered_at, push_count) VALUES ('$tokenA', '2026-01-01T00:00:00Z', 7)");
$legacy->exec("INSERT INTO push_history (device_token, alert_type, payload, status, sent_at)
    VALUES ('$tokenA', 'general', '{}', 'sent', '2026-01-01T00:00:00Z')");
$legacy = null;

$db = new Database($legacyPath);
check('schema upgraded to current version', $db->schemaVersion() === Database::SCHEMA_VERSION);
$rows = $db->getAllDevices();
check('existing device preserved', count($rows) === 1 && (int)$rows[0]['push_count'] === 7);
check('new columns present with defaults', array_key_exists('failure_count', $rows[0]) && (int)$rows[0]['failure_count'] === 0);
$db2 = new Database($legacyPath);
check('re-opening is a no-op', $db2->schemaVersion() === Database::SCHEMA_VERSION);

$future = new PDO('sqlite:' . "$tmp/future.db");
$future->exec('PRAGMA user_version = 99');
$future = null;
$threw = false;
try {
    new Database("$tmp/future.db");
} catch (RuntimeException $e) {
    $threw = true;
}
check('refuses a database from a newer version', $threw);

// ---------------------------------------------------------------------------
echo "Device lifecycle\n";
$tokenB = str_repeat('b', 64);
$db->registerDevice($tokenB, '1.0', 'Test');
check('register adds active device', $db->getActiveDevice($tokenB) !== null);
check('lookup is case-insensitive for legacy rows', $db->getActiveDevice($tokenA) !== null);

check('first BadDeviceToken keeps device', $db->recordPushFailure($tokenB, '400: BadDeviceToken', false, true) === false);
$db->recordPushFailure($tokenB, '400: BadDeviceToken', false, true);
check(
    'threshold BadDeviceToken deactivates',
    $db->recordPushFailure($tokenB, '400: BadDeviceToken', false, true) === true && $db->getActiveDevice($tokenB) === null
);
$db->registerDevice($tokenB, '1.1', 'Test');
$b = $db->getActiveDevice($tokenB);
check('re-register reactivates and resets failures', $b !== null && (int)$b['failure_count'] === 0 && $b['last_error'] === null);

$db->recordPushFailure($tokenB, '400: BadDeviceToken', false, true);
$db->recordPushSuccess($tokenB);
check('success resets failure count', (int)$db->getActiveDevice($tokenB)['failure_count'] === 0);

check('410 deactivates immediately', $db->recordPushFailure($tokenB, '410: Unregistered', true, false) === true);
check('active count reflects deactivation', $db->countActiveDevices() === 1);

// tokenA last activity 2026-01-01 -> older than 30 days relative to "now".
$deleted = $db->cleanupInactiveDevices(30);
check('cleanup removes stale device', $deleted >= 1 && $db->getActiveDevice($tokenA) === null);
$orphans = (new PDO('sqlite:' . $legacyPath))->query(
    "SELECT COUNT(*) FROM push_history WHERE device_token = '$tokenA'"
)->fetchColumn();
check('cleanup removes history of deleted devices', (int)$orphans === 0);

$db->registerDevice($tokenB, '1.1', 'Test');
$db->logPushHistory($tokenB, 'general', '{}', 'sent', null, null);
$p = new PDO('sqlite:' . $legacyPath);
$p->exec("UPDATE push_history SET sent_at = '2000-01-01T00:00:00Z'");
check('pruneHistory removes old rows', $db->pruneHistory(30) === 1);

// ---------------------------------------------------------------------------
echo "Provider token cache\n";
$keyPath = "$tmp/AuthKey_TEST.p8";
openssl_pkey_export_to_file($key, $keyPath);
$client = new APNsClient('ABCDE12345', 'FGHIJ67890', $keyPath, 'com.example.app', false, $db, '127.0.0.1:9');
$client->send(str_repeat('c', 64), ['aps' => ['alert' => 'x']]);
$first = json_decode((string)$db->getMeta('apns_provider_token'), true);
check('token cached in database', is_array($first) && is_string($first['token']));

$client2 = new APNsClient('ABCDE12345', 'FGHIJ67890', $keyPath, 'com.example.app', false, $db, '127.0.0.1:9');
$client2->send(str_repeat('c', 64), ['aps' => ['alert' => 'x']]);
$second = json_decode((string)$db->getMeta('apns_provider_token'), true);
check('token reused across client instances (requests)', $first['token'] === $second['token']);

$client3 = new APNsClient('ZZZZZ99999', 'FGHIJ67890', $keyPath, 'com.example.app', false, $db, '127.0.0.1:9');
$client3->send(str_repeat('c', 64), ['aps' => ['alert' => 'x']]);
$third = json_decode((string)$db->getMeta('apns_provider_token'), true);
check('token re-minted when key ID changes', $third['token'] !== $first['token']);

$r = $client->send('not-hex', ['aps' => ['alert' => 'x']]);
check('malformed token rejected before network', $r['success'] === false && $r['reason'] === 'BadDeviceToken');
$r = $client->send(str_repeat('c', 64), ['aps' => ['alert' => 'x']]);
check('transport error reported with status 0', $r['success'] === false && $r['status'] === 0 && str_starts_with((string)$r['error'], 'cURL error'));

$missing = new APNsClient('ABCDE12345', 'FGHIJ67890', "$tmp/nope.p8", 'com.example.app', false, $db, '127.0.0.1:9');
$db->deleteMeta('apns_provider_token');
$r = $missing->send(str_repeat('c', 64), ['aps' => ['alert' => 'x']]);
check('missing key fails without leaking the path', $r['success'] === false && !str_contains((string)$r['error'], $tmp));

// ---------------------------------------------------------------------------
array_map('unlink', glob("$tmp/*"));
rmdir($tmp);

echo "\n$count checks, $failures failed\n";
exit($failures === 0 ? 0 : 1);
