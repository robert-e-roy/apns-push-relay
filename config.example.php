<?php
/**
 * APNs Push Relay configuration.
 *
 * Copy to config.php and fill in your values. Never commit config.php.
 *
 * Every setting can instead come from an environment variable of the same
 * name (e.g. API_KEY, APNS_KEY_PATH). A constant here wins over the
 * environment, so you can mix both, or skip config.php entirely.
 *
 * To keep this file outside the web root, put it anywhere and point the
 * APNS_RELAY_CONFIG environment variable at it (Apache: SetEnv
 * APNS_RELAY_CONFIG /home/you/private/push-config.php).
 */

// ---------------------------------------------------------------------------
// Required
// ---------------------------------------------------------------------------

// From Apple Developer > Certificates, Identifiers & Profiles > Keys.
define('APNS_KEY_ID', 'ABCDE12345');        // 10-character Key ID
define('APNS_TEAM_ID', 'FGHIJ67890');       // 10-character Team ID

// Path to the downloaded AuthKey_XXXXXXXXXX.p8 file. Outside the web root is
// best; if it must live here, .htaccess denies HTTP access to it.
define('APNS_KEY_PATH', __DIR__ . '/AuthKey_ABCDE12345.p8');

// Your app's bundle identifier (the APNs topic).
define('APNS_BUNDLE_ID', 'com.example.myapp');

// false = sandbox (Xcode/debug builds), true = production (TestFlight/App Store).
define('APNS_PRODUCTION', false);

// Shared secret clients send as "Authorization: Bearer <key>" or "X-API-Key: <key>".
// Generate with: openssl rand -hex 32   (at least 32 characters required)
define('API_KEY', 'your_secret_api_key_here');

// SQLite database. The directory must be writable by PHP. Outside the web root
// is best; if it must live here, .htaccess denies HTTP access to it.
define('DB_PATH', __DIR__ . '/push.db');

// ---------------------------------------------------------------------------
// Optional
// ---------------------------------------------------------------------------

// Title used when an /alert request doesn't include one.
// define('DEFAULT_ALERT_TITLE', 'Alert');

// /cleanup also deletes push history older than this many days.
// define('HISTORY_RETENTION_DAYS', 30);

// Show device count and environment on /health without authentication.
// define('PUBLIC_HEALTH_DETAILS', false);

// Only needed if a browser page calls the relay directly.
// define('CORS_ALLOW_ORIGIN', 'https://dashboard.example.com');
