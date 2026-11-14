# APNs Push Relay
[![CI](https://github.com/robert-e-roy/apns-push-relay/actions/workflows/ci.yml/badge.svg)](https://github.com/robert-e-roy/apns-push-relay/actions/workflows/ci.yml)

A small, dependency-free PHP service that stores Apple Push Notification
service (APNs) device tokens and relays alert notifications to them. It is
built for ordinary shared hosting: drop the files in a directory, add a config
file and your `.p8` key, and you have a push backend. You don't need Composer,
MySQL or a long-running process.

- **APNs only.** It targets Apple devices (iOS, iPadOS, macOS, watchOS,
  visionOS). It doesn't support Firebase Cloud Messaging (FCM) or web push.
- **Current APNs protocol.** It uses the HTTP/2 provider API with token-based
  (`.p8` / JWT ES256) authentication. Apple retired the legacy binary
  interface on port 2195 in 2021, and this relay doesn't use it.
- **SQLite storage.** The database file is created and migrated automatically.

## Features

- Register device tokens, then send alerts to one device or to every device.
- Provider-token (JWT) caching that follows Apple's refresh rules. The token is
  reused across requests for 50 minutes, so Apple never returns
  `TooManyProviderTokenUpdates`.
- Dead-token handling:
  - `410 Unregistered` deactivates a device immediately.
  - Repeated `400 BadDeviceToken` responses deactivate it after three in a row.
    A single `BadDeviceToken` can just mean a sandbox/production mismatch.
  - A device that registers again is reactivated.
- HTTP/2 connection reuse across devices, and one retry on transport errors and
  APNs 500/503 responses.
- Input validation:
  - Device tokens are checked as hex, and strings are checked for length and
    UTF-8.
  - Oversized alert bodies are trimmed to fit the 4 KB APNs payload limit.
- Optional `interruption-level`, `thread-id` and `apns-collapse-id`, plus a
  free-form `data` object passed through to your app.
- Push history, with cleanup of stale devices and old history.
- Safe failure:
  - Configuration is validated at startup, and the relay refuses to run with
    the example API key.
  - Clients only ever get generic error messages. Details go to the log.

## Requirements

- PHP **8.0+** with these extensions: `pdo_sqlite`, `openssl`, `curl` and
  `json`. `mbstring` is recommended.
- **libcurl built with HTTP/2 support.** APNs requires HTTP/2. To check, run
  `php -r 'var_dump((curl_version()["features"] & CURL_VERSION_HTTP2) !== 0);'`.
  The authenticated `/health` response also reports it.
- Apache with `mod_rewrite`, or nginx with PHP-FPM.
- HTTPS for your endpoint. Clients send an API key, so plain HTTP isn't safe.
- An Apple Developer account and an APNs authentication key (`.p8`).

## Installation

1. **Create an APNs key.**
   1. In the Apple Developer portal, go to *Certificates, Identifiers & Profiles*.
   2. Open *Keys* and create a key with *Apple Push Notifications service (APNs)*
      enabled.
   3. Download the `AuthKey_XXXXXXXXXX.p8` file. Apple only lets you download
      it once.
   4. Note the **Key ID** and your **Team ID**.

2. **Upload the files** to a directory on your host, for example
   `public_html/push/`:

   ```
   index.php
   .htaccess
   lib/
   config.example.php
   ```

3. **Configure.** Copy `config.example.php` to `config.php` and fill it in, or
   use environment variables (see [Configuration](#configuration)).

   ```bash
   cp config.example.php config.php
   openssl rand -hex 32        # use the output as API_KEY
   ```

4. **Place the key and database outside the web root** if your host allows it,
   and point `APNS_KEY_PATH` and `DB_PATH` at them. If they have to live in the
   relay directory, the included `.htaccess` denies HTTP access to every file
   except `index.php`.

5. **Set permissions.** PHP must be able to write to the directory that holds
   the database.

   ```bash
   chmod 600 config.php AuthKey_*.p8
   ```

6. **Check it's running:**

   ```bash
   curl https://example.com/push/health
   # {"status": "healthy", "version": "2.0.0", "timestamp": "..."}

   curl -H "Authorization: Bearer $API_KEY" https://example.com/push/health
   # also shows environment, active_devices, http2, apns_key_readable
   ```

### nginx

```nginx
location /push/ {
    # Only the front controller is reachable; config, keys, DB and logs are not.
    location ~ ^/push/(lib/|config|.*\.(p8|db|log|md)$|\.) { deny all; }
    try_files $uri /push/index.php$is_args$args;
}

location = /push/index.php {
    include fastcgi_params;
    fastcgi_param SCRIPT_FILENAME $document_root/push/index.php;
    fastcgi_param HTTP_AUTHORIZATION $http_authorization;
    fastcgi_pass unix:/run/php/php-fpm.sock;
}
```

## Configuration

Settings are read from `config.php` constants. Any setting that `config.php`
doesn't define is read from an environment variable with the same name. You can
use either source, or mix them.

To keep `config.php` outside the web root, set `APNS_RELAY_CONFIG` to its path.
With Apache that looks like this:
`SetEnv APNS_RELAY_CONFIG /home/you/private/push-config.php`

| Setting | Required | Description |
|---|---|---|
| `APNS_KEY_ID` | yes | 10-character key ID of the `.p8` key |
| `APNS_TEAM_ID` | yes | 10-character Apple Team ID |
| `APNS_KEY_PATH` | yes | Path to the `.p8` file |
| `APNS_BUNDLE_ID` | yes | Your app's bundle ID (the APNs topic) |
| `API_KEY` | yes | Shared secret for clients, at least 32 characters |
| `DB_PATH` | yes | Path to the SQLite database; its directory must be writable |
| `APNS_PRODUCTION` | no | `true` for TestFlight/App Store builds, `false` (default) for development builds |
| `DEFAULT_ALERT_TITLE` | no | Title used when `/alert` omits one (default `Alert`) |
| `HISTORY_RETENTION_DAYS` | no | `/cleanup` removes history older than this (default `30`) |
| `PUBLIC_HEALTH_DETAILS` | no | Show device count and environment on `/health` without auth (default `false`) |
| `CORS_ALLOW_ORIGIN` | no | Only needed if a browser page calls the relay (default: no CORS headers) |

Development builds of your app get **sandbox** tokens and TestFlight/App Store
builds get **production** tokens. Sending to the wrong environment fails with
`BadDeviceToken`.

## API

Every endpoint except `/health` requires the API key, sent in one of these
headers:

```
Authorization: Bearer <API_KEY>
X-API-Key: <API_KEY>
```

Request bodies are JSON objects and responses are JSON.

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/health` | Liveness check. Shows more detail when authenticated |
| `POST` | `/register` | Register or refresh a device token |
| `POST` | `/alert` | Send an alert to one device or every active device |
| `POST` | `/test` | Send a fixed test notification to a token |
| `GET` | `/devices` | List registered devices |
| `POST` | `/cleanup` | Delete stale devices and old history |

### Register a device

```bash
curl -X POST https://example.com/push/register \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"device_token": "<hex token>", "app_version": "1.0", "device_name": "iPhone"}'
```

### Send a push

```bash
curl -X POST https://example.com/push/alert \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Disk space low",
    "subtitle": "web-01",
    "body": "/var is 93% full",
    "severity": "warning",
    "alert_type": "disk_usage",
    "hostname": "web-01",
    "interruption_level": "time-sensitive",
    "data": {"metric": "disk", "value": 93, "threshold": 90}
  }'
```

`/alert` accepts these fields:

| Field | Notes |
|---|---|
| `body` | Required. Trimmed to fit the 4 KB payload limit |
| `title`, `subtitle` | Optional |
| `sound` | Default `default` |
| `badge` | Optional |
| `device_token` | Omit to send to every active device |
| `interruption_level` | `passive`, `active` or `time-sensitive` |
| `thread_id`, `collapse_id` | Optional |
| `alert_type`, `severity`, `hostname`, `shortcut_name` | Copied into the payload for your app |
| `data` | Object of up to 20 scalar values, delivered under the `data` key |

The response reports per-device results. Device tokens in the response are
truncated.

```json
{
  "success": true,
  "devices_notified": 1,
  "total_devices": 1,
  "results": [
    {"device_token": "a1b2c3d4...", "success": true, "apns_id": "…", "error": null}
  ]
}
```

### Cleanup

```bash
curl -X POST https://example.com/push/cleanup \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"days": 90}'
```

This deletes devices with no successful push (or registration) in `days` days,
their history, and any history older than `HISTORY_RETENTION_DAYS`. You can run
it from cron.

## Security

- **Never commit secrets.** `config.php`, `.env`, `*.p8`, `*.p12`, `*.pem`,
  databases and logs are all in `.gitignore`. Commit only
  `config.example.php` with placeholder values.
- **Keep the `.p8` key, database and config outside the web root** when your
  host allows it. The bundled `.htaccess` denies every file except `index.php`
  as a second line of defence. If you use nginx, add the equivalent rules.
- **The API key is a shared secret.** Anyone holding it can list device tokens
  and send notifications to your users. If you embed it in an app, it can be
  extracted from the app binary. Treat it as rate-limiting friction, not real
  access control, and rotate it if it leaks. A per-device credential is the
  stronger design for public apps.
- **Always serve over HTTPS.**
- Errors returned to clients are generic. Details, including file paths, go to
  `error.log` (or your PHP error log), which is denied over HTTP.

## Development

```bash
php tests/unit.php     # JWT signing, schema migration, token lifecycle
tests/smoke.sh         # end-to-end against the PHP built-in server
```

Neither suite contacts Apple. The smoke test points the client at a closed
local port using the test-only `APNS_HOST_OVERRIDE` setting.

## Upgrading from 1.x

The database migrates in place on first request. Existing devices and history
are kept, and the schema version is tracked with `PRAGMA user_version`.

Behaviour changes from 1.x:

- `/health` no longer shows the device count without authentication. Set
  `PUBLIC_HEALTH_DETAILS` to restore it.
- CORS headers are off by default.
- `/test` returns `502` instead of `500` when APNs rejects the push.

## License

[MIT](LICENSE)
