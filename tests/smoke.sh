#!/usr/bin/env bash
# End-to-end checks against the PHP built-in server. No network access to
# Apple: APNS_HOST_OVERRIDE points at a closed local port.
#
#   tests/smoke.sh
set -euo pipefail

unset CDPATH
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
PORT="${PORT:-8765}"
PID=""

cleanup() {
    [[ -n "$PID" ]] && kill "$PID" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT

API_KEY="$(openssl rand -hex 32)"
openssl ecparam -name prime256v1 -genkey -noout 2>/dev/null \
    | openssl pkcs8 -topk8 -nocrypt -out "$WORK/AuthKey_TEST.p8"

write_config() { # $1 = api key
    cat > "$WORK/config.php" <<EOF
<?php
define('APNS_KEY_ID', 'ABCDE12345');
define('APNS_TEAM_ID', 'FGHIJ67890');
define('APNS_KEY_PATH', '$WORK/AuthKey_TEST.p8');
define('APNS_BUNDLE_ID', 'com.example.app');
define('APNS_PRODUCTION', false);
define('API_KEY', '$1');
define('DB_PATH', '$WORK/push.db');
define('APNS_HOST_OVERRIDE', '127.0.0.1:9');
EOF
}

start_server() {
    APNS_RELAY_CONFIG="$WORK/config.php" APNS_RELAY_ERROR_LOG=1 \
        php -d error_log="$WORK/error.log" -S "127.0.0.1:$PORT" -t "$ROOT" "$ROOT/index.php" \
        >"$WORK/server.log" 2>&1 &
    PID=$!
    for _ in $(seq 1 50); do
        curl -s -o /dev/null "http://127.0.0.1:$PORT/health" && return 0
        sleep 0.1
    done
    echo "server did not start"; cat "$WORK/server.log"; exit 1
}

stop_server() { kill "$PID" 2>/dev/null || true; wait "$PID" 2>/dev/null || true; PID=""; }

PASS=0; FAIL=0
BASE="http://127.0.0.1:$PORT"
TOKEN="$(printf 'ab%.0s' $(seq 1 32))"

# expect <name> <expected-status> <grep-pattern|-> curl-args...
expect() {
    local name="$1" want="$2" pattern="$3"; shift 3
    local body status
    body="$(curl -s -w $'\n%{http_code}' "$@")"
    status="${body##*$'\n'}"; body="${body%$'\n'*}"
    if [[ "$status" == "$want" ]] && { [[ "$pattern" == "-" ]] || grep -qE -- "$pattern" <<<"$body"; }; then
        echo "  ok   $name"; PASS=$((PASS+1))
    else
        echo "  FAIL $name (status $status, want $want)"; echo "$body" | sed 's/^/       /'; FAIL=$((FAIL+1))
    fi
}

AUTH=(-H "Authorization: Bearer $API_KEY")
JSON=(-H "Content-Type: application/json")

echo "Configured server"
write_config "$API_KEY"
start_server

expect "health is public"                 200 '"status": "healthy"'   "$BASE/health"
if curl -s "$BASE/health" | grep -q active_devices; then
    echo "  FAIL health leaks device count publicly"; FAIL=$((FAIL+1))
else
    echo "  ok   health hides details publicly"; PASS=$((PASS+1))
fi
expect "health shows details with auth"   200 '"active_devices": 0'  "${AUTH[@]}" "$BASE/health"
expect "index.php/health route"           200 healthy                 "$BASE/index.php/health"
expect "unknown route"                    404 'Not found'             "$BASE/nope"
expect "register without auth"            401 'Missing Authorization' -X POST "$BASE/register"
expect "register with wrong key"          403 'Invalid API key'       -X POST -H "Authorization: Bearer wrong" "$BASE/register"
expect "wrong method"                     405 'Method not allowed'    "${AUTH[@]}" "$BASE/register"
expect "invalid JSON"                     400 'Invalid JSON'          "${AUTH[@]}" "${JSON[@]}" -d '{nope' "$BASE/register"
expect "JSON array body rejected"         400 'JSON object'           "${AUTH[@]}" "${JSON[@]}" -d '[1,2]' "$BASE/register"
expect "missing token"                    400 'Missing device_token'  "${AUTH[@]}" "${JSON[@]}" -d '{}' "$BASE/register"
expect "non-hex token rejected"           400 hexadecimal             "${AUTH[@]}" "${JSON[@]}" -d '{"device_token":"../../x"}' "$BASE/register"
expect "register device"                  200 '"success": true'       "${AUTH[@]}" "${JSON[@]}" \
    -d "{\"device_token\":\"$TOKEN\",\"app_version\":\"1.0\",\"device_name\":\"Test\"}" "$BASE/register"
expect "X-API-Key header accepted"        200 '"total": 1'            -H "X-API-Key: $API_KEY" "$BASE/devices"
expect "alert needs body"                 400 'Missing alert body'    "${AUTH[@]}" "${JSON[@]}" -d '{"title":"t"}' "$BASE/alert"
expect "alert rejects bad data object"    400 'data must be'          "${AUTH[@]}" "${JSON[@]}" -d '{"body":"b","data":[1]}' "$BASE/alert"
expect "alert rejects bad level"          400 interruption_level      "${AUTH[@]}" "${JSON[@]}" -d '{"body":"b","interruption_level":"critical"}' "$BASE/alert"
expect "alert to unknown device"          404 'No active devices'     "${AUTH[@]}" "${JSON[@]}" \
    -d "{\"body\":\"b\",\"device_token\":\"$(printf 'cd%.0s' $(seq 1 32))\"}" "$BASE/alert"
expect "alert reports transport failure"  200 '"devices_notified": 0' "${AUTH[@]}" "${JSON[@]}" \
    -d "{\"title\":\"CPU\",\"body\":\"High\",\"severity\":\"warning\",\"hostname\":\"h\",\"shortcut_name\":null,\"data\":{\"metric\":\"cpu\",\"value\":95.5,\"threshold\":90}}" "$BASE/alert"
expect "transport failure keeps device"   200 '"is_active": 1'        "${AUTH[@]}" "$BASE/devices"
expect "test endpoint reports failure"    502 'cURL error'            "${AUTH[@]}" "${JSON[@]}" -d "{\"device_token\":\"$TOKEN\"}" "$BASE/test"
expect "cleanup validates days"           400 'days must be'          "${AUTH[@]}" "${JSON[@]}" -d '{"days":0}' "$BASE/cleanup"
expect "cleanup"                          200 '"deleted_count": 0'    "${AUTH[@]}" "${JSON[@]}" -d '{"days":90}' "$BASE/cleanup"
expect "OPTIONS preflight"                204 -                       -X OPTIONS "$BASE/alert"

if grep -E 'Deprecated|Warning|Notice|Fatal' "$WORK/error.log" >/dev/null 2>&1; then
    echo "  FAIL PHP diagnostics in error log:"; grep -E 'Deprecated|Warning|Notice|Fatal' "$WORK/error.log" | sed 's/^/       /'
    FAIL=$((FAIL+1))
else
    echo "  ok   no PHP warnings/deprecations logged"; PASS=$((PASS+1))
fi
stop_server

echo "Misconfigured server (placeholder API key)"
write_config "your_secret_api_key_here_000000000000000"
start_server
expect "refuses to run with placeholder key" 500 'not configured' "$BASE/health"
if grep -q "$WORK" <(curl -s "$BASE/health"); then
    echo "  FAIL response leaks a filesystem path"; FAIL=$((FAIL+1))
else
    echo "  ok   no filesystem path in error response"; PASS=$((PASS+1))
fi
stop_server

echo "Environment-only configuration (no config.php)"
rm -f "$WORK/config.php"
APNS_KEY_ID=ABCDE12345 APNS_TEAM_ID=FGHIJ67890 APNS_KEY_PATH="$WORK/AuthKey_TEST.p8" \
APNS_BUNDLE_ID=com.example.app API_KEY="$API_KEY" DB_PATH="$WORK/env.db" APNS_PRODUCTION=true \
    php -d error_log="$WORK/error.log" -S "127.0.0.1:$PORT" -t "$ROOT" "$ROOT/index.php" >"$WORK/server.log" 2>&1 &
PID=$!
for _ in $(seq 1 50); do curl -s -o /dev/null "$BASE/health" && break; sleep 0.1; done
expect "env vars configure the server"    200 '"environment": "production"' "${AUTH[@]}" "$BASE/health"
stop_server

echo
echo "$((PASS+FAIL)) checks, $FAIL failed"
[[ "$FAIL" -eq 0 ]]
