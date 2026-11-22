#!/usr/bin/env bash
# End-to-end test: the proxy must forward traffic and let both Java and Python
# extensions modify the request before it reaches the origin server.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BUILD="${TMPDIR:-/tmp}/blurp-proxy-e2e"
PROXY_PORT="${BLURP_PROXY_PORT:-18080}"
ORIGIN_PORT="${BLURP_ORIGIN_PORT:-18090}"
LISTENER_MARKER="${BUILD}/listener"

rm -rf "$BUILD"
mkdir -p "$BUILD/classes" "$BUILD/example-classes"

javac --release 17 -d "$BUILD/classes" \
    "$ROOT/src/main/java/burp/"*.java \
    "$ROOT/src/main/java/com/blurpsuite/"*.java \
    "$ROOT/src/main/java/com/blurpsuite/"*/*.java
javac --release 17 -cp "$BUILD/classes" -d "$BUILD/example-classes" \
    "$ROOT/examples/java/HeaderModifier.java" \
    "$ROOT/examples/java/TrafficLogger.java"

origin_log="$BUILD/origin.log"
blurp_log="$BUILD/blurp.log"
python3 "$ROOT/tests/e2e/origin_server.py" "$ORIGIN_PORT" > "$origin_log" 2>&1 &
origin_pid=$!
BLURP_LISTENER_MARKER="$LISTENER_MARKER" java -cp "$BUILD/classes" com.blurpsuite.Main \
    --headless \
    --port "$PROXY_PORT" \
    --python-home "$ROOT/python" \
    --extension "$ROOT/python/examples/header_modifier.py" \
    --extension "$ROOT/tests/e2e/python_listener.py" \
    --extension "$BUILD/example-classes" > "$blurp_log" 2>&1 &
blurp_pid=$!

cleanup() {
    for pid in "${blurp_pid:-}" "${origin_pid:-}"; do
        if [ -n "${pid:-}" ] && kill -0 "$pid" 2>/dev/null; then
            kill -TERM "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    done
}
trap cleanup EXIT

wait_for_log() {
    local file="$1" pattern="$2"
    for _ in $(seq 1 80); do
        if grep -q "$pattern" "$file" 2>/dev/null; then
            return 0
        fi
        sleep 0.2
    done
    echo "FAIL: timed out waiting for '$pattern' in $file"
    echo "--- $file ---"
    cat "$file"
    exit 1
}

wait_for_log "$origin_log" "origin listening"
wait_for_log "$blurp_log" "listening on"

response="$(curl --silent --show-error --max-time 10 \
    --noproxy '' \
    -x "http://127.0.0.1:$PROXY_PORT" \
    "http://127.0.0.1:$ORIGIN_PORT/proxy-test")"

for expected in \
    "GET /proxy-test HTTP/1.1" \
    "X-Blurp-Java: yes" \
    "X-Blurp-Python: yes"; do
    if ! grep -qF "$expected" <<< "$response"; then
        echo "FAIL: response did not contain '$expected'"
        echo "--- response ---"
        echo "$response"
        echo "--- blurp log ---"
        cat "$blurp_log"
        exit 1
    fi
done

for callback in http scope; do
    if [ ! -e "${LISTENER_MARKER}.${callback}" ]; then
        echo "FAIL: Python ${callback} listener did not fire"
        echo "--- blurp log ---"
        cat "$blurp_log"
        exit 1
    fi
done

echo "PASS: proxy forwarded traffic, and Python HTTP and scope listeners fired"
