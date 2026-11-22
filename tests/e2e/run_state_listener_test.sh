#!/usr/bin/env bash
# Verifies that both Java and Python IExtensionStateListener implementations are
# notified exactly once when the host shuts down.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BUILD="${TMPDIR:-/tmp}/blurp-state-listener-test"
PORT="${BLURP_TEST_PORT:-18123}"
MARKER="${BUILD}/marker"

rm -rf "$BUILD"
mkdir -p "$BUILD/classes"

javac --release 17 -d "$BUILD/classes" \
    "$ROOT/src/main/java/burp/"*.java \
    "$ROOT/src/main/java/com/blurpsuite/"*.java \
    "$ROOT/src/main/java/com/blurpsuite/"*/*.java \
    "$ROOT/tests/e2e/StateListenerExtension.java"

log="${BUILD}/server.log"
BLURP_TEST_MARKER="$MARKER" BLURP_TEST_ARGS="${BUILD}/args.json" \
java -cp "$BUILD/classes" com.blurpsuite.Main \
    --headless --port "$PORT" \
    --extension "$BUILD/classes" \
    --extension "$ROOT/tests/e2e/state_listener.py" \
    --python-home "$ROOT/python" \
    --extension-arg alpha --extension-arg beta > "$log" 2>&1 &
pid=$!

cleanup() {
    if kill -0 "$pid" 2>/dev/null; then
        kill -TERM "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    fi
}
trap cleanup EXIT

for _ in $(seq 1 60); do
    if grep -q "listening on" "$log" 2>/dev/null; then
        break
    fi
    sleep 0.2
done

if [ -e "${MARKER}.java" ] || [ -e "${MARKER}.python" ]; then
    echo "FAIL: state listener fired before unload"
    exit 1
fi

kill -TERM "$pid"
wait "$pid" 2>/dev/null || true
trap - EXIT

for suffix in java python; do
    if [ ! -e "${MARKER}.${suffix}" ]; then
        echo "FAIL: ${suffix} state listener did not fire"
        echo "--- server log ---"
        cat "$log"
        exit 1
    fi
    count="$(tr -d '[:space:]' < "${MARKER}.${suffix}")"
    if [ "$count" != "1" ]; then
        echo "FAIL: ${suffix} state listener fired ${count} times (expected 1)"
        exit 1
    fi
done

if [ ! -f "${BUILD}/args.json" ]; then
    echo "FAIL: Python extension did not receive an extension arguments marker"
    exit 1
fi
args="$(python3 -c 'import json,sys;print(json.dumps(json.load(open(sys.argv[1]))))' \
    "${BUILD}/args.json")"
if [ "$args" != '["alpha", "beta"]' ]; then
    echo "FAIL: Python extension arguments were ${args}, expected [\"alpha\", \"beta\"]"
    exit 1
fi

echo "PASS: Java and Python state listeners were notified exactly once on shutdown"
