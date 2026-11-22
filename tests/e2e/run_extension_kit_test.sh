#!/usr/bin/env bash
# Verifies that the bundled offline extension kit loads as one Python extension.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BUILD="${TMPDIR:-/tmp}/blurp-extension-kit-test"
PORT="${BLURP_KIT_PORT:-18124}"

rm -rf "$BUILD"
mkdir -p "$BUILD/classes"

javac --release 17 -d "$BUILD/classes" \
    "$ROOT/src/main/java/burp/"*.java \
    "$ROOT/src/main/java/com/blurpsuite/"*.java \
    "$ROOT/src/main/java/com/blurpsuite/"*/*.java

log="$BUILD/server.log"
java -cp "$BUILD/classes" com.blurpsuite.Main \
    --headless --port "$PORT" \
    --python-home "$ROOT/python" \
    --extension "$ROOT/python/examples/kit/all.py" \
    --extension-arg blurp.kit.paramminer.enabled=true > "$log" 2>&1 &
pid=$!

cleanup() {
    if kill -0 "$pid" 2>/dev/null; then
        kill -TERM "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    fi
}
trap cleanup EXIT

expected="[kit] loaded: Autorize, ActiveScan++, Logger++, ParamMiner, TurboIntruder, CollaboratorEverywhere, JSONBeautifier, RetireJS, BackslashScanner, CSRFScanner"
for _ in $(seq 1 80); do
    if grep -qF "$expected" "$log" 2>/dev/null; then
        break
    fi
    sleep 0.2
done

if ! grep -qF "$expected" "$log" 2>/dev/null; then
    echo "FAIL: extension kit did not register all ten modules"
    echo "--- server log ---"
    cat "$log"
    exit 1
fi
if grep -qE "Could not load extension|Traceback \(most recent call last\)|Bad JSON" "$log"; then
    echo "FAIL: extension kit load produced an error"
    echo "--- server log ---"
    cat "$log"
    exit 1
fi
if grep -q "paramminer.enabled=true to enable" "$log"; then
    echo "FAIL: extension argument did not configure Param Miner"
    echo "--- server log ---"
    cat "$log"
    exit 1
fi

kill -TERM "$pid"
wait "$pid" 2>/dev/null || true
trap - EXIT

echo "PASS: extension kit loaded all ten modules through the Python bridge"
