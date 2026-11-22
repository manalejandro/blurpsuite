#!/usr/bin/env bash
# Blurp Suite build helper: javac build, Java/Python unit tests, and end-to-end checks.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_ROOT="${BLURP_BUILD_DIR:-$ROOT/build}"
MAIN_CLASSES="$BUILD_ROOT/classes"
TEST_CLASSES="$BUILD_ROOT/test-classes"
EXAMPLE_CLASSES="$BUILD_ROOT/example-extensions"

usage() {
    cat <<'EOF'
Usage: ./build.sh <command> [arguments]

Commands:
  build      Compile all main sources with javac --release 17 into build/classes
  test       Compile tests/java and run the dependency-free TestRunner
  python-test Run the Python bridge unit tests with unittest
  e2e        Run both end-to-end tests (state listener and proxy)
  examples   Compile examples/java into build/example-extensions
  all        Run build, test, python-test, and e2e
  run [args] Build, then launch com.blurpsuite.Main with the given arguments
  clean      Remove the build directory
  help       Show this help

Environment:
  BLURP_BUILD_DIR  Override the build output directory (default: ./build)
EOF
}

collect_java() {
    find "$1" -type f -name '*.java' -print0
}

compile_java() {
    local output="$1"
    shift
    mkdir -p "$output"
    local sources=()
    mapfile -d '' -t sources < <(cat "$@")
    if [ "${#sources[@]}" -eq 0 ]; then
        echo "No Java sources found" >&2
        return 1
    fi
    javac --release 17 -encoding UTF-8 -d "$output" "${sources[@]}"
}

build_main() {
    local list="$BUILD_ROOT/.main-sources"
    mkdir -p "$BUILD_ROOT"
    collect_java "$ROOT/src/main/java" > "$list"
    compile_java "$MAIN_CLASSES" "$list"
    echo "Main classes: $MAIN_CLASSES"
}

build_tests() {
    build_main
    local list="$BUILD_ROOT/.test-sources"
    collect_java "$ROOT/tests/java" > "$list"
    mkdir -p "$TEST_CLASSES"
    local sources=()
    mapfile -d '' -t sources < "$list"
    javac --release 17 -encoding UTF-8 \
        -cp "$MAIN_CLASSES" -d "$TEST_CLASSES" "${sources[@]}"
    echo "Test classes: $TEST_CLASSES"
}

python_tests() {
    (cd "$ROOT" && python3 -m unittest discover -s tests/python -v)
}

build_examples() {
    build_main
    local list="$BUILD_ROOT/.example-sources"
    collect_java "$ROOT/examples/java" > "$list"
    local sources=()
    mapfile -d '' -t sources < "$list"
    mkdir -p "$EXAMPLE_CLASSES"
    javac --release 17 -encoding UTF-8 \
        -cp "$MAIN_CLASSES" -d "$EXAMPLE_CLASSES" "${sources[@]}"
    echo "Example extensions: $EXAMPLE_CLASSES"
}

command="${1:-build}"
if [ "$#" -gt 0 ]; then
    shift
fi

case "$command" in
    build)
        build_main
        ;;
    test)
        build_tests
        java -cp "$MAIN_CLASSES:$TEST_CLASSES" com.blurpsuite.tests.TestRunner "$@"
        ;;
    python-test)
        python_tests
        ;;
    e2e)
        build_main
        (cd "$ROOT" && bash tests/e2e/run_state_listener_test.sh "$@")
        (cd "$ROOT" && bash tests/e2e/run_proxy_test.sh "$@")
        ;;
    examples)
        build_examples
        ;;
    all)
        build_tests
        java -cp "$MAIN_CLASSES:$TEST_CLASSES" com.blurpsuite.tests.TestRunner
        python_tests
        (cd "$ROOT" && bash tests/e2e/run_state_listener_test.sh)
        (cd "$ROOT" && bash tests/e2e/run_proxy_test.sh)
        ;;
    run)
        build_main
        exec java -cp "$MAIN_CLASSES" com.blurpsuite.Main "$@"
        ;;
    clean)
        rm -rf "$BUILD_ROOT"
        echo "Removed $BUILD_ROOT"
        ;;
    help|-h|--help)
        usage
        ;;
    *)
        usage >&2
        echo "Unknown command: $command" >&2
        exit 2
        ;;
esac
