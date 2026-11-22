# Contributing to Blurp Suite

Thanks for your interest in improving Blurp Suite. This project is independent
of PortSwigger; please keep contributions original and do not copy PortSwigger
source code.

## Development setup

- JDK 17 or newer (`javac --release 17` is used for all builds).
- Python 3.9 or newer for the extension bridge (Python 3.13 is used in CI).
- No third-party Java libraries are required.

```bash
./build.sh all          # build, unit tests, and end-to-end test
./build.sh examples     # compile example Java extensions
./build.sh run --help   # build and launch the CLI
```

You can also use `mvn test` or `gradle test`; both ultimately run the
dependency-free `com.blurpsuite.tests.TestRunner`.

## Repository layout

- `src/main/java/com/blurpsuite` - application code (core, api, extensions, ui, util).
- `src/main/java/burp` - **generated** compatibility interfaces. Do not edit.
- `tools/api-contract.json` - the generated API contract (signatures and constants).
- `tests/java` - unit tests using `TestRunner`.
- `tests/e2e` - end-to-end extension lifecycle test.
- `python/` - Python bridge and API compatibility package.
- `examples/` - example extensions for both languages.

## Changing the API compatibility layer

The interfaces under `src/main/java/burp` are generated from `tools/api-contract.json`
by `python3 tools/generate_burp_api.py`. To change them:

1. Update the contract (or regenerate it with `tools/fetch_burp_api.py` from
   published Javadoc), keeping only signatures, constant names, and values.
2. Run `python3 tools/generate_burp_api.py`.
3. Update implementations under `src/main/java/com/blurpsuite/api` if required.
4. Run `./build.sh all`.

Never hand-edit generated files; changes will be overwritten.

## Tests

- Add unit tests to `tests/java/com/blurpsuite/tests` as public classes with
  public `void test*()` methods. `TestRunner` discovers them automatically.
- Use the `TestRunner.check`, `eq`, `eqBytes`, and `throwsIllegalArgument`
  helpers instead of adding a test dependency.
- Run the extension lifecycle check with `./build.sh e2e` when changing
  extension loading, callbacks, or shutdown behavior.
- Keep tests deterministic and free of external network dependencies.

## Style

- Java 17 language level, four-space indentation, no tabs.
- Keep public types and non-obvious behavior documented with Javadoc.
- Python code should follow PEP 8 conventions and remain standard-library only.
- Documentation must be in English.

## Pull requests

1. Fork the repository and create a topic branch.
2. Make focused changes with a clear rationale.
3. Run `./build.sh all` (and `mvn test` / `gradle test` if you touched build files).
4. Update documentation when behavior or CLI flags change.
5. Open a pull request describing what changed, why, and how you verified it.

By contributing, you agree that your contribution is licensed under the
project's MIT License.
