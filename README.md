# Blurp Suite

Blurp Suite is an independent, dependency-free Java application that combines a
small HTTP/1.1 intercepting proxy with a host for Burp Extender-compatible
extensions. It can run as a Swing desktop application or as a headless proxy.
Java extensions implement the `burp.*` interfaces directly; Python extensions
are loaded through a JSON-RPC bridge and can import the familiar `burp` package.

> **Legal and independence notice**
>
> Blurp Suite is an independent clean-room project. It is **not affiliated
> with, endorsed by, or sponsored by PortSwigger Web Security**. Burp Suite and
> Burp are trademarks of PortSwigger Web Security. The `burp.*` interfaces in
> `src/main/java/burp` are a compatibility layer generated from method
> signatures, constant names, and constant values published in PortSwigger's
> Extender API Javadoc. No PortSwigger source code is included. See [NOTICE](NOTICE).

## Requirements

- JDK 17 or newer for building (`javac --release 17` is used by the build script).
- Python 3 with `python3` on `PATH` for the Python bridge, its unit tests, and
  Python extensions.
- A graphical environment for the desktop UI; `--headless` needs none.

There are no third-party Java dependencies.

## Quick start

```bash
./build.sh build
java -cp build/classes com.blurpsuite.Main --help
java -cp build/classes com.blurpsuite.Main
```

The application prints the listen address, for example
`Blurp Suite 1.0.0 listening on 127.0.0.1:8080`. Point your browser or client's
**HTTP proxy** at `127.0.0.1:8080` and open a plain HTTP page to see traffic in
the Proxy History and Intercept tabs.

Run without the UI:

```bash
java -cp build/classes com.blurpsuite.Main --headless --port 8080
```

Alternatively, use the build helper as a launcher:

```bash
./build.sh run --headless --port 8080
```

## Command-line flags

All flags below come from `com.blurpsuite.Main`. Short aliases are accepted
where noted.

| Flag | Default | Description |
| --- | --- | --- |
| `--port <port>` | `8080` | Proxy listen port. |
| `--bind <address>` | `127.0.0.1` | Bind address. |
| `--extension <path>` (`-e`) | none | Load a Java JAR, class directory, single `.class` file, or Python `.py` file. Repeatable. |
| `--python-home <path>` | `python` | Root directory of the Python bridge package (`blurp`/`burp`). |
| `--python <executable>` | `python3` | Python executable used to start Python extensions. |
| `--headless` | off | Run without the Swing UI; press Ctrl+C to stop. |
| `--extension-arg <value>` | none | Pass a value to extensions (exposed via `IBurpExtenderCallbacks.getCommandLineArguments()` and to Python as `BLURP_EXTENSION_ARGS`). Repeatable. |
| `--version` (`-V`) | — | Print `Blurp Suite 1.0.0` and exit. |
| `--help` (`-h`) | — | Show usage and exit. |

Example with repeated flags:

```bash
java -cp build/classes com.blurpsuite.Main \
  --headless \
  --port 9090 \
  --bind 127.0.0.1 \
  --extension-arg example \
  --extension build/example-extensions \
  --extension python/examples/commenter.py
```

## Extension examples

### Java extensions

The bundled examples are in `examples/java`:

- `HeaderModifier.java` adds `X-Blurp-Java: yes` to proxied requests.
- `TrafficLogger.java` prints one line per proxied request and response.

Compile and load them:

```bash
./build.sh examples
java -cp build/classes com.blurpsuite.Main \
  --extension build/example-extensions
```

`--extension` also accepts a built JAR or a single compiled `.class` file. The
loader instantiates every concrete `IBurpExtender` implementation it finds in
the artifact, so loading a directory with both examples registers both.

### Python extensions

The bundled examples are in `python/examples`:

- `header_modifier.py` adds `X-Blurp-Python: yes` to proxied requests.
- `commenter.py` sets comments and highlights on proxied responses.

```bash
java -cp build/classes com.blurpsuite.Main \
  --python-home python \
  --extension python/examples/header_modifier.py
```

A Python extension defines a `BurpExtender` (or `Extension`) class, implements
`registerExtenderCallbacks`, and may implement listener interfaces such as
`IProxyListener` and `IExtensionStateListener`. The Java host starts the bridge
as `python -m blurp.bridge <script>` with `PYTHONPATH` set to `--python-home`.

## Architecture

```text
src/main/java/com/blurpsuite/
  Main.java              CLI parsing, startup, shutdown hooks
  core/                  ProxyServer, HttpParser, HttpExchange, Scope, Service,
                         TrafficListener
  api/                   BurpExtenderCallbacksImpl, ExtensionHelpersImpl and the
                         other concrete API implementations
  extensions/            ExtensionManager, JavaExtensionLoader,
                         PythonExtensionHost, JrpcConnection
  ui/                    Swing MainWindow and tabs (Dashboard, Intercept,
                         History, Scope, Extensions)
  util/                  ByteUtil, Json
src/main/java/burp/       Generated clean-room burp.* compatibility interfaces
python/blurp/             JSON-RPC bridge entry point (python -m blurp.bridge)
python/burp/              Python API objects exposed to extensions
tools/                    api-contract.json and the API contract/generation scripts
tests/java/               Dependency-free TestRunner plus CoreTests and ApiTests
tests/python/             Python bridge unit tests (unittest, no third-party packages)
tests/e2e/                End-to-end scripts: state-listener and proxy integration tests
examples/                 Java and Python example extensions
```

Traffic flows from `ProxyServer` to registered `TrafficListener`s. The API
bridge translates between `HttpExchange` objects and the `burp.*` interfaces
used by extensions; Python extensions cross a line-delimited JSON-RPC pipe
handled by `PythonExtensionHost` and `python/blurp/bridge.py`.

The sources in `src/main/java/burp` are generated: do not edit them by hand.
Regenerate them with `python3 tools/generate_burp_api.py` after changing
`tools/api-contract.json`. The contract was extracted from published Javadoc by
`tools/fetch_burp_api.py`.

## Build and test

### javac helper (no additional tooling)

```bash
./build.sh build       # compile main sources into build/classes
./build.sh test        # compile tests/java and run TestRunner
./build.sh python-test # run the Python bridge unit tests with unittest
./build.sh e2e         # run both end-to-end tests (state listener and proxy)
./build.sh examples    # compile examples/java
./build.sh all         # build + test + python-test + e2e
./build.sh run [args]  # build and launch com.blurpsuite.Main
./build.sh clean       # remove build/
```

`BLURP_BUILD_DIR` overrides the output directory. The state-listener e2e helper
honors `BLURP_TEST_PORT` (default `18123`).

### Python unit tests and end-to-end tests

The Python bridge has a dependency-free `unittest` suite, and two shell scripts
exercise the running application end to end. Run all three directly from the
repository root:

```bash
python3 -m unittest discover -s tests/python -v
bash tests/e2e/run_state_listener_test.sh
bash tests/e2e/run_proxy_test.sh
```

`./build.sh python-test` runs the same unittest suite, `./build.sh e2e` runs
both end-to-end scripts, and `./build.sh all` runs the Java and Python unit
tests followed by both end-to-end scripts. The proxy test also honors
`BLURP_PROXY_PORT` (default `18080`) and `BLURP_ORIGIN_PORT` (default `18090`).

### Maven

```bash
mvn package            # builds target/blurpsuite-1.0.0.jar
mvn exec:java          # runs com.blurpsuite.Main (configure args with -Dexec.args="...")
mvn test               # runs the dependency-free TestRunner via exec-maven-plugin
```

The Maven test sources are declared as `tests/java`. Surefire is skipped
because the tests are plain `test*()` methods discovered by `TestRunner`, not
JUnit tests; see the comments in `pom.xml`.

### Gradle

```bash
gradle build           # compile and run checks
gradle run             # run com.blurpsuite.Main
gradle test            # runs the Java TestRunner and the Python unittest suite
gradle e2e             # runs both end-to-end extension tests
```

Gradle compiles `tests/java` (and `src/test/java`) as test sources; the custom
`unitTests` task performs the Java test run, `pythonTests` runs the Python bridge
unit tests, and `e2e` runs both `tests/e2e` scripts.

## Limitations

- **HTTP/1.1 only.** The proxy parses HTTP/1.1 messages. HTTP/2 is not
  implemented; API calls that request HTTP/2 emit an error message and send an
  HTTP/1.1 equivalent instead.
- **No TLS man-in-the-middle.** `CONNECT` requests are tunnelled byte-for-byte
  without interception, so HTTPS bodies are not visible to proxy listeners or
  extensions. Outbound HTTPS requests made through the callbacks API are not
  supported.
- **No full Burp tool engine.** There is no scanner, spider, Intruder, Repeater,
  or Sequencer implementation. Tool interfaces are accepted for API
  compatibility; for example, active scan calls return an unavailable queue
  item.
- **Compatibility subset.** `src/main/java/burp` currently covers the 42
  interfaces described in `tools/api-contract.json`, not every present-day Burp
  API feature.
- **Custom test framework.** Java tests use the dependency-free `TestRunner`
  rather than JUnit; Maven Surefire and Gradle's framework-based `Test` task are
  therefore configured not to look for JUnit classes. Python tests use the
  standard `unittest` module.
- **UI requirements.** The desktop interface uses Swing and needs a display;
  use `--headless` on servers and in CI.

See [docs/ROADMAP.md](docs/ROADMAP.md) for planned work.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidance and
[SECURITY.md](SECURITY.md) for vulnerability reporting.

## License

MIT. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
