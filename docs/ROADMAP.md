# Roadmap

This document tracks proposed work for Blurp Suite. It is a plan, not a
promise; items move as implementation and testing capacity allow.

## Current state

- Dependency-free Java 17 proxy, desktop UI, and extension host.
- 42 clean-room `burp.*` compatibility interfaces generated from published
  Javadoc signatures and constants.
- Java extension loading from JARs, class directories, and single class files.
- Python extensions through a JSON-RPC bridge using the `burp` package name.
- Dependency-free unit tests and an end-to-end extension lifecycle test.

## Next

1. **TLS interception for HTTPS traffic**
   - Generate a local CA and per-host certificates.
   - Terminate `CONNECT` tunnels, inspect HTTP/1.1 inside TLS, and re-encrypt
     upstream.
   - Surface certificate trust and revocation in the UI (`--bind` remains local
     by default).
   - This is the most requested capability because the current proxy tunnels
     `CONNECT` without interception.

2. **HTTP/2 support**
   - Replace the HTTP/1.1-only parser with a protocol-aware message model.
   - Implement the `makeHttp2Request` callbacks instead of sending an HTTP/1.1
     fallback.

3. **Broader API compatibility**
   - Extend `tools/api-contract.json` based on published Javadoc only.
   - Regenerate `src/main/java/burp` with `tools/generate_burp_api.py`.
   - Implement meaningful behavior for scanner, Intruder, and Repeater
     callbacks instead of compatibility stubs.

4. **Test framework and CI**
   - Migrate `tests/java` to a conventional framework where appropriate while
     keeping the suite dependency-free for local builds.
   - Expand end-to-end coverage to request/response modification, scope events,
     intercept actions, and extension unloading.

5. **Packaging and distribution**
   - Produce a runnable JAR with a documented manifest.
   - Add installable startup scripts and reproducible build instructions for
     Maven and Gradle.

6. **Persistence and usability**
   - Persist scope, intercept settings, and extension configuration across
     restarts.
   - Improve history filtering, search, and export.

## Non-goals

- Bundling or reusing PortSwigger proprietary code.
- Becoming a drop-in replacement for Burp Suite Professional.
- Enabling undisclosed interception of third-party traffic.
