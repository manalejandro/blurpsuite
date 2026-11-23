# Offline extension kit

The kit in `python/examples/kit/` contains ten independent, offline
implementations inspired by the workflow described in
["Top 10 Burp Suite Extensions Every Pentester Should Use"](https://datafarm-cybersecurity.medium.com/top-10-burp-suite-extensions-every-pentester-should-use-2036597ce48c).
They are original Blurp Suite code and use only the supported `burp` Python
API. No third-party extension code or vulnerability feed is bundled.

## Loading

All ten modules at once:

```bash
java -cp build/classes com.blurpsuite.Main \
  --python-home python \
  --extension python/examples/kit/all.py
```

A single module, for example the JSON beautifier:

```bash
java -cp build/classes com.blurpsuite.Main \
  --python-home python \
  --extension python/examples/kit/json_beautifier.py
```

## Modules

| Module | File | What it does |
| --- | --- | --- |
| Autorize | `autorize.py` | Compares responses from sessions with different cookies/Authorization headers and optionally replays a configured low-privilege identity. |
| Active Scan++ | `active_scan_plus.py` | Passive error/debug signatures and small reflected-parameter probes (SSTI, XSS, XML entity). |
| Logger++ | `logger_plus.py` | Bounded in-memory traffic log with keyword/status/MIME filters. |
| Param Miner | `param_miner.py` | Replays a copied request with candidate hidden parameter names and compares response signatures. |
| Turbo Intruder | `turbo_intruder.py` | Concurrent socket request engine with `standard` and `race` (barrier) modes. |
| Collaborator Everywhere | `collaborator_everywhere.py` | Injects locally generated OAST payloads into commonly trusted headers. |
| JSON Beautifier | `json_beautifier.py` | Pretty-prints JSON responses and repairs `Content-Length`. |
| Retire.js | `retire_js.py` | Detects old jQuery/Angular/Bootstrap/lodash/React versions from a small embedded signature table. |
| Backslash Powered Scanner | `backslash_scanner.py` | Flags ambiguous CL+TE framing and parser anomalies from delimiter probes. |
| CSRF Scanner | `csrf_scanner.py` | Flags state-changing requests without an anti-CSRF parameter or header. |

## Configuration

Settings are read from `IBurpExtenderCallbacks.loadExtensionSetting`; in the
CLI they can be supplied as `--extension-arg key=value`. Every module has a
`blurp.kit.<name>.enabled` setting (`true` by default except Autorize,
Param Miner and Collaborator Everywhere, which are opt-in).

Useful settings:

| Setting | Default | Purpose |
| --- | --- | --- |
| `blurp.kit.logger.filters` | empty | Comma-separated terms to print from the traffic log. |
| `blurp.kit.logger.entries` | `500` | Maximum responses kept in memory. |
| `blurp.kit.paramminer.words` | built-in list | Comma-separated candidate parameter names. |
| `blurp.kit.paramminer.limit` | `12` | Maximum probes per endpoint. |
| `blurp.kit.activescan.active` | `true` | Enable active probes. |
| `blurp.kit.backslashscanner.active` | `true` | Enable delimiter probes. |
| `blurp.kit.autorize.lowpriv.cookie` | empty | Low-privilege `Cookie` header used for replay. |
| `blurp.kit.autorize.lowpriv.header` | empty | Extra low-privilege header, e.g. `Authorization: Bearer lowpriv`. |
| `blurp.kit.collab.headers` | built-in list | Headers that receive OAST payloads. |
| `blurp.kit.retirejs.enabled` | `true` | Enable library version checks. |
| `blurp.kit.turbo.payloads` | `1,2,3` | Comma-separated payloads. |
| `blurp.kit.turbo.workers` | `8` | Concurrent workers (1-64). |
| `blurp.kit.turbo.mode` | `standard` | `standard` or `race`. |

Turbo Intruder only runs on requests that contain `%s` **and** the header
`X-Blurp-Turbo: 1`. Collaborator payloads use the local `blurp.local` context,
so interactions must be observed in the Proxy history or an external listener
configured by the tester.

## Safety notes

- Active modules send additional requests to the target. Use them only on
  systems you are authorized to test.
- The kit is a workflow demonstration, not a replacement for a full scanner.
  Review findings manually.
- The embedded Retire.js signature table is intentionally small; extend
  `LIBRARIES` in `retire_js.py` for broader coverage.
