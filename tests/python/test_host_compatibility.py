"""Compatibility checks for the Python extension host, without launching Java."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from support import REPO_ROOT  # noqa: F401  (path setup must happen before imports)
from support import encode, log_event, run_bridge

import burp
from blurp import bridge
from blurp.api import BurpExtenderCallbacks
from burp.api import HttpRequestResponse, HttpService


class RecordingTransport:
    """Minimal stand-in for the JSON-RPC transport used by callbacks."""

    def __init__(self, results: dict[str, dict[str, Any]] | None = None):
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.notifications: list[tuple[str, dict[str, Any]]] = []
        self.results = results or {}

    def call(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        self.calls.append((method, params or {}))
        return self.results.get(method, {})

    def notify(self, method: str, params: dict[str, Any]) -> None:
        self.notifications.append((method, params))


class InterfaceCompatibilityTests(unittest.TestCase):
    def test_interfaces_are_selectively_overridable(self):
        class Extension(burp.IBurpExtender, burp.IProxyListener,
                        burp.IExtensionStateListener, burp.IHttpListener):
            def processProxyMessage(self, messageIsRequest, message):
                return "proxy"

        extension = Extension()
        self.assertEqual(extension.processProxyMessage(True, None), "proxy")
        self.assertIsNone(extension.extensionUnloaded())
        self.assertIsNone(extension.processHttpMessage(4, True, None))
        self.assertIsNone(extension.registerExtenderCallbacks(None))

    def test_constants_match_the_java_api(self):
        self.assertEqual(burp.IBurpExtenderCallbacks.TOOL_PROXY, 4)
        self.assertEqual(burp.IBurpExtenderCallbacks.TOOL_REPEATER, 64)
        self.assertEqual(burp.IInterceptedProxyMessage.ACTION_DROP, 3)
        self.assertEqual(burp.IParameter.PARAM_JSON, 6)
        self.assertEqual(burp.IRequestInfo.CONTENT_TYPE_JSON, 4)
        self.assertEqual(burp.IScannerInsertionPoint.INS_HEADER, 32)


class ExtensionLoadingTests(unittest.TestCase):
    def test_load_extension_accepts_both_entry_point_names(self):
        with tempfile.TemporaryDirectory(prefix="blurp-load-test-") as directory:
            for filename, class_name, source in [
                ("a.py", "BurpExtender", "class BurpExtender: pass\n"),
                ("b.py", "Extension", "class Extension: pass\n"),
                ("c.py", "Missing", "class SomethingElse: pass\n"),
            ]:
                path = Path(directory) / filename
                path.write_text(source, encoding="utf-8")
                if class_name == "Missing":
                    with self.assertRaises(TypeError):
                        bridge.load_extension(path)
                else:
                    instance = bridge.load_extension(path)
                    self.assertEqual(type(instance).__name__, class_name)

    def test_extension_script_directory_is_importable(self):
        source = log_event() + '''
import sibling
from burp import IBurpExtender

class BurpExtender(IBurpExtender):
    def registerExtenderCallbacks(self, callbacks):
        log(value=sibling.VALUE)
'''
        result = run_bridge(source, extra_files={"sibling.py": "VALUE = 'sibling imported'\n"})
        self.assertEqual(json.loads(result.log.strip()), {"value": "sibling imported"})

    def test_extension_arguments_are_read_from_the_environment(self):
        source = log_event() + '''
from burp import IBurpExtender

class BurpExtender(IBurpExtender):
    def registerExtenderCallbacks(self, callbacks):
        log(args=callbacks.getCommandLineArguments(),
            filename=callbacks.getExtensionFilename().endswith("extension.py"))
'''
        result = run_bridge(source, extension_args='["--flag", "7"]')
        self.assertEqual(json.loads(result.log.strip()),
                         {"args": ["--flag", "7"], "filename": True})

        broken = run_bridge(source, extension_args="not json")
        self.assertEqual(json.loads(broken.log.strip()), {"args": [], "filename": True})
        self.assertEqual(broken.returncode, 0)
        self.assertNotIn("Traceback", broken.stderr)

    def test_bridge_usage_error_is_reported_without_touching_stdout(self):
        from unittest import mock
        import io
        import sys

        stderr = io.StringIO()
        with mock.patch.object(sys, "argv", ["blurp.bridge"]), \
                mock.patch.object(sys, "stderr", stderr):
            self.assertEqual(bridge.main(), 2)
        self.assertIn("usage: python -m blurp.bridge", stderr.getvalue())


class CallbacksCompatibilityTests(unittest.TestCase):
    def setUp(self):
        self.transport = RecordingTransport()
        self.callbacks = BurpExtenderCallbacks(self.transport, "extension.py", ["--one"])

    def test_local_callback_state_and_tool_names(self):
        callbacks = self.callbacks
        callbacks.setExtensionName("Local Extension")
        self.assertEqual(callbacks.extensionName, "Local Extension")
        self.assertEqual(callbacks.getExtensionFilename(), "extension.py")
        self.assertEqual(callbacks.getCommandLineArguments(), ["--one"])
        self.assertEqual(callbacks.getBurpVersion(), ("Blurp Suite", "1.0.0", "community"))
        self.assertIsNotNone(callbacks.getHelpers())
        self.assertEqual(callbacks.getToolName(4), "Proxy")
        self.assertEqual(callbacks.getToolName(9999), "Unknown")

        listener = object()
        callbacks.registerProxyListener(listener)
        callbacks.registerHttpListener(listener)
        callbacks.registerExtensionStateListener(listener)
        callbacks.registerScopeChangeListener(listener)
        callbacks.removeProxyListener(listener)
        callbacks.removeHttpListener(listener)
        self.assertEqual(callbacks.proxy_listeners, [])
        self.assertEqual(callbacks.http_listeners, [])
        self.assertEqual(callbacks.state_listeners, [listener])
        self.assertEqual(callbacks.scope_listeners, [listener])

        callbacks.saveExtensionSetting("key", 5)
        self.assertEqual(callbacks.loadExtensionSetting("key"), "5")
        self.assertEqual(callbacks.saveConfig(), {"key": "5"})
        callbacks.loadConfigFromJson('{"other": "value"}')
        self.assertEqual(json.loads(callbacks.saveConfigAsJson()),
                         {"key": "5", "other": "value"})
        with tempfile.TemporaryDirectory(prefix="blurp-state-test-") as directory:
            path = Path(directory) / "state.json"
            callbacks.saveState(path)
            restored = BurpExtenderCallbacks(RecordingTransport())
            restored.restoreState(path)
            self.assertEqual(restored.saveConfig(), callbacks.saveConfig())

        header_lines = callbacks.getHeaders(b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n")
        self.assertEqual(header_lines, ["Host: example.test"])
        self.assertEqual(callbacks.getParameters(
            b"GET /?a=1 HTTP/1.1\r\nHost: example.test\r\n\r\n"), [["a", "1"]])
        base = HttpRequestResponse(b"REQ", b"RES", HttpService("h", 80, "http"))
        marked = callbacks.applyMarkers(base, [(1, 2)], [(3, 4)])
        self.assertEqual(marked.getRequestMarkers(), [(1, 2)])
        self.assertEqual(marked.getResponseMarkers(), [(3, 4)])

    def test_notifications_use_the_methods_the_host_understands(self):
        self.callbacks.printOutput("hello")
        self.callbacks.printError("problem")
        self.callbacks.issueAlert("alert")
        self.callbacks.exitSuite(True)
        self.callbacks.unloadExtension()
        self.assertEqual(self.transport.notifications, [
            ("print_output", {"message": "hello"}),
            ("print_error", {"message": "problem"}),
            ("print_output", {"message": "ALERT: alert"}),
            ("exit_suite", {"prompt": True}),
            ("unload_extension", {}),
        ])
        self.assertEqual(self.transport.calls, [])

    def test_host_calls_carry_the_expected_method_names_and_params(self):
        service = HttpService("example.test", 443, "https")
        item = HttpRequestResponse(b"REQ", b"RES", service)
        self.transport.results = {
            "is_in_scope": {"value": True},
            "get_proxy_history": {"items": [{
                "request": encode(b"REQ"), "response": encode(b"RES"),
                "comment": "noted", "highlight": "orange",
                "service": service.to_dict(), "reference": 17,
            }]},
            "make_http_request": {
                "request": encode(b"NEW-REQ"),
                "response": encode(b"NEW-RES"),
                "service": {"host": "example.test", "port": 443, "protocol": "https"},
            },
        }

        self.assertTrue(self.callbacks.isInScope("http://example.test/"))
        self.callbacks.includeInScope("http://example.test/include")
        self.callbacks.excludeFromScope("http://example.test/exclude")
        history = self.callbacks.getProxyHistory()
        self.assertEqual(len(history), 1)
        self.assertIsInstance(history[0], HttpRequestResponse)
        self.assertEqual(history[0].getRequest(), b"REQ")
        self.assertEqual(history[0].getResponse(), b"RES")
        self.assertEqual(history[0].getComment(), "noted")
        self.assertEqual(history[0].getHighlight(), "orange")
        self.assertEqual(history[0].getHttpService().to_dict(), service.to_dict())
        self.callbacks.setProxyInterceptionEnabled(True)
        self.callbacks.addToSiteMap(item)
        result = self.callbacks.makeHttpRequest(service, b"REQ")
        self.callbacks.doPassiveScan("example.test", 443, True, b"REQ", b"RES")

        self.assertEqual(self.transport.calls, [
            ("is_in_scope", {"url": "http://example.test/"}),
            ("include_in_scope", {"url": "http://example.test/include"}),
            ("exclude_from_scope", {"url": "http://example.test/exclude"}),
            ("get_proxy_history", {}),
            ("set_interception", {"enabled": True}),
            ("add_to_site_map", {
                "request": encode(b"REQ"), "response": encode(b"RES"),
                "service": service.to_dict(),
            }),
            ("make_http_request", {"service": service.to_dict(), "request": encode(b"REQ")}),
            ("do_passive_scan", {
                "host": "example.test", "port": 443, "useHttps": True,
                "request": encode(b"REQ"), "response": encode(b"RES"),
            }),
        ])
        self.assertEqual(result.getRequest(), b"NEW-REQ")
        self.assertEqual(result.getResponse(), b"NEW-RES")
        self.assertEqual(result.getHttpService().getHost(), "example.test")
        self.assertEqual(result.getHttpService().getProtocol(), "https")

    def test_offline_collaborator_is_available(self):
        context = self.callbacks.createBurpCollaboratorClientContext()
        self.assertTrue(context.generatePayload(True).endswith(".blurp.local"))
        self.assertEqual(context.getCollaboratorServerLocation(), "blurp.local")
        self.assertEqual(context.fetchAllCollaboratorInteractions(), [])
        self.assertEqual(context.fetchAllInfiltratorInteractions(), [])
        self.assertEqual(context.fetchCollaboratorInteractionsFor("payload"), [])
        self.assertEqual(context.fetchInfiltratorInteractionsFor("payload"), [])

    def test_is_in_scope_accepts_plain_boolean_reply(self):
        self.transport.results["is_in_scope"] = True
        self.assertTrue(self.callbacks.isInScope("http://example.test/"))
        self.transport.results["is_in_scope"] = False
        self.assertFalse(self.callbacks.isInScope("http://example.test/"))


if __name__ == "__main__":
    unittest.main()
