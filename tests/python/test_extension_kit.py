"""Unit tests for the bundled offline extension kit."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from collections import OrderedDict
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[2]
KIT = REPO_ROOT / "python" / "examples" / "kit"
sys.path.insert(0, str(KIT))
sys.path.insert(0, str(REPO_ROOT / "python"))


def load(name):
    spec = importlib.util.spec_from_file_location("kit_" + name, KIT / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.BurpExtender


class Message:
    def __init__(self, request=b"", response=b"", host="example.test"):
        self.request = request
        self.response = response
        self.service = Service(host)

    def getRequest(self):
        return self.request

    def setRequest(self, value):
        self.request = value

    def getResponse(self):
        return self.response

    def setResponse(self, value):
        self.response = value

    def getHttpService(self):
        return self.service

    def getComment(self):
        return ""


class Service:
    def __init__(self, host="example.test", port=80, protocol="http"):
        self.host, self.port, self.protocol = host, port, protocol

    def getHost(self):
        return self.host

    def getPort(self):
        return self.port

    def getProtocol(self):
        return self.protocol


class Helpers:
    def analyzeRequest(self, request):
        return mock.Mock(getParameters=lambda: [])


class Collaborator:
    def generatePayload(self, include_location=True):
        return "payload.blurp.local"


class Callbacks:
    def __init__(self, settings=None, replies=None, arguments=None):
        self.settings = dict(settings or {})
        self.replies = list(replies or [])
        self.arguments = list(arguments or [])
        self.output = []
        self.requests = []
        self.http_listeners = []
        self.proxy_listeners = []
        self.state_listeners = []
        self.name = ""

    def setExtensionName(self, name):
        self.name = name

    def loadExtensionSetting(self, key):
        return self.settings.get(key)

    def saveExtensionSetting(self, key, value):
        self.settings[key] = value

    def getCommandLineArguments(self):
        return self.arguments

    def printOutput(self, message):
        self.output.append(message)

    def registerHttpListener(self, listener):
        self.http_listeners.append(listener)

    def registerProxyListener(self, listener):
        self.proxy_listeners.append(listener)

    def registerExtensionStateListener(self, listener):
        self.state_listeners.append(listener)

    def getToolName(self, flag):
        return "Proxy"

    def getHelpers(self):
        return Helpers()

    def createBurpCollaboratorClientContext(self):
        return Collaborator()

    def makeHttpRequest(self, service, request):
        self.requests.append((service, request))
        if self.replies:
            return self.replies.pop(0)
        return Message(request, b"HTTP/1.1 200 OK\r\n\r\nsame")


def response(body: bytes, content_type="text/plain") -> bytes:
    return (b"HTTP/1.1 200 OK\r\nContent-Type: " + content_type.encode()
            + b"\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)


class KitTests(unittest.TestCase):
    def test_json_beautifier_formats_and_fixes_length(self):
        callbacks = Callbacks()
        extension = load("json_beautifier")()
        extension.registerExtenderCallbacks(callbacks)
        original = response(b'{"b":2,"a":1}', "application/json")
        message = Message(b"GET / HTTP/1.1\r\n\r\n", original)
        extension.processHttpMessage(4, False, message)
        self.assertIn(b'"a": 1', message.getResponse())
        self.assertIn(b'"b": 2', message.getResponse())
        self.assertIn(str(len(message.getResponse().split(b"\r\n\r\n", 1)[1])).encode(),
                      message.getResponse())

    def test_csrf_scanner_flags_state_changing_request_without_token(self):
        callbacks = Callbacks()
        extension = load("csrf_scanner")()
        extension.registerExtenderCallbacks(callbacks)
        extension.processHttpMessage(4, True,
                                      Message(b"POST /login HTTP/1.1\r\nHost: x.test\r\n\r\na=b"))
        self.assertTrue(any("no anti-CSRF token" in line for line in callbacks.output))

    def test_csrf_scanner_accepts_header_token(self):
        callbacks = Callbacks()
        extension = load("csrf_scanner")()
        extension.registerExtenderCallbacks(callbacks)
        extension.processHttpMessage(4, True, Message(
            b"POST /login HTTP/1.1\r\nHost: x.test\r\nX-CSRF-Token: abc\r\n\r\na=b"))
        self.assertEqual(callbacks.output, [])

    def test_retire_js_reports_outdated_library(self):
        callbacks = Callbacks()
        extension = load("retire_js")()
        extension.registerExtenderCallbacks(callbacks)
        body = b"<script>/* jQuery v1.2.3 */</script>"
        extension.processHttpMessage(
            4, False, Message(b"GET / HTTP/1.1\r\n\r\n", response(body, "text/html")))
        self.assertTrue(any("jquery 1.2.3" in line for line in callbacks.output))

    def test_retire_js_matches_full_banner_and_prerelease(self):
        callbacks = Callbacks()
        extension = load("retire_js")()
        extension.registerExtenderCallbacks(callbacks)
        banner = b"<script>/* jQuery JavaScript Library v1.2.3 */</script>"
        extension.processHttpMessage(
            4, False, Message(b"GET / HTTP/1.1\r\n\r\n", response(banner, "text/html")))
        self.assertTrue(any("jquery 1.2.3" in line for line in callbacks.output))
        callbacks.output.clear()
        prerelease = b"<script>/* jQuery v3.5.0-rc1 */</script>"
        extension.processHttpMessage(
            4, False, Message(b"GET / HTTP/1.1\r\n\r\n", response(prerelease, "text/html")))
        self.assertTrue(any("jquery 3.5.0-rc1" in line for line in callbacks.output))

    def test_param_miner_detects_changed_response(self):
        callbacks = Callbacks(replies=[Message(response=b"HTTP/1.1 200 OK\r\n\r\nadmin")])
        callbacks.settings["blurp.kit.paramminer.enabled"] = "true"
        callbacks.settings["blurp.kit.paramminer.words"] = "debug"
        extension = load("param_miner")()
        extension.registerExtenderCallbacks(callbacks)
        extension.processHttpMessage(4, False, Message(
            b"GET /x HTTP/1.1\r\n\r\n", response(b"normal")))
        self.assertTrue(any("'debug'" in line for line in callbacks.output))

    def test_active_scan_dedupes_probes_across_responses(self):
        callbacks = Callbacks(replies=[
            Message(response=response(b"49")) for _ in range(10)])
        extension = load("active_scan_plus")()
        extension.registerExtenderCallbacks(callbacks)
        message = Message(b"GET /x?v=1 HTTP/1.1\r\nHost: x.test\r\n\r\n",
                          response(b"normal"))
        extension.processHttpMessage(4, False, message)
        extension.processHttpMessage(4, False, message)
        self.assertEqual(len(callbacks.requests), 3)
        self.assertTrue(any("indicator reflected" in line for line in callbacks.output))

    def test_active_scan_injects_into_first_form_value_only(self):
        callbacks = Callbacks()
        extension = load("active_scan_plus")()
        extension.registerExtenderCallbacks(callbacks)
        message = Message(b"POST /x HTTP/1.1\r\nHost: x.test\r\n\r\na=1&b=2",
                          response(b"normal"))
        extension.processHttpMessage(4, False, message)
        self.assertIn(b"a=1{{7*7}}&b=2", callbacks.requests[0][1])

    def test_active_scan_does_not_rewrite_chunked_bodies(self):
        callbacks = Callbacks()
        extension = load("active_scan_plus")()
        extension.registerExtenderCallbacks(callbacks)
        request = (b"POST /x HTTP/1.1\r\nHost: x.test\r\nTransfer-Encoding: chunked\r\n\r\n"
                   b"4\r\na=1\r\n0\r\n\r\n")
        extension.processHttpMessage(4, False, Message(request, response(b"normal")))
        self.assertEqual(callbacks.requests, [])

    def test_bounded_helpers_cap_long_running_caches(self):
        import common
        seen = OrderedDict()
        for value in range(5):
            self.assertTrue(common.bounded_add(seen, value, size=3))
        self.assertEqual(list(seen), [2, 3, 4])
        mapping = OrderedDict()
        for value in range(5):
            common.bounded_put(mapping, value, str(value), size=3)
        self.assertEqual(list(mapping), [2, 3, 4])
        chunked = b"POST /x HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
        rewritten = common.set_content_length(chunked, 5)
        self.assertNotIn(b"Transfer-Encoding", rewritten)
        self.assertIn(b"Content-Length: 5", rewritten)

    def test_autorize_compares_sessions(self):
        callbacks = Callbacks()
        callbacks.settings["blurp.kit.autorize.enabled"] = "true"
        extension = load("autorize")()
        extension.registerExtenderCallbacks(callbacks)
        baseline = Message(b"GET /a HTTP/1.1\r\nCookie: admin=1\r\n\r\n", response(b"secret"))
        other = Message(b"GET /a HTTP/1.1\r\nCookie: low=1\r\n\r\n", response(b"secret"))
        extension.processHttpMessage(4, False, baseline)
        extension.processHttpMessage(4, False, other)
        self.assertTrue(any("different session" in line for line in callbacks.output))

    def test_autorize_replaces_session_headers_with_lf_only(self):
        callbacks = Callbacks()
        callbacks.settings["blurp.kit.autorize.enabled"] = "true"
        callbacks.settings["blurp.kit.autorize.lowpriv.cookie"] = "low=1"
        extension = load("autorize")()
        extension.registerExtenderCallbacks(callbacks)
        replay = extension._replace_markers(b"GET /a HTTP/1.1\nCookie: admin=1\n\n")
        self.assertIn(b"Cookie: low=1", replay)
        self.assertNotIn(b"admin=1", replay)
        self.assertIn(b"\n\n", replay)

    def test_ambiguous_framing_detected(self):
        callbacks = Callbacks()
        extension = load("backslash_scanner")()
        extension.registerExtenderCallbacks(callbacks)
        extension.processHttpMessage(
            4, True,
            Message(b"POST /a HTTP/1.1\r\nContent-Length: 4\r\n"
                    b"Transfer-Encoding: chunked\r\n\r\nabcd"))
        self.assertTrue(any("ambiguous framing" in line for line in callbacks.output))

    def test_collaborator_everywhere_injects_headers(self):
        callbacks = Callbacks()
        callbacks.settings["blurp.kit.collab.enabled"] = "true"
        extension = load("collaborator_everywhere")()
        extension.registerExtenderCallbacks(callbacks)
        intercepted = mock.Mock()
        message = Message(b"GET /a HTTP/1.1\r\nHost: x.test\r\n\r\n")
        intercepted.getMessageInfo.return_value = message
        extension.processProxyMessage(True, intercepted)
        self.assertIn(b"X-Forwarded-Host: payload.blurp.local", message.getRequest())

    def test_collaborator_everywhere_injects_headers_with_lf_only(self):
        callbacks = Callbacks()
        callbacks.settings["blurp.kit.collab.enabled"] = "true"
        extension = load("collaborator_everywhere")()
        extension.registerExtenderCallbacks(callbacks)
        intercepted = mock.Mock()
        message = Message(b"GET /a HTTP/1.1\nHost: x.test\n\n")
        intercepted.getMessageInfo.return_value = message
        extension.processProxyMessage(True, intercepted)
        self.assertIn(b"X-Forwarded-Host: payload.blurp.local", message.getRequest())

    def test_turbo_intruder_only_runs_for_triggered_requests(self):
        callbacks = Callbacks()
        extension = load("turbo_intruder")()
        extension.registerExtenderCallbacks(callbacks)
        with mock.patch.object(extension, "_send", return_value=b"HTTP/1.1 200 OK\r\n\r\n"):
            extension.processHttpMessage(4, True,
                                          Message(b"POST /a HTTP/1.1\r\n\r\nid=%s"))
            self.assertEqual(callbacks.output, [])
            extension.processHttpMessage(4, True, Message(
                b"POST /a HTTP/1.1\r\nX-Blurp-Turbo: 1\r\n\r\nid=%s"))
        self.assertTrue(any("payload=" in line for line in callbacks.output))

    def test_logger_plus_filters_and_reports_unload(self):
        callbacks = Callbacks()
        callbacks.settings["blurp.kit.logger.filters"] = "admin,404"
        extension = load("logger_plus")()
        extension.registerExtenderCallbacks(callbacks)
        extension.processHttpMessage(4, False, Message(
            b"GET /admin HTTP/1.1\r\n\r\n", response(b"ok")))
        self.assertTrue(any("/admin" in line for line in callbacks.output))
        extension.extensionUnloaded()
        self.assertTrue(any("captured 1" in line for line in callbacks.output))

    def test_settings_accept_extension_arguments(self):
        import common
        callbacks = Callbacks(arguments=[
            "blurp.kit.paramminer.enabled=true",
            "blurp.kit.paramminer.limit=7",
        ])
        self.assertEqual(common.setting(callbacks, "paramminer.limit", "12"), "7")
        self.assertTrue(common.enabled(callbacks, "paramminer"))

    def test_invalid_numeric_settings_fall_back(self):
        callbacks = Callbacks(settings={"blurp.kit.paramminer.limit": "many"})
        param_miner = load("param_miner")()
        param_miner.registerExtenderCallbacks(callbacks)
        self.assertEqual(param_miner.limit, 12)
        callbacks.settings["blurp.kit.turbo.workers"] = "many"
        turbo = load("turbo_intruder")()
        turbo.registerExtenderCallbacks(callbacks)
        self.assertEqual(turbo.workers, 8)

    def test_json_beautifier_handles_lf_only_messages(self):
        callbacks = Callbacks()
        extension = load("json_beautifier")()
        extension.registerExtenderCallbacks(callbacks)
        message = Message(
            b"GET / HTTP/1.1\n\n",
            b'HTTP/1.1 200 OK\nContent-Type: application/json\n\n{"a":1}')
        extension.processHttpMessage(4, False, message)
        updated = message.getResponse()
        self.assertIn(b'\n\n{\n  "a": 1\n}', updated)
        self.assertIn(b"Content-Length: 12\n", updated)

    def test_csrf_scanner_accepts_lf_only_header_token(self):
        callbacks = Callbacks()
        extension = load("csrf_scanner")()
        extension.registerExtenderCallbacks(callbacks)
        extension.processHttpMessage(4, True, Message(
            b"POST /login HTTP/1.1\nX-CSRF-Token: abc\n\na=b"))
        self.assertEqual(callbacks.output, [])

    def test_backslash_scanner_preserves_query_structure_and_length(self):
        import backslash_scanner
        callbacks = Callbacks(replies=[
            Message(response=response(b"normal")) for _ in range(10)])
        extension = load("backslash_scanner")()
        extension.registerExtenderCallbacks(callbacks)
        extension.processHttpMessage(4, False, Message(
            b"GET /x?a=1&b=2 HTTP/1.1\r\nHost: x.test\r\n\r\n", response(b"normal")))
        payload = backslash_scanner.PROBES[0].encode()
        self.assertTrue(any(b"/x?a=1" + payload + b"&b=2" in request
                            for _, request in callbacks.requests))
        callbacks.requests.clear()
        extension.processHttpMessage(4, False, Message(
            b"POST /x HTTP/1.1\r\nHost: x.test\r\nContent-Length: 3\r\n\r\na=1",
            response(b"normal")))
        self.assertTrue(any(b"Content-Length: 5\r\n" in request and b"a=1" in request
                            for _, request in callbacks.requests))

    def test_param_miner_ignores_empty_replay_responses(self):
        callbacks = Callbacks(replies=[Message(response=b"")])
        callbacks.settings["blurp.kit.paramminer.enabled"] = "true"
        callbacks.settings["blurp.kit.paramminer.words"] = "debug"
        extension = load("param_miner")()
        extension.registerExtenderCallbacks(callbacks)
        extension.processHttpMessage(4, False, Message(
            b"GET /x HTTP/1.1\r\n\r\n", response(b"normal")))
        self.assertTrue(any("produced no response" in line for line in callbacks.output))
        self.assertFalse(any("hidden parameter" in line for line in callbacks.output))

    def test_retire_js_accepts_two_part_safe_version(self):
        callbacks = Callbacks()
        extension = load("retire_js")()
        extension.registerExtenderCallbacks(callbacks)
        extension.processHttpMessage(4, False, Message(
            b"GET / HTTP/1.1\r\n\r\n", response(b"jQuery v3.5", "text/html")))
        self.assertEqual(callbacks.output, [])

    def test_url_of_brackets_ipv6_hosts(self):
        import common
        request = b"GET /x HTTP/1.1\r\n\r\n"
        self.assertEqual(common.url_of(request, Service("::1", 8080)),
                         "http://[::1]:8080/x")
        self.assertEqual(common.url_of(request, Service("[::1]", 8080)),
                         "http://[::1]:8080/x")
        self.assertEqual(common.url_of(request, Service("2001:db8::1", 80)),
                         "http://[2001:db8::1]:80/x")

    def test_all_loader_registers_ten_modules(self):
        callbacks = Callbacks()
        extension = load("all")()
        extension.registerExtenderCallbacks(callbacks)
        self.assertEqual(len(extension.modules), 10)
        self.assertEqual(callbacks.name, "Blurp Extension Kit (10 modules)")


if __name__ == "__main__":
    unittest.main()
