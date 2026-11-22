"""End-to-end handler tests for ``blurp.bridge`` driven by scripted host frames."""

from __future__ import annotations

import base64
import json
import unittest
from typing import Any

from support import encode, log_event, run_bridge

RAW_REQUEST = (
    "GET /index.html?q=1 HTTP/1.1\r\n"
    "Host: example.test\r\n"
    "Accept: */*\r\n"
    "\r\n"
)
REWRITTEN_REQUEST = RAW_REQUEST.replace("\r\n", "\r\nX-Blurp-Python: yes\r\n", 1)
RAW_RESPONSE = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nhello"

REQUEST_REWRITER = log_event() + r'''
from burp import IBurpExtender, IProxyListener

class BurpExtender(IBurpExtender, IProxyListener):
    def registerExtenderCallbacks(self, callbacks):
        callbacks.setExtensionName("Request Rewriter")
        callbacks.registerProxyListener(self)
        self.helpers = callbacks.getHelpers()

    def processProxyMessage(self, messageIsRequest, message):
        info = message.getMessageInfo()
        service = info.getHttpService()
        log(isRequest=messageIsRequest, reference=message.getMessageReference(),
            listener=message.getListenerInterface(), client=message.getClientIpAddress(),
            action=message.getInterceptAction(),
            service=[service.getHost(), service.getPort(), service.getProtocol()],
            request=self.helpers.bytesToString(info.getRequest()),
            response=self.helpers.bytesToString(info.getResponse()),
            comment=info.getComment(), highlight=info.getHighlight())
        if messageIsRequest:
            lines = self.helpers.bytesToString(info.getRequest()).split("\r\n")
            lines.insert(1, "X-Blurp-Python: yes")
            info.setRequest("\r\n".join(lines).encode("latin-1"))
'''

RESPONSE_RELABELER = log_event() + r'''
from burp import IBurpExtender, IProxyListener

class BurpExtender(IBurpExtender, IProxyListener):
    def registerExtenderCallbacks(self, callbacks):
        callbacks.setExtensionName("Response Relabeler")
        callbacks.registerProxyListener(self)
        self.helpers = callbacks.getHelpers()

    def processProxyMessage(self, messageIsRequest, message):
        if messageIsRequest:
            return
        info = message.getMessageInfo()
        log(isRequest=False,
            request=self.helpers.bytesToString(info.getRequest()),
            response=self.helpers.bytesToString(info.getResponse()))
        info.setComment("Python saw https://example.test:8443")
        info.setHighlight("yellow")
        message.setInterceptAction(3)
'''

FLAKY_LISTENER = r'''
from burp import IBurpExtender, IProxyListener

class BurpExtender(IBurpExtender, IProxyListener):
    def registerExtenderCallbacks(self, callbacks):
        callbacks.registerProxyListener(self)

    def processProxyMessage(self, messageIsRequest, message):
        if message.getMessageInfo().getComment() == "bad":
            raise ValueError("listener boom")
        message.getMessageInfo().setComment("handled")
'''

CALLBACK_LISTENER = log_event() + r'''
from burp import IBurpExtender, IProxyListener

class BurpExtender(IBurpExtender, IProxyListener):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        callbacks.registerProxyListener(self)
        callbacks.printOutput("Python listener ready")

    def processProxyMessage(self, messageIsRequest, message):
        if messageIsRequest:
            log(inScope=self.callbacks.isInScope("http://example.test/"))
'''

HTTP_LISTENER = log_event() + r'''
from burp import IBurpExtender, IHttpListener, IScopeChangeListener

class BurpExtender(IBurpExtender, IHttpListener, IScopeChangeListener):
    def registerExtenderCallbacks(self, callbacks):
        callbacks.registerHttpListener(self)
        callbacks.registerScopeChangeListener(self)
        self.helpers = callbacks.getHelpers()

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        log(tool=toolFlag, isRequest=messageIsRequest,
            response=self.helpers.bytesToString(messageInfo.getResponse()))
        if not messageIsRequest:
            messageInfo.setResponse(b"HTTP/1.1 204 No Content\r\n\r\n")

    def scopeChanged(self):
        log(scope="changed")
'''


def proxy_params(*, is_request: bool, message: str, reference: int = 42,
                 comment: str = "original", highlight: str = "blue") -> dict[str, Any]:
    return {
        "jsonrpc": "2.0", "id": 1, "method": "on_proxy_message",
        "params": {
            "isRequest": is_request,
            "message": message,
            "reference": reference,
            "listener": "127.0.0.1:8080",
            "clientAddress": "10.1.2.3",
            "comment": comment,
            "highlight": highlight,
            "service": {"host": "example.test", "port": 8443, "protocol": "HTTPS"},
        },
    }


def events(result) -> list[dict[str, Any]]:
    return [json.loads(line) for line in result.log.splitlines() if line.strip()]


class ProxyHandlerTests(unittest.TestCase):
    def test_request_message_is_rewritten_and_returned_only_when_changed(self):
        result = run_bridge(REQUEST_REWRITER, [proxy_params(
            is_request=True, message=encode(RAW_REQUEST.encode("latin-1")))])

        self.assertEqual(result.returncode, 0)
        self.assertEqual(len(result.frames), 1)
        reply = result.frames[0]
        self.assertEqual(reply["id"], 1)
        self.assertEqual(reply["result"]["action"], 0)
        self.assertFalse(reply["result"]["drop"])
        self.assertEqual(reply["result"]["message"], encode(REWRITTEN_REQUEST.encode("latin-1")))
        self.assertNotIn("comment", reply["result"])
        self.assertNotIn("highlight", reply["result"])

        self.assertEqual(events(result), [{
            "action": 0, "client": "10.1.2.3", "comment": "original",
            "highlight": "blue", "isRequest": True, "listener": "127.0.0.1:8080",
            "reference": 42, "request": RAW_REQUEST, "response": "",
            "service": ["example.test", 8443, "https"],
        }])

    def test_response_handler_sets_comment_highlight_and_drop_action(self):
        result = run_bridge(RESPONSE_RELABELER, [proxy_params(
            is_request=False, message=encode(RAW_RESPONSE.encode("latin-1")))])

        reply = result.frames[0]
        self.assertEqual(reply["result"]["action"], 3)
        self.assertTrue(reply["result"]["drop"])
        self.assertEqual(reply["result"]["comment"],
                         "Python saw https://example.test:8443")
        self.assertEqual(reply["result"]["highlight"], "yellow")
        self.assertNotIn("message", reply["result"])
        self.assertEqual(events(result), [{
            "isRequest": False, "request": "", "response": RAW_RESPONSE,
        }])

    def test_listener_exception_becomes_error_reply_and_bridge_keeps_serving(self):
        inbound = [
            proxy_params(is_request=True, message=encode(RAW_REQUEST.encode()),
                         comment="bad", reference=1),
            proxy_params(is_request=True, message=encode(RAW_REQUEST.encode()),
                         comment="good", reference=2),
        ]
        inbound[0]["id"], inbound[1]["id"] = 11, 12
        result = run_bridge(FLAKY_LISTENER, inbound)

        self.assertEqual(result.returncode, 0)
        self.assertEqual([frame["id"] for frame in result.frames], [11, 12])
        self.assertEqual(result.frames[0]["error"]["code"], -32000)
        self.assertEqual(result.frames[0]["error"]["message"], "listener boom")
        self.assertEqual(result.frames[1]["result"]["comment"], "handled")
        self.assertEqual(result.frames[1]["result"]["action"], 0)

    def test_extension_can_call_host_while_proxy_request_is_being_handled(self):
        # Both sides number requests from 1, exactly like the real host does.
        inbound = [
            proxy_params(is_request=True, message=encode(RAW_REQUEST.encode())),
            {"id": 1, "result": {"value": True}},
        ]
        result = run_bridge(CALLBACK_LISTENER, inbound)

        self.assertEqual(events(result), [{"inScope": True}])
        self.assertEqual(result.frames, [
            {"jsonrpc": "2.0", "method": "print_output",
             "params": {"message": "Python listener ready"}},
            {"jsonrpc": "2.0", "id": 1, "method": "is_in_scope",
             "params": {"url": "http://example.test/"}},
            {"jsonrpc": "2.0", "id": 1, "result": {"action": 0, "drop": False}},
        ])

    def test_startup_diagnostics_stay_on_stderr(self):
        result = run_bridge(REQUEST_REWRITER, [proxy_params(
            is_request=True, message=encode(RAW_REQUEST.encode()))])
        self.assertIn("[blurp] starting Python extension extension.py", result.stderr)
        self.assertIn("[blurp] extension registered as Request Rewriter", result.stderr)
        # Every stdout line is a protocol frame; parsed in run_bridge().
        self.assertEqual(len(result.stdout.splitlines()), len(result.frames))

    def test_http_message_and_scope_change_handlers(self):
        inbound = [
            {"id": 3, "method": "on_http_message", "params": {
                "isRequest": False, "tool": 64,
                "message": encode(RAW_RESPONSE.encode()),
                "service": {"host": "example.test", "port": 443, "protocol": "https"},
            }},
            {"id": 4, "method": "on_scope_changed", "params": {}},
        ]
        result = run_bridge(HTTP_LISTENER, inbound)

        self.assertEqual(result.frames, [
            {"jsonrpc": "2.0", "method": "set_http_listener_count",
             "params": {"count": 1}},
            {"jsonrpc": "2.0", "method": "set_scope_listener_count",
             "params": {"count": 1}},
            {"jsonrpc": "2.0", "id": 3, "result": {
                "message": encode(b"HTTP/1.1 204 No Content\r\n\r\n")}},
            {"jsonrpc": "2.0", "id": 4, "result": {}},
        ])
        self.assertEqual(events(result), [
            {"tool": 64, "isRequest": False, "response": RAW_RESPONSE},
            {"scope": "changed"},
        ])


STATE_LISTENER = log_event() + r'''
from burp import IBurpExtender, IExtensionStateListener

class BurpExtender(IBurpExtender, IExtensionStateListener):
    def registerExtenderCallbacks(self, callbacks):
        callbacks.registerExtensionStateListener(self)

    def extensionUnloaded(self):
        log(unloaded=True)
'''

TWO_STATE_LISTENERS = log_event() + r'''
from burp import IBurpExtender, IExtensionStateListener

class Broken:
    def extensionUnloaded(self):
        raise RuntimeError("listener failed")

class Working:
    def extensionUnloaded(self):
        log(unloaded=True)

class BurpExtender(IBurpExtender):
    def registerExtenderCallbacks(self, callbacks):
        callbacks.registerExtensionStateListener(Broken())
        callbacks.registerExtensionStateListener(Working())
'''


class StateListenerTests(unittest.TestCase):
    def test_explicit_unloaded_notification_fires_listener_once(self):
        result = run_bridge(STATE_LISTENER, [
            {"id": 1, "method": "on_unloaded", "params": {}}])

        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.frames, [{"jsonrpc": "2.0", "id": 1, "result": {}}])
        self.assertEqual(events(result), [{"unloaded": True}])

    def test_eof_fallback_notifies_state_listeners(self):
        result = run_bridge(STATE_LISTENER)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.frames, [])
        self.assertEqual(events(result), [{"unloaded": True}])

    def test_failing_state_listener_does_not_stop_other_listeners(self):
        result = run_bridge(TWO_STATE_LISTENERS)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(events(result), [{"unloaded": True}])
        self.assertIn("state listener failed: listener failed", result.stderr)


INFO_EXTENSION = r'''
from burp import (IBurpExtender, IProxyListener, IHttpListener,
                  IScopeChangeListener, IExtensionStateListener)

class Listener(IProxyListener, IHttpListener, IScopeChangeListener, IExtensionStateListener):
    pass

class BurpExtender(IBurpExtender):
    def registerExtenderCallbacks(self, callbacks):
        callbacks.setExtensionName("Everything")
        listener = Listener()
        callbacks.registerProxyListener(listener)
        callbacks.registerHttpListener(listener)
        callbacks.registerScopeChangeListener(listener)
        callbacks.registerExtensionStateListener(listener)
'''


class ExtensionInfoTests(unittest.TestCase):
    def test_get_extension_info_reports_name_and_listener_counts(self):
        result = run_bridge(INFO_EXTENSION, [
            {"id": 9, "method": "get_extension_info", "params": {}}])

        self.assertEqual(result.frames, [
            {"jsonrpc": "2.0", "method": "set_http_listener_count",
             "params": {"count": 1}},
            {"jsonrpc": "2.0", "method": "set_scope_listener_count",
             "params": {"count": 1}},
            {"jsonrpc": "2.0", "id": 9, "result": {
                "name": "Everything", "proxyListeners": 1, "httpListeners": 1,
                "scopeListeners": 1, "stateListeners": 1,
            }},
        ])

    def test_unknown_method_gets_method_not_found_error(self):
        result = run_bridge(INFO_EXTENSION, [
            {"id": 8, "method": "does_not_exist", "params": {}}])
        self.assertEqual(result.frames, [
            {"jsonrpc": "2.0", "method": "set_http_listener_count",
             "params": {"count": 1}},
            {"jsonrpc": "2.0", "method": "set_scope_listener_count",
             "params": {"count": 1}},
            {"jsonrpc": "2.0", "id": 8, "error": {
                "code": -32601, "message": "Unknown method: does_not_exist",
            }},
        ])


if __name__ == "__main__":
    unittest.main()
