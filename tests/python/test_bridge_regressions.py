"""Regressions for the Python bridge metadata and compatibility surface."""

from __future__ import annotations

import unittest

from support import encode, run_bridge

from burp import (
    HttpRequestResponse,
    IBurpExtender,
    IHttpListener,
    IMenuItemHandler,
    IProxyListener,
    IResponseKeywords,
    IResponseVariations,
    InterceptedProxyMessage,
)

RAW_REQUEST = "GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"
RAW_RESPONSE = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"

SERVICE_CHANGER = r'''
from burp import HttpService, IBurpExtender, IProxyListener

class BurpExtender(IBurpExtender, IProxyListener):
    def registerExtenderCallbacks(self, callbacks):
        callbacks.registerProxyListener(self)

    def processProxyMessage(self, messageIsRequest, message):
        message.getMessageInfo().setHttpService(
            HttpService("changed.test", 9443, "https"))
'''

HTTP_METADATA_CHANGER = r'''
from burp import HttpService, IBurpExtender, IHttpListener

class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        callbacks.registerHttpListener(self)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        messageInfo.setComment("http-comment")
        messageInfo.setHighlight("green")
        messageInfo.setHttpService(HttpService("http.test", 8443, "https"))
'''


def proxy_params(message: str) -> dict:
    return {
        "isRequest": True,
        "message": encode(message.encode("latin-1")),
        "reference": 1,
        "listener": "127.0.0.1:8080",
        "clientAddress": "10.1.2.3",
        "comment": "old",
        "highlight": "blue",
        "service": {"host": "example.test", "port": 80, "protocol": "http"},
    }


def http_params() -> dict:
    return {
        "isRequest": False,
        "tool": 4,
        "message": encode(RAW_RESPONSE.encode("latin-1")),
        "reference": 2,
        "comment": "old",
        "highlight": "blue",
        "service": {"host": "example.test", "port": 80, "protocol": "http"},
    }


class CompatibilitySurfaceTests(unittest.TestCase):
    def test_contract_interfaces_are_importable(self):
        for interface in (IMenuItemHandler, IResponseKeywords, IResponseVariations):
            self.assertTrue(callable(interface))

    def test_client_address_supports_jython_style_inetaddress_calls(self):
        message = InterceptedProxyMessage(
            HttpRequestResponse(b"GET / HTTP/1.1\r\n\r\n"),
            client_address="10.1.2.3")
        address = message.getClientIpAddress()

        self.assertEqual(address, "10.1.2.3")
        self.assertEqual(address.getHostAddress(), "10.1.2.3")
        self.assertEqual(address.getHostName(), "10.1.2.3")


class MetadataReplyTests(unittest.TestCase):
    def test_proxy_service_changes_are_returned_to_the_host(self):
        result = run_bridge(SERVICE_CHANGER, [{
            "id": 1, "method": "on_proxy_message", "params": proxy_params(RAW_REQUEST)}])

        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.frames[-1]["result"]["service"], {
            "host": "changed.test", "port": 9443, "protocol": "https"})

    def test_http_metadata_changes_are_returned_to_the_host(self):
        result = run_bridge(HTTP_METADATA_CHANGER, [{
            "id": 1, "method": "on_http_message", "params": http_params()}])

        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.frames[-1]["result"], {
            "comment": "http-comment",
            "highlight": "green",
            "service": {"host": "http.test", "port": 8443, "protocol": "https"},
        })
