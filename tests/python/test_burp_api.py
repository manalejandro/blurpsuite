"""Tests for the Burp-compatible value objects and extension helpers."""

from __future__ import annotations

import unittest

from support import REPO_ROOT  # noqa: F401  (path setup must happen before imports)

import burp
from blurp import api as blurp_api
from burp import api as burp_api

FORM_REQUEST = (
    b"POST /search?q=a%20b&x=1 HTTP/1.1\r\n"
    b"Host: example.test\r\n"
    b"Content-Type: application/x-www-form-urlencoded\r\n"
    b"Content-Length: 18\r\n"
    b"\r\n"
    b"name=Alice&city=NY"
)
JSON_REQUEST = (
    b"POST /api HTTP/1.1\r\n"
    b"Host: example.test\r\n"
    b"Content-Type: application/json\r\n"
    b"\r\n"
    b'{"a":1,"b":"x"}'
)
HTML_RESPONSE = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: text/html; charset=utf-8\r\n"
    b"Set-Cookie: sid=abc; Path=/; Domain=example.test\r\n"
    b"\r\n"
    b"<html><body>hi</body></html>"
)


def body_offset(message: bytes) -> int:
    return message.index(b"\r\n\r\n") + 4


class CodecTests(unittest.TestCase):
    def test_module_level_encode_decode(self):
        self.assertEqual(burp_api.encode(b"\x00\xff"), "AP8=")
        self.assertEqual(burp_api.encode("café"), "Y2Fm6Q==")  # latin-1 like Burp
        self.assertEqual(burp_api.decode("Y2Fm6Q=="), b"caf\xe9")
        self.assertEqual(burp_api.decode(None), b"")
        self.assertEqual(burp_api.decode(""), b"")
        self.assertEqual(burp_api.decode("a"), b"")  # malformed base64

    def test_helper_codecs_delegate_to_the_same_rules(self):
        helpers = burp_api.Helpers()
        self.assertEqual(helpers.base64Encode(b"\x00\xff"), "AP8=")
        self.assertEqual(helpers.base64Decode("AP8="), b"\x00\xff")
        self.assertEqual(helpers.bytesToString(b"caf\xe9"), "café")
        self.assertEqual(helpers.bytesToString(bytearray(b"a\xff")), "aÿ")
        self.assertEqual(helpers.bytesToString(None), "")
        self.assertEqual(helpers.stringToBytes("café"), b"caf\xe9")
        self.assertEqual(helpers.urlEncode("a b+c/d"), "a+b%2Bc%2Fd")
        self.assertEqual(helpers.urlDecode("a+b%2Bc"), "a b+c")
        self.assertEqual(helpers.indexOf("Hello hello", "hello"), 6)
        self.assertEqual(helpers.indexOf("Hello hello", "hello", False), 0)
        self.assertEqual(helpers.indexOf("abcabc", "abc", True, 1, 5), -1)


class ValueObjectTests(unittest.TestCase):
    def test_http_service(self):
        service = burp_api.HttpService("example.test", "8443", "HTTPS")
        self.assertEqual(service.getHost(), "example.test")
        self.assertEqual(service.getPort(), 8443)
        self.assertEqual(service.getProtocol(), "https")
        self.assertEqual(service.to_dict(),
                         {"host": "example.test", "port": 8443, "protocol": "https"})
        self.assertEqual(str(service), "https://example.test:8443")
        self.assertIn("HttpService(", repr(service))

        default = burp_api.HttpService.from_dict(None)
        self.assertEqual(default.to_dict(), {"host": "", "port": 0, "protocol": "http"})
        self.assertEqual(burp_api.HttpService.from_dict(
            {"host": "h", "port": "8080", "protocol": "ftp"}).getProtocol(), "http")

    def test_http_request_response_is_mutable(self):
        service = burp_api.HttpService("example.test", 443, "https")
        info = burp_api.HttpRequestResponse(bytearray(b"REQ"), bytearray(b"RES"), service)
        self.assertEqual(info.getRequest(), b"REQ")
        self.assertEqual(info.getResponse(), b"RES")
        self.assertIs(info.getHttpService(), service)

        info.setRequest(b"NEW-REQ")
        info.setResponse(b"NEW-RES")
        info.setHttpService(burp_api.HttpService("other", 80, "http"))
        info.setComment(None)
        info.setHighlight(None)
        self.assertEqual(info.getRequest(), b"NEW-REQ")
        self.assertEqual(info.getResponse(), b"NEW-RES")
        self.assertEqual(info.getHttpService().getHost(), "other")
        self.assertEqual(info.getComment(), "")
        self.assertEqual(info.getHighlight(), "")

        info.setMarkers([(1, 2)], [(3, 4)])
        self.assertEqual(info.getRequestMarkers(), [(1, 2)])
        self.assertEqual(info.getResponseMarkers(), [(3, 4)])

    def test_intercepted_proxy_message(self):
        info = burp_api.HttpRequestResponse(b"REQ")
        message = burp_api.InterceptedProxyMessage(info, 17, "listener-1", "10.0.0.1")
        self.assertIs(message.getMessageInfo(), info)
        self.assertEqual(message.getMessageReference(), 17)
        self.assertEqual(message.getListenerInterface(), "listener-1")
        self.assertEqual(message.getClientIpAddress(), "10.0.0.1")
        self.assertEqual(message.getInterceptAction(), burp_api.ACTION_FOLLOW_RULES)
        message.setInterceptAction(str(burp_api.ACTION_DROP))
        self.assertEqual(message.getInterceptAction(), 3)
        self.assertEqual(burp.IParameter.PARAM_JSON, 6)
        self.assertEqual(burp.IInterceptedProxyMessage.ACTION_DROP, 3)

    def test_small_value_objects(self):
        header = burp_api.HttpHeader("X-Test", "yes")
        self.assertEqual((header.getName(), header.getValue()), ("X-Test", "yes"))

        cookie = burp_api.Cookie("example.test", "tomorrow", "sid", "/", "abc")
        self.assertEqual((cookie.getDomain(), cookie.getExpiration(), cookie.getName(),
                          cookie.getPath(), cookie.getValue()),
                         ("example.test", "tomorrow", "sid", "/", "abc"))

        parameter = burp_api.Parameter("q", "a b", burp_api.Parameter.PARAM_BODY,
                                       1, 2, 3, 4)
        self.assertEqual((parameter.getName(), parameter.getValue(), parameter.getType(),
                          parameter.getNameStart(), parameter.getNameEnd(),
                          parameter.getValueStart(), parameter.getValueEnd()),
                         ("q", "a b", 1, 1, 2, 3, 4))
        self.assertIn("Parameter(", repr(parameter))

        request_info = burp_api.RequestInfo(
            "POST", "https://example.test:8443/api?x=1", ["Host: example.test"],
            [parameter], 12, burp_api.RequestInfo.CONTENT_TYPE_JSON)
        self.assertEqual(request_info.getMethod(), "POST")
        self.assertEqual(request_info.getUrl().geturl(),
                         "https://example.test:8443/api?x=1")
        self.assertEqual(request_info.getHeaders(), ["Host: example.test"])
        self.assertEqual(request_info.getParameters(), [parameter])
        self.assertEqual(request_info.getBodyOffset(), 12)
        self.assertEqual(request_info.getContentType(), 4)

        response_info = burp_api.ResponseInfo(201, ["HTTP/1.1 201 Created"],
                                              [cookie], 42, "application/json", "JSON")
        self.assertEqual(response_info.getStatusCode(), 201)
        self.assertEqual(response_info.getHeaders(), ["HTTP/1.1 201 Created"])
        self.assertEqual(response_info.getCookies(), [cookie])
        self.assertEqual(response_info.getBodyOffset(), 42)
        self.assertEqual(response_info.getStatedMimeType(), "application/json")
        self.assertEqual(response_info.getInferredMimeType(), "JSON")


class HelpersTests(unittest.TestCase):
    def setUp(self):
        self.helpers = burp_api.Helpers()

    def test_builders(self):
        self.assertEqual(self.helpers.buildHeader("A", "b").getValue(), "b")
        parameter = self.helpers.buildParameter("a", "b", burp_api.Parameter.PARAM_COOKIE)
        self.assertEqual((parameter.getName(), parameter.getType()), ("a", 2))
        self.assertEqual(self.helpers.buildHttpService("h", 443, True).getProtocol(), "https")
        self.assertEqual(self.helpers.buildHttpService("h", 80, False).getProtocol(), "http")
        self.assertEqual(self.helpers.buildHttpMessage(["GET / HTTP/1.1", "Host: h"], b"x"),
                         b"GET / HTTP/1.1\r\nHost: h\r\n\r\nx")
        self.assertTrue(self.helpers.buildHttpRequest(
            "https://example.test:8443/a?b=c").startswith(
                b"GET /a?b=c HTTP/1.1\r\nHost: example.test:8443\r\n"))

    def test_analyze_request_with_service(self):
        parsed = self.helpers.analyzeRequest(
            FORM_REQUEST, burp_api.HttpService("example.test", 8080, "https"))
        self.assertEqual(parsed.getMethod(), "POST")
        self.assertEqual(parsed.getUrl().geturl(),
                         "https://example.test:8080/search?q=a%20b&x=1")
        self.assertEqual(parsed.getHeaders(), [
            "Host: example.test",
            "Content-Type: application/x-www-form-urlencoded",
            "Content-Length: 18",
        ])
        self.assertEqual(parsed.getBodyOffset(), body_offset(FORM_REQUEST))
        self.assertEqual(parsed.getContentType(),
                         burp_api.RequestInfo.CONTENT_TYPE_URL_ENCODED)
        self.assertEqual([(p.getName(), p.getValue(), p.getType())
                          for p in parsed.getParameters()],
                         [("q", "a b", 0), ("x", "1", 0),
                          ("name", "Alice", 1), ("city", "NY", 1)])

    def test_analyze_request_from_message_info_and_json_body(self):
        info = burp_api.HttpRequestResponse(
            JSON_REQUEST, service=burp_api.HttpService("example.test", 443, "https"))
        parsed = self.helpers.analyzeRequest(info)
        self.assertEqual(parsed.getUrl().geturl(), "https://example.test/api")
        self.assertEqual(parsed.getContentType(), burp_api.RequestInfo.CONTENT_TYPE_JSON)
        self.assertEqual([(p.getName(), p.getValue(), p.getType())
                          for p in parsed.getParameters()],
                         [("a", "1", 6), ("b", "x", 6)])
        self.assertEqual(self.helpers.getRequestParameter(FORM_REQUEST, "x").getValue(), "1")
        self.assertIsNone(self.helpers.getRequestParameter(FORM_REQUEST, "missing"))

    def test_analyze_response(self):
        parsed = self.helpers.analyzeResponse(HTML_RESPONSE)
        self.assertEqual(parsed.getStatusCode(), 200)
        self.assertEqual(parsed.getBodyOffset(), body_offset(HTML_RESPONSE))
        self.assertEqual(parsed.getStatedMimeType(), "text/html")
        self.assertEqual(parsed.getInferredMimeType(), "HTML")
        self.assertEqual(parsed.getHeaders(), [
            "Content-Type: text/html; charset=utf-8",
            "Set-Cookie: sid=abc; Path=/; Domain=example.test",
        ])
        self.assertEqual([(c.getName(), c.getValue(), c.getDomain(), c.getPath())
                          for c in parsed.getCookies()],
                         [("sid", "abc", "example.test", "/")])
        json_response = b"HTTP/1.1 404 Not Found\r\n\r\n{\"error\":true}"
        json_info = self.helpers.analyzeResponse(json_response)
        self.assertEqual(json_info.getStatusCode(), 404)
        self.assertEqual(json_info.getInferredMimeType(), "JSON")

    def test_scanner_helpers(self):
        insertion = self.helpers.makeScannerInsertionPoint("param", b"abcDEFghi", 3, 6)
        self.assertEqual(insertion.getBaseValue(), "DEF")
        self.assertEqual(insertion.buildRequest(b"X"), b"abcXghi")
        self.assertEqual(insertion.getPayloadOffsets(b"XY"), (3, 5))
        self.assertEqual(insertion.getInsertionPointName(), "param")
        self.assertEqual(insertion.getInsertionPointType(), 64)

        keywords = self.helpers.analyzeResponseKeywords(["error", "ok"], "ok ok", "error")
        self.assertEqual(keywords.getKeywordCount("ok", 0), 2)
        self.assertEqual(keywords.getKeywordCount("error", 1), 1)
        self.assertEqual(keywords.getKeywordCount("absent", 0), 0)
        self.assertEqual(keywords.getVariantKeywords(), ["error", "ok"])
        self.assertEqual(keywords.getInvariantKeywords(), [])

        responses = (b"HTTP/1.1 200 OK\r\nX: a\r\n\r\nhi",
                     b"HTTP/1.1 500 Error\r\nX: a\r\n\r\nlong body")
        variations = self.helpers.analyzeResponseVariations(*responses)
        self.assertEqual(variations.getAttributeValue("status_code", 0), 200)
        self.assertEqual(variations.getAttributeValue("status_code", 1), 500)
        self.assertEqual(variations.getVariantAttributes(),
                         ["status_code", "content_length", "body_offset"])
        self.assertEqual(variations.getInvariantAttributes(), ["header_count"])


class ReexportTests(unittest.TestCase):
    def test_burp_all_names_are_importable(self):
        for name in burp.__all__:
            with self.subTest(name=name):
                self.assertTrue(hasattr(burp, name), name)

    def test_blurp_api_reexports_the_same_objects(self):
        for name in blurp_api.__all__:
            with self.subTest(name=name):
                self.assertIs(getattr(blurp_api, name), getattr(burp_api, name))


if __name__ == "__main__":
    unittest.main()
