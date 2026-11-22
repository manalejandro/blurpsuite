"""Concrete API objects used by Blurp Suite's Python extension bridge."""

from __future__ import annotations

import base64
import json
import re
import urllib.parse
from datetime import datetime
from http.cookies import SimpleCookie
from typing import Any, Iterable

TOOL_SUITE = 1
TOOL_TARGET = 2
TOOL_PROXY = 4
TOOL_SPIDER = 8
TOOL_SCANNER = 16
TOOL_INTRUDER = 32
TOOL_REPEATER = 64
TOOL_SEQUENCER = 128
TOOL_DECODER = 256
TOOL_COMPARER = 512
TOOL_EXTENDER = 1024

ACTION_FOLLOW_RULES = 0
ACTION_DO_INTERCEPT = 1
ACTION_DONT_INTERCEPT = 2
ACTION_DROP = 3
ACTION_FOLLOW_RULES_AND_REHOOK = 16
ACTION_DO_INTERCEPT_AND_REHOOK = 17
ACTION_DONT_INTERCEPT_AND_REHOOK = 18


def _unsupported(method: str, detail: str = ""):
    """Build a callback that fails loudly instead of silently doing nothing."""

    def unsupported(self, *args, **kwargs):
        suffix = f" {detail}" if detail else ""
        raise NotImplementedError(
            f"{method} is not supported by the Blurp Suite Python bridge{suffix}")

    unsupported.__name__ = method
    unsupported.__qualname__ = f"BurpExtenderCallbacks.{method}"
    unsupported.__doc__ = f"Compatibility placeholder for {method}."
    return unsupported


class _CallbackOutputStream:
    """Small file-like object backed by a callbacks print method."""

    def __init__(self, write):
        self._write = write

    def write(self, data) -> int:
        text = _text(data)
        if text:
            self._write(text)
        return len(text)

    def writelines(self, lines) -> None:
        for line in lines:
            self.write(line)

    def flush(self) -> None:
        pass

    def close(self) -> None:
        pass

    def writable(self) -> bool:
        return True

    def isatty(self) -> bool:
        return False


def encode(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("latin-1")
    return base64.b64encode(data).decode("ascii")


def decode(value: str | None) -> bytes:
    if not value:
        return b""
    try:
        return base64.b64decode(value)
    except Exception:
        return b""


class HttpService:
    """Value object implementing the Extender HTTP service contract."""

    def __init__(self, host: str = "", port: int = 0, protocol: str = "http"):
        self._host = host
        self._port = int(port)
        self._protocol = "https" if str(protocol).lower() == "https" else "http"

    @classmethod
    def from_dict(cls, data: dict | None) -> "HttpService":
        data = data or {}
        return cls(str(data.get("host", "")), int(data.get("port", 0) or 0),
                   str(data.get("protocol", "http")))

    def to_dict(self) -> dict:
        return {"host": self._host, "port": self._port, "protocol": self._protocol}

    def getHost(self) -> str:
        return self._host

    def getPort(self) -> int:
        return self._port

    def getProtocol(self) -> str:
        return self._protocol

    def __str__(self) -> str:
        return f"{self._protocol}://{self._host}:{self._port}"

    def __repr__(self) -> str:
        return f"HttpService({self._host!r}, {self._port}, {self._protocol!r})"


class HttpRequestResponse:
    """Mutable request/response pair delivered to Python listeners."""

    def __init__(self, request: bytes = b"", response: bytes = b"",
                 service: HttpService | None = None, comment: str = "",
                 highlight: str = "", reference: int = 0):
        self._request = bytes(request)
        self._response = bytes(response)
        self._service = service or HttpService()
        self._comment = comment
        self._highlight = highlight
        self._reference = reference
        self._request_markers: list[tuple[int, int]] = []
        self._response_markers: list[tuple[int, int]] = []

    def getRequest(self) -> bytes:
        return self._request

    def setRequest(self, message: bytes) -> None:
        self._request = bytes(message or b"")

    def getResponse(self) -> bytes:
        return self._response

    def setResponse(self, message: bytes) -> None:
        self._response = bytes(message or b"")

    def getHttpService(self) -> HttpService:
        return self._service

    def setHttpService(self, service: HttpService) -> None:
        self._service = service

    def getComment(self) -> str:
        return self._comment

    def setComment(self, comment: str) -> None:
        self._comment = comment or ""

    def getHighlight(self) -> str:
        return self._highlight

    def setHighlight(self, color: str) -> None:
        self._highlight = color or ""

    def getRequestMarkers(self):
        return self._request_markers

    def getResponseMarkers(self):
        return self._response_markers

    def setMarkers(self, request_markers, response_markers) -> None:
        self._request_markers = [tuple(pair) for pair in request_markers]
        self._response_markers = [tuple(pair) for pair in response_markers]


class _InetAddress(str):
    """String-compatible stand-in for java.net.InetAddress used by the bridge."""

    def getHostAddress(self) -> str:
        return str(self)

    def getHostName(self) -> str:
        return str(self)


class InterceptedProxyMessage:
    """Proxy message with a mutable intercept action."""

    def __init__(self, message_info: HttpRequestResponse, reference: int = 0,
                 listener: str = "", client_address: str = ""):
        self._message_info = message_info
        self._reference = reference
        self._listener = listener
        self._client_address = client_address
        self._action = ACTION_FOLLOW_RULES

    def getClientIpAddress(self) -> _InetAddress:
        return _InetAddress(self._client_address)

    def getInterceptAction(self) -> int:
        return self._action

    def setInterceptAction(self, action: int) -> None:
        self._action = int(action)

    def getListenerInterface(self) -> str:
        return self._listener

    def getMessageInfo(self) -> HttpRequestResponse:
        return self._message_info

    def getMessageReference(self) -> int:
        return self._reference


class Parameter:
    """HTTP parameter value object."""

    PARAM_URL = 0
    PARAM_BODY = 1
    PARAM_COOKIE = 2
    PARAM_XML = 3
    PARAM_XML_ATTR = 4
    PARAM_MULTIPART_ATTR = 5
    PARAM_JSON = 6

    def __init__(self, name: str, value: str, kind: int = PARAM_URL,
                 name_start: int = -1, name_end: int = -1,
                 value_start: int = -1, value_end: int = -1):
        self._name = name
        self._value = value
        self._type = int(kind)
        self._name_start = name_start
        self._name_end = name_end
        self._value_start = value_start
        self._value_end = value_end

    def getName(self) -> str:
        return self._name

    def getValue(self) -> str:
        return self._value

    def getType(self) -> int:
        return self._type

    def getNameStart(self) -> int:
        return self._name_start

    def getNameEnd(self) -> int:
        return self._name_end

    def getValueStart(self) -> int:
        return self._value_start

    def getValueEnd(self) -> int:
        return self._value_end

    def __repr__(self) -> str:
        return f"Parameter({self._name!r}, {self._value!r}, {self._type})"


class HttpHeader:
    def __init__(self, name: str, value: str):
        self._name = name
        self._value = value

    def getName(self) -> str:
        return self._name

    def getValue(self) -> str:
        return self._value


class Cookie:
    def __init__(self, domain: str = "", expiration=None, name: str = "",
                 path: str = "", value: str = ""):
        self._domain = domain
        self._expiration = expiration
        self._name = name
        self._path = path
        self._value = value

    def getDomain(self) -> str:
        return self._domain

    def getExpiration(self):
        return self._expiration

    def getName(self) -> str:
        return self._name

    def getPath(self) -> str:
        return self._path

    def getValue(self) -> str:
        return self._value


class RequestInfo:
    CONTENT_TYPE_NONE = 0
    CONTENT_TYPE_URL_ENCODED = 1
    CONTENT_TYPE_MULTIPART = 2
    CONTENT_TYPE_XML = 3
    CONTENT_TYPE_JSON = 4
    CONTENT_TYPE_AMF = 5
    CONTENT_TYPE_UNKNOWN = -1

    def __init__(self, method: str, url: str, headers: list[str],
                 parameters: list[Parameter], body_offset: int, content_type: int):
        self._method = method
        self._url = url
        self._headers = headers
        self._parameters = parameters
        self._body_offset = body_offset
        self._content_type = content_type

    def getMethod(self) -> str:
        return self._method

    def getUrl(self):
        return urllib.parse.urlsplit(self._url)

    def getHeaders(self) -> list[str]:
        return list(self._headers)

    def getParameters(self) -> list[Parameter]:
        return list(self._parameters)

    def getBodyOffset(self) -> int:
        return self._body_offset

    def getContentType(self) -> int:
        return self._content_type


class ResponseInfo:
    def __init__(self, status: int, headers: list[str], cookies: list[Cookie],
                 body_offset: int, stated: str, inferred: str):
        self._status = status
        self._headers = headers
        self._cookies = cookies
        self._body_offset = body_offset
        self._stated = stated
        self._inferred = inferred

    def getStatusCode(self) -> int:
        return self._status

    def getHeaders(self) -> list[str]:
        return list(self._headers)

    def getCookies(self) -> list[Cookie]:
        return list(self._cookies)

    def getBodyOffset(self) -> int:
        return self._body_offset

    def getStatedMimeType(self) -> str:
        return self._stated

    def getInferredMimeType(self) -> str:
        return self._inferred


def _text(data: bytes | bytearray | memoryview | str) -> str:
    if isinstance(data, (bytes, bytearray, memoryview)):
        return bytes(data).decode("latin-1")
    return data or ""


def _body_offset(message: bytes) -> int:
    index = message.find(b"\r\n\r\n")
    if index >= 0:
        return index + 4
    index = message.find(b"\n\n")
    return index + 2 if index >= 0 else len(message)


def _headers(message: bytes) -> list[str]:
    head = _text(message[:_body_offset(message)])
    lines = head.splitlines()
    return [line for line in lines[1:] if line.strip()]


def _header(message: bytes, name: str) -> str | None:
    for line in _headers(message):
        key, separator, value = line.partition(":")
        if separator and key.strip().lower() == name.lower():
            return value.strip()
    return None


class Helpers:
    """Pure-Python implementation of the common extension helper methods."""

    def analyzeRequest(self, request, service=None, message=None):
        if hasattr(request, "getRequest"):
            service = request.getHttpService()
            message = request
            request = request.getRequest()
        data = request if isinstance(request, bytes) else _text(request).encode("latin-1")
        offset = _body_offset(data)
        line = _text(data[:data.find(b"\n") if b"\n" in data else offset]).strip()
        parts = line.split()
        method = parts[0] if parts else "GET"
        target = parts[1] if len(parts) > 1 else "/"
        headers = _headers(data)
        scheme = service.getProtocol() if service else "http"
        host = service.getHost() if service else (_header(data, "Host") or "localhost")
        port = service.getPort() if service else 80
        authority = host if port in (80, 443) else f"{host}:{port}"
        url = target if target.startswith("http") else f"{scheme}://{authority}{target}"

        parameters: list[Parameter] = []
        if "?" in target:
            query = target.split("?", 1)[1]
            for pair in query.split("&"):
                name, _, value = pair.partition("=")
                parameters.append(Parameter(self.urlDecode(name), self.urlDecode(value),
                                            Parameter.PARAM_URL))
        content_type = _header(data, "Content-Type") or ""
        if "x-www-form-urlencoded" in content_type.lower():
            for pair in _text(data[offset:]).split("&"):
                name, _, value = pair.partition("=")
                if name:
                    parameters.append(Parameter(self.urlDecode(name), self.urlDecode(value),
                                                Parameter.PARAM_BODY))
        elif "json" in content_type.lower():
            try:
                parsed = json.loads(_text(data[offset:]))
                if isinstance(parsed, dict):
                    for key, value in parsed.items():
                        parameters.append(Parameter(key, str(value), Parameter.PARAM_JSON))
            except (ValueError, TypeError):
                pass

        kind = RequestInfo.CONTENT_TYPE_NONE
        lower = content_type.lower()
        if "urlencoded" in lower:
            kind = RequestInfo.CONTENT_TYPE_URL_ENCODED
        elif "multipart" in lower:
            kind = RequestInfo.CONTENT_TYPE_MULTIPART
        elif "json" in lower:
            kind = RequestInfo.CONTENT_TYPE_JSON
        elif "xml" in lower:
            kind = RequestInfo.CONTENT_TYPE_XML
        elif "amf" in lower:
            kind = RequestInfo.CONTENT_TYPE_AMF
        elif lower:
            kind = RequestInfo.CONTENT_TYPE_UNKNOWN
        return RequestInfo(method, url, headers, parameters, offset, kind)

    def analyzeResponse(self, response):
        data = response if isinstance(response, bytes) else _text(response).encode("latin-1")
        offset = _body_offset(data)
        line = _text(data[:data.find(b"\n") if b"\n" in data else offset]).strip().split()
        status = 0
        if len(line) > 1:
            try:
                status = int(line[1])
            except ValueError:
                pass
        headers = _headers(data)
        cookies: list[Cookie] = []
        for header in headers:
            name, separator, value = header.partition(":")
            if separator and name.strip().lower() == "set-cookie":
                jar = SimpleCookie()
                try:
                    jar.load(value.strip())
                    for key, morsel in jar.items():
                        cookies.append(Cookie(morsel.get("domain", ""),
                                              morsel.get("expires"), key,
                                              morsel.get("path", ""), morsel.value))
                except Exception:
                    continue
        stated = _header(data, "Content-Type") or ""
        if ";" in stated:
            stated = stated.split(";", 1)[0].strip()
        body = _text(data[offset:]).lstrip().lower()
        inferred = "UNKNOWN"
        if body.startswith("<!doctype html") or body.startswith("<html"):
            inferred = "HTML"
        elif body.startswith("<?xml") or body.startswith("<svg"):
            inferred = "XML"
        elif body.startswith("{") or body.startswith("["):
            inferred = "JSON"
        return ResponseInfo(status, headers, cookies, offset, stated, inferred)

    def base64Encode(self, data) -> str:
        return encode(data)

    def base64Decode(self, data) -> bytes:
        return decode(data)

    def bytesToString(self, data) -> str:
        return _text(data)

    def stringToBytes(self, data) -> bytes:
        return _text(data).encode("latin-1")

    def urlEncode(self, data) -> str:
        if isinstance(data, bytes):
            data = _text(data)
        return urllib.parse.quote_plus(data)

    def urlDecode(self, data) -> str:
        if isinstance(data, bytes):
            data = _text(data)
        return urllib.parse.unquote_plus(data)

    def indexOf(self, data, pattern, caseSensitive=True, start=0, end=None):
        haystack = _text(data)
        needle = _text(pattern)
        if not caseSensitive:
            haystack, needle = haystack.lower(), needle.lower()
        limit = len(haystack) if end is None else min(end, len(haystack))
        return haystack.find(needle, max(0, start), limit)

    def buildHeader(self, name: str, value: str) -> HttpHeader:
        return HttpHeader(name, value)

    def buildParameter(self, name: str, value: str, kind: int) -> Parameter:
        return Parameter(name, value, kind)

    def buildHttpService(self, host: str, port: int, useHttpsOrProtocol) -> HttpService:
        if isinstance(useHttpsOrProtocol, bool):
            protocol = "https" if useHttpsOrProtocol else "http"
        else:
            protocol = str(useHttpsOrProtocol)
        return HttpService(host, port, protocol)

    def buildHttpMessage(self, headers: Iterable[str], body: bytes = b"") -> bytes:
        head = "\r\n".join(headers) + "\r\n\r\n"
        payload = body if isinstance(body, bytes) else _text(body).encode("latin-1")
        return head.encode("latin-1") + payload

    def buildHttpRequest(self, url) -> bytes:
        parts = urllib.parse.urlsplit(str(url))
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        port = parts.port or (443 if parts.scheme == "https" else 80)
        authority = parts.hostname or "localhost"
        if port not in (80, 443):
            authority += f":{port}"
        return (f"GET {path} HTTP/1.1\r\nHost: {authority}\r\n"
                "User-Agent: Blurp Suite\r\nAccept: */*\r\nConnection: close\r\n\r\n").encode("latin-1")

    def getRequestParameter(self, request, name: str):
        for parameter in self.analyzeRequest(request).getParameters():
            if parameter.getName() == name:
                return parameter
        return None

    def addParameter(self, request: bytes, parameter: Parameter) -> bytes:
        text = _text(request)
        offset = _body_offset(request)
        head, body = text[:offset], text[offset:]
        pair = f"{self.urlEncode(parameter.getName())}={self.urlEncode(parameter.getValue())}"
        if parameter.getType() == Parameter.PARAM_URL:
            line_end = head.find("\n")
            first = head[:line_end].rstrip("\r")
            head = first + ("&" if "?" in first else "?") + pair + head[line_end:]
        elif parameter.getType() == Parameter.PARAM_COOKIE:
            cookie = _header(request, "Cookie")
            if cookie:
                head = re.sub(r"(?im)^(Cookie:)([^\r\n]*)", rf"\1 {pair}; \2", head)
            else:
                lines = head.splitlines(keepends=True)
                lines.insert(1, f"Cookie: {pair}\r\n")
                head = "".join(lines)
        else:
            body = pair if not body else f"{body}&{pair}"
        head = re.sub(r"(?im)^(Content-Length:)\s*\d+",
                      rf"\1 {len(body.encode('latin-1'))}", head)
        return (head + body).encode("latin-1")

    def updateParameter(self, request: bytes, parameter: Parameter) -> bytes:
        return self._replace_parameter(request, parameter,
                                       self.urlEncode(parameter.getValue()))

    def removeParameter(self, request: bytes, parameter: Parameter) -> bytes:
        return self._replace_parameter(request, parameter, "")

    def _replace_parameter(self, request: bytes, parameter: Parameter, value: str) -> bytes:
        start, end = parameter.getValueStart(), parameter.getValueEnd()
        if start < 0 or end < start or end > len(request):
            return request
        result = request[:start] + value.encode("latin-1") + request[end:]
        offset = _body_offset(result)
        head, body = _text(result[:offset]), _text(result[offset:])
        head = re.sub(r"(?im)^(Content-Length:)\s*\d+",
                      rf"\1 {len(body.encode('latin-1'))}", head)
        return (head + body).encode("latin-1")

    def toggleRequestMethod(self, request: bytes) -> bytes:
        text = _text(request)
        line_end = text.find("\n")
        if line_end < 0:
            return request
        parts = text[:line_end].rstrip("\r").split()
        if len(parts) < 2:
            return request
        to_post = parts[0].upper() == "GET"
        parts[0] = "POST" if to_post else "GET"
        head = " ".join(parts) + text[line_end:]
        offset = _body_offset(head.encode("latin-1"))
        headers, body = head[:offset], head[offset:]
        if to_post:
            if not re.search(r"(?im)^Content-Type:", headers):
                lines = headers.splitlines(keepends=True)
                lines.insert(1, "Content-Type: application/x-www-form-urlencoded\r\n")
                headers = "".join(lines)
            headers = re.sub(r"(?im)^(Content-Length:)\s*\d+",
                             rf"\1 {len(body.encode('latin-1'))}", headers)
        else:
            headers = re.sub(r"(?im)^(Content-Length|Content-Type):[^\r\n]*\r?\n?", "", headers)
        return (headers + body).encode("latin-1")

    def makeScannerInsertionPoint(self, name, request, start, end):
        return _InsertionPoint(name, bytes(request), int(start), int(end))

    def analyzeResponseKeywords(self, keywords, *responses):
        return _ResponseKeywords(list(keywords), responses)

    def analyzeResponseVariations(self, *responses):
        return _ResponseVariations(responses)


class _InsertionPoint:
    INS_USER_PROVIDED = 64

    def __init__(self, name, base, start, end):
        self._name = name
        self._base = base
        self._start = max(0, min(start, len(base)))
        self._end = max(self._start, min(end, len(base)))

    def getBaseValue(self):
        return _text(self._base[self._start:self._end])

    def buildRequest(self, payload):
        payload = payload if isinstance(payload, bytes) else _text(payload).encode("latin-1")
        return self._base[:self._start] + payload + self._base[self._end:]

    def getPayloadOffsets(self, payload):
        return (self._start, self._start + len(payload))

    def getInsertionPointName(self):
        return self._name

    def getInsertionPointType(self):
        return self.INS_USER_PROVIDED


class _ResponseKeywords:
    def __init__(self, keywords, responses):
        self._keywords = keywords
        self.updateWith(*responses)

    def updateWith(self, *responses):
        self._counts = []
        for response in responses:
            text = _text(response)
            self._counts.append([text.count(word) if word else 0 for word in self._keywords])

    def getKeywordCount(self, keyword, index):
        if keyword not in self._keywords or index >= len(self._counts):
            return 0
        return self._counts[index][self._keywords.index(keyword)]

    def getVariantKeywords(self):
        if not self._counts:
            return []
        return [word for i, word in enumerate(self._keywords)
                if any(row[i] != self._counts[0][i] for row in self._counts)]

    def getInvariantKeywords(self):
        variants = set(self.getVariantKeywords())
        return [word for word in self._keywords if word not in variants]


class _ResponseVariations:
    def __init__(self, responses):
        self.updateWith(*responses)

    def updateWith(self, *responses):
        self._rows = []
        for response in responses:
            info = Helpers().analyzeResponse(response)
            self._rows.append({
                "status_code": info.getStatusCode(),
                "content_length": len(response),
                "header_count": len(info.getHeaders()),
                "body_offset": info.getBodyOffset(),
            })

    def getAttributeValue(self, name, index):
        return self._rows[index].get(name, 0) if index < len(self._rows) else 0

    def getVariantAttributes(self):
        if not self._rows:
            return []
        return [key for key in self._rows[0]
                if any(row[key] != self._rows[0][key] for row in self._rows)]

    def getInvariantAttributes(self):
        variants = set(self.getVariantAttributes())
        return [key for key in self._rows[0] if key not in variants] if self._rows else []


class BurpExtenderCallbacks:
    """Callbacks object passed to Python extensions.

    Local state (listener registrations, settings, UI tabs) lives in the bridge;
    host-dependent operations are forwarded over JSON-RPC.
    """

    def __init__(self, transport, filename: str = "", arguments=None):
        self._transport = transport
        self._filename = filename
        self._arguments = list(arguments or [])
        self._name = filename or "Unnamed Python extension"
        self._helpers = Helpers()
        self._settings: dict[str, str] = {}
        self.proxy_listeners: list[Any] = []
        self.http_listeners: list[Any] = []
        self.state_listeners: list[Any] = []
        self.scope_listeners: list[Any] = []
        self.context_menu_factories: list[Any] = []
        self.tab_factories: list[Any] = []
        self.suite_tabs: list[Any] = []
        self.scanner_checks: list[Any] = []
        self.payload_generator_factories: list[Any] = []
        self.payload_processors: list[Any] = []
        self.insertion_point_providers: list[Any] = []
        self.scanner_listeners: list[Any] = []
        self.session_handling_actions: list[Any] = []

    @property
    def extensionName(self) -> str:
        return self._name

    def setExtensionName(self, name: str) -> None:
        self._name = str(name or "Unnamed Python extension")

    def getExtensionFilename(self) -> str:
        return self._filename

    def getBurpVersion(self):
        return ("Blurp Suite", "1.0.0", "community")

    def getCommandLineArguments(self):
        return list(self._arguments)

    def getToolName(self, flag: int) -> str:
        return {
            TOOL_SUITE: "Suite", TOOL_TARGET: "Target", TOOL_PROXY: "Proxy",
            TOOL_SPIDER: "Spider", TOOL_SCANNER: "Scanner", TOOL_INTRUDER: "Intruder",
            TOOL_REPEATER: "Repeater", TOOL_SEQUENCER: "Sequencer",
            TOOL_DECODER: "Decoder", TOOL_COMPARER: "Comparer", TOOL_EXTENDER: "Extender",
        }.get(int(flag), "Unknown")

    def getHelpers(self) -> Helpers:
        return self._helpers

    def printOutput(self, message) -> None:
        self._transport.notify("print_output", {"message": str(message)})

    def printError(self, message) -> None:
        self._transport.notify("print_error", {"message": str(message)})

    def issueAlert(self, message) -> None:
        self.printOutput("ALERT: " + str(message))

    def getStdout(self):
        return _CallbackOutputStream(self.printOutput)

    def getStderr(self):
        return _CallbackOutputStream(self.printError)

    def registerProxyListener(self, listener) -> None:
        if listener not in self.proxy_listeners:
            self.proxy_listeners.append(listener)

    def removeProxyListener(self, listener) -> None:
        if listener in self.proxy_listeners:
            self.proxy_listeners.remove(listener)

    def getProxyListeners(self):
        return list(self.proxy_listeners)

    def registerHttpListener(self, listener) -> None:
        if listener not in self.http_listeners:
            self.http_listeners.append(listener)
            self._transport.notify("set_http_listener_count",
                                   {"count": len(self.http_listeners)})

    def removeHttpListener(self, listener) -> None:
        if listener in self.http_listeners:
            self.http_listeners.remove(listener)
            self._transport.notify("set_http_listener_count",
                                   {"count": len(self.http_listeners)})

    def getHttpListeners(self):
        return list(self.http_listeners)

    def registerExtensionStateListener(self, listener) -> None:
        if listener not in self.state_listeners:
            self.state_listeners.append(listener)

    def removeExtensionStateListener(self, listener) -> None:
        if listener in self.state_listeners:
            self.state_listeners.remove(listener)

    def getExtensionStateListeners(self):
        return list(self.state_listeners)

    def registerScopeChangeListener(self, listener) -> None:
        if listener not in self.scope_listeners:
            self.scope_listeners.append(listener)
            self._transport.notify("set_scope_listener_count",
                                   {"count": len(self.scope_listeners)})

    def removeScopeChangeListener(self, listener) -> None:
        if listener in self.scope_listeners:
            self.scope_listeners.remove(listener)
            self._transport.notify("set_scope_listener_count",
                                   {"count": len(self.scope_listeners)})

    def getScopeChangeListeners(self):
        return list(self.scope_listeners)

    def registerContextMenuFactory(self, factory) -> None:
        if factory not in self.context_menu_factories:
            self.context_menu_factories.append(factory)

    def removeContextMenuFactory(self, factory) -> None:
        if factory in self.context_menu_factories:
            self.context_menu_factories.remove(factory)

    def getContextMenuFactories(self):
        return list(self.context_menu_factories)

    def registerMessageEditorTabFactory(self, factory) -> None:
        if factory not in self.tab_factories:
            self.tab_factories.append(factory)

    def removeMessageEditorTabFactory(self, factory) -> None:
        if factory in self.tab_factories:
            self.tab_factories.remove(factory)

    def getMessageEditorTabFactories(self):
        return list(self.tab_factories)

    def registerScannerCheck(self, check) -> None:
        if check not in self.scanner_checks:
            self.scanner_checks.append(check)

    def removeScannerCheck(self, check) -> None:
        if check in self.scanner_checks:
            self.scanner_checks.remove(check)

    def getScannerChecks(self):
        return list(self.scanner_checks)

    def registerIntruderPayloadGeneratorFactory(self, factory) -> None:
        if factory not in self.payload_generator_factories:
            self.payload_generator_factories.append(factory)

    def removeIntruderPayloadGeneratorFactory(self, factory) -> None:
        if factory in self.payload_generator_factories:
            self.payload_generator_factories.remove(factory)

    def getIntruderPayloadGeneratorFactories(self):
        return list(self.payload_generator_factories)

    def registerIntruderPayloadProcessor(self, processor) -> None:
        if processor not in self.payload_processors:
            self.payload_processors.append(processor)

    def removeIntruderPayloadProcessor(self, processor) -> None:
        if processor in self.payload_processors:
            self.payload_processors.remove(processor)

    def getIntruderPayloadProcessors(self):
        return list(self.payload_processors)

    def registerScannerInsertionPointProvider(self, provider) -> None:
        if provider not in self.insertion_point_providers:
            self.insertion_point_providers.append(provider)

    def removeScannerInsertionPointProvider(self, provider) -> None:
        if provider in self.insertion_point_providers:
            self.insertion_point_providers.remove(provider)

    def getScannerInsertionPointProviders(self):
        return list(self.insertion_point_providers)

    def registerScannerListener(self, listener) -> None:
        if listener not in self.scanner_listeners:
            self.scanner_listeners.append(listener)

    def removeScannerListener(self, listener) -> None:
        if listener in self.scanner_listeners:
            self.scanner_listeners.remove(listener)

    def getScannerListeners(self):
        return list(self.scanner_listeners)

    def registerSessionHandlingAction(self, action) -> None:
        if action not in self.session_handling_actions:
            self.session_handling_actions.append(action)

    def removeSessionHandlingAction(self, action) -> None:
        if action in self.session_handling_actions:
            self.session_handling_actions.remove(action)

    def getSessionHandlingActions(self):
        return list(self.session_handling_actions)

    def addSuiteTab(self, tab) -> None:
        if tab not in self.suite_tabs:
            self.suite_tabs.append(tab)

    def removeSuiteTab(self, tab) -> None:
        if tab in self.suite_tabs:
            self.suite_tabs.remove(tab)

    def isExtensionBapp(self) -> bool:
        return False

    def isInScope(self, url) -> bool:
        reply = self._transport.call("is_in_scope", {"url": str(url)})
        if isinstance(reply, dict):
            return bool(reply.get("value", False))
        return bool(reply)

    def includeInScope(self, url) -> None:
        self._transport.call("include_in_scope", {"url": str(url)})

    def excludeFromScope(self, url) -> None:
        self._transport.call("exclude_from_scope", {"url": str(url)})

    def setProxyInterceptionEnabled(self, enabled: bool) -> None:
        self._transport.call("set_interception", {"enabled": bool(enabled)})

    def getProxyHistory(self) -> list[HttpRequestResponse]:
        reply = self._transport.call("get_proxy_history", {})
        rows = reply.get("items", []) if isinstance(reply, dict) else reply or []
        history: list[HttpRequestResponse] = []
        for row in rows:
            if isinstance(row, HttpRequestResponse):
                history.append(row)
            elif isinstance(row, dict):
                history.append(HttpRequestResponse(
                    decode(row.get("request")), decode(row.get("response")),
                    HttpService.from_dict(row.get("service")),
                    comment=row.get("comment", "") or "",
                    highlight=row.get("highlight", "") or "",
                    reference=int(row.get("reference", 0) or 0)))
        return history

    def addToSiteMap(self, item) -> None:
        request = item.getRequest() if hasattr(item, "getRequest") else b""
        response = item.getResponse() if hasattr(item, "getResponse") else b""
        service = item.getHttpService() if hasattr(item, "getHttpService") else HttpService()
        self._transport.call("add_to_site_map", {
            "request": encode(request), "response": encode(response),
            "service": service.to_dict() if hasattr(service, "to_dict") else {},
        })

    def makeHttpRequest(self, service, request, *args):
        data = self._transport.call("make_http_request", {
            "service": service.to_dict() if hasattr(service, "to_dict") else {},
            "request": encode(request),
        })
        return HttpRequestResponse(decode(data.get("request")), decode(data.get("response")),
                                   HttpService.from_dict(data.get("service")))

    def saveExtensionSetting(self, name: str, value: str) -> None:
        self._settings[str(name)] = str(value)

    def loadExtensionSetting(self, name: str):
        return self._settings.get(str(name))

    def saveConfig(self) -> dict:
        return dict(self._settings)

    def loadConfig(self, config: dict) -> None:
        self._settings.update({str(key): str(value) for key, value in (config or {}).items()})

    def saveConfigAsJson(self, *paths) -> str:
        return json.dumps(self._settings)

    def loadConfigFromJson(self, config: str) -> None:
        parsed = json.loads(config)
        if isinstance(parsed, dict):
            self.loadConfig(parsed)

    def saveState(self, file) -> None:
        with open(file, "w", encoding="utf-8") as handle:
            json.dump(self._settings, handle)

    def restoreState(self, file) -> None:
        with open(file, encoding="utf-8") as handle:
            self.loadConfig(json.load(handle))

    def getHeaders(self, message):
        return _headers(message if isinstance(message, bytes)
                        else _text(message).encode("latin-1"))

    def getParameters(self, request):
        return [[p.getName(), p.getValue()] for p in self._helpers.analyzeRequest(request).getParameters()]

    def applyMarkers(self, base, request_markers, response_markers):
        marked = HttpRequestResponse(base.getRequest(), base.getResponse(), base.getHttpService())
        marked.setMarkers(request_markers, response_markers)
        return marked

    def exitSuite(self, promptUser=False) -> None:
        self._transport.notify("exit_suite", {"prompt": bool(promptUser)})

    def unloadExtension(self) -> None:
        self._transport.notify("unload_extension", {})

    def createBurpCollaboratorClientContext(self):
        return _OfflineCollaborator()

    def doPassiveScan(self, host, port, useHttps, request, response) -> None:
        self._transport.call("do_passive_scan", {
            "host": host, "port": port, "useHttps": bool(useHttps),
            "request": encode(request), "response": encode(response),
        })

    def generateScanReport(self, format, issues, file) -> None:
        with open(file, "w", encoding="utf-8") as handle:
            handle.write("<html><body><h1>Blurp Suite scan report</h1><ul>")
            for issue in issues:
                handle.write(f"<li>{getattr(issue, 'getIssueName', lambda: '')()}</li>")
            handle.write("</ul></body></html>")

    # These names are part of the published callback contract, but the Python
    # bridge has no host-side implementation for them.  They fail loudly so an
    # extension can never mistake a missing feature for a successful no-op.
    addScanIssue = _unsupported("addScanIssue", "scan issues are not collected")
    createMessageEditor = _unsupported("createMessageEditor", "Swing editors are Java-only")
    createTextEditor = _unsupported("createTextEditor", "Swing editors are Java-only")
    customizeUiComponent = _unsupported("customizeUiComponent", "Swing UI is Java-only")
    doActiveScan = _unsupported("doActiveScan", "active scanning is not implemented")
    getCookieJarContents = _unsupported("getCookieJarContents", "the cookie jar is not bridged")
    getScanIssues = _unsupported("getScanIssues", "scan issues are not collected")
    getSiteMap = _unsupported("getSiteMap", "the site map is not bridged")
    makeHttp2Request = _unsupported("makeHttp2Request", "the proxy supports HTTP/1.1 only")
    registerMenuItem = _unsupported("registerMenuItem", "menu items are not displayed")
    saveBuffersToTempFiles = _unsupported("saveBuffersToTempFiles", "temp files are not bridged")
    saveToTempFile = _unsupported("saveToTempFile", "temp files are not bridged")
    sendToComparer = _unsupported("sendToComparer", "the Comparer tool is not implemented")
    sendToIntruder = _unsupported("sendToIntruder", "the Intruder tool is not implemented")
    sendToRepeater = _unsupported("sendToRepeater", "the Repeater tool is not implemented")
    sendToSpider = _unsupported("sendToSpider", "the Spider tool is not implemented")
    updateCookieJar = _unsupported("updateCookieJar", "the cookie jar is not bridged")


class _OfflineCollaborator:
    def generatePayload(self, includeCollaboratorServerLocation=True):
        import uuid
        return uuid.uuid4().hex + ".blurp.local"

    def getCollaboratorServerLocation(self):
        return "blurp.local"

    def fetchAllCollaboratorInteractions(self):
        return []

    def fetchAllInfiltratorInteractions(self):
        return []

    def fetchCollaboratorInteractionsFor(self, payload):
        return []

    def fetchInfiltratorInteractionsFor(self, payload):
        return []
