"""Backslash Powered Scanner style anomaly detection (offline implementation).

Combines passive detection of ambiguous request framing with active
backslash/delimiter probes that look for response discrepancies.
"""

from __future__ import annotations

import re
from collections import OrderedDict

try:
    from .common import (bounded_add, enabled, header_value, is_chunked, raw_split, report,
                         set_content_length, setting, split_message, text, url_of)
except ImportError:
    from common import (bounded_add, enabled, header_value, is_chunked, raw_split, report,
                        set_content_length, setting, split_message, text, url_of)

from burp import IBurpExtender, IHttpListener

PROBES = (r"\\", r"\'", r'\"', r";", r"//", r"%00")
DIFFERENT = re.compile(r"(error|exception|invalid|unexpected|parse|syntax)", re.IGNORECASE)


class BurpExtender(IBurpExtender, IHttpListener):
    TAG = "BackslashScanner"

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.reported = OrderedDict()
        self.probed = OrderedDict()
        callbacks.setExtensionName("Blurp Backslash Scanner")
        if enabled(callbacks, "backslashscanner"):
            callbacks.registerHttpListener(self)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        request = messageInfo.getRequest()
        if not request:
            return
        url = url_of(request, messageInfo.getHttpService())
        _, headers, _ = split_message(request)
        if messageIsRequest:
            length = header_value(headers, "Content-Length")
            transfer = header_value(headers, "Transfer-Encoding")
            if length and transfer:
                key = ("ambiguous-framing", url)
                if bounded_add(self.reported, key):
                    report(self.callbacks, self.TAG,
                           f"ambiguous framing (CL+TE) on {url}")
            return
        if setting(self.callbacks, "backslashscanner.active", "true").lower() != "true":
            return
        self._probe(messageInfo, url)

    def _probe(self, messageInfo, url):
        baseline = text(messageInfo.getResponse() or b"")
        request = messageInfo.getRequest()
        head, separator, body = raw_split(request)
        if not separator or (b"=" not in body and b"?" not in head):
            return
        for payload in PROBES:
            modified = self._inject(request, payload)
            key = (payload, url)
            if modified == request or not bounded_add(self.probed, key):
                continue
            try:
                replay = self.callbacks.makeHttpRequest(messageInfo.getHttpService(), modified)
            except Exception as exc:
                report(self.callbacks, self.TAG, f"probe failed on {url}: {exc}")
                continue
            candidate = text(replay.getResponse() or b"")
            if (DIFFERENT.search(candidate) and not DIFFERENT.search(baseline)
                    and bounded_add(self.reported, key)):
                report(self.callbacks, self.TAG,
                       f"parser anomaly with {payload!r} on {url}")

    @staticmethod
    def _inject(request: bytes, payload: str) -> bytes:
        head, separator, body = raw_split(request)
        if not separator:
            return request
        line_separator = b"\r\n" if separator == b"\r\n\r\n" else b"\n"
        lines = head.split(line_separator)
        parts = lines[0].decode("latin-1", "replace").split(" ", 2)
        if len(parts) == 3 and "?" in parts[1] and "=" in parts[1].split("?", 1)[1]:
            method, target, version = parts
            path, _, query = target.partition("?")
            name, value = query.split("=", 1)
            end = len(value)
            for delimiter in ("&", "#"):
                index = value.find(delimiter)
                if index >= 0:
                    end = min(end, index)
            new_target = f"{path}?{name}={value[:end]}{payload}{value[end:]}"
            lines[0] = f"{method} {new_target} {version}".encode("latin-1", "replace")
            return line_separator.join(lines) + separator + body
        if is_chunked(request):
            return request
        if b"=" in body:
            name, _, value = body.partition(b"=")
            end = len(value)
            for delimiter in (b"&", b"\r\n", b"\n"):
                index = value.find(delimiter)
                if index >= 0:
                    end = min(end, index)
            body = name + b"=" + value[:end] + payload.encode() + value[end:]
            updated = line_separator.join(lines) + separator + body
            return set_content_length(updated, len(body))
        return request
