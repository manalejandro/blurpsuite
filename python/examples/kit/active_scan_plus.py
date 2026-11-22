"""Active Scan++ style edge-case checks (offline implementation).

Runs passive signature checks on traffic and a small set of active probes
against request parameters. All probes are read-only-style payloads injected
into a copied request through ``makeHttpRequest``; no traffic is sent by the
extension itself.
"""

from __future__ import annotations

import re
from collections import OrderedDict

try:
    from .common import (body_of, bounded_add, enabled, is_chunked, raw_split, report,
                         set_content_length, setting, text, url_of)
except ImportError:
    from common import (body_of, bounded_add, enabled, is_chunked, raw_split, report,
                        set_content_length, setting, text, url_of)

from burp import IBurpExtender, IHttpListener

PASSIVE_SIGNATURES = {
    "SQL error": re.compile(r"(sql syntax|mysql|ora-\d{5}|unclosed quotation|pg_query)", re.I),
    "stack trace": re.compile(r"(at [a-z_]+(?:\.[a-z_]+)+\(|traceback|exception in thread)", re.I),
    "template error": re.compile(r"(templateerror|twig|jinja|freemarker|smarty)", re.I),
    "debug output": re.compile(r"(stack trace|debug mode|phpinfo|<pre>\s*array)", re.I),
}

PROBES = {
    "SSTI": ("{{7*7}}", "49"),
    "XSS reflection": ("<b>burpkit</b>", "<b>burpkit</b>"),
    "XML entity": ("&xxe;", "xxe"),
}


def _inject(request: bytes, value: str) -> bytes:
    """Append a probe to the first query parameter or form field."""
    head, separator, body = raw_split(request)
    if not separator:
        return request
    line_separator = b"\r\n" if separator == b"\r\n\r\n" else b"\n"
    lines = head.split(line_separator)
    parts = lines[0].decode("latin-1", "replace").split(" ", 2)
    if len(parts) == 3 and "?" in parts[1] and "=" in parts[1].split("?", 1)[1]:
        method, target, version = parts
        base, _, query = target.partition("?")
        name, old = query.split("=", 1)
        modified = f"{base}?{name}={old}{value}"
        lines[0] = f"{method} {modified} {version}".encode("latin-1", "replace")
        return line_separator.join(lines) + separator + body
    if is_chunked(request) or b"=" not in body:
        return request
    name, _, old = body.partition(b"=")
    end = len(old)
    for delimiter in (b"&", b"\r\n", b"\n"):
        index = old.find(delimiter)
        if index >= 0:
            end = min(end, index)
    body = name + b"=" + old[:end] + value.encode() + old[end:]
    updated = line_separator.join(lines) + separator + body
    return set_content_length(updated, len(body))


class BurpExtender(IBurpExtender, IHttpListener):
    TAG = "ActiveScan++"

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.passive_reported = OrderedDict()
        self.active_reported = OrderedDict()
        callbacks.setExtensionName("Blurp Active Scan++")
        if enabled(callbacks, "activescan"):
            callbacks.registerHttpListener(self)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        response = messageInfo.getResponse()
        if messageIsRequest or not response:
            return
        url = url_of(messageInfo.getRequest(), messageInfo.getHttpService())
        body = text(body_of(response))
        for name, pattern in PASSIVE_SIGNATURES.items():
            if pattern.search(body) and bounded_add(self.passive_reported, (name, url)):
                report(self.callbacks, self.TAG, f"passive {name} on {url}")
        if setting(self.callbacks, "activescan.active", "true").lower() != "true":
            return
        self._active(messageInfo, url)

    def _active(self, messageInfo, url):
        request = messageInfo.getRequest()
        baseline = messageInfo.getResponse()
        head, _, body = raw_split(request) if request else (b"", b"", b"")
        first_line = head.split(b"\r\n", 1)[0].split(b"\n", 1)[0]
        if not request or (b"?" not in first_line and b"=" not in body):
            return
        for name, (payload, expected) in PROBES.items():
            modified = _inject(request, payload)
            if modified == request:
                continue
            key = (name, url)
            if not bounded_add(self.active_reported, key):
                continue
            try:
                replay = self.callbacks.makeHttpRequest(messageInfo.getHttpService(), modified)
            except Exception as exc:
                report(self.callbacks, self.TAG, f"probe {name} failed for {url}: {exc}")
                continue
            new_body = text(body_of(replay.getResponse() or b""))
            if expected in new_body and expected not in text(body_of(baseline)):
                report(self.callbacks, self.TAG, f"{name} indicator reflected on {url}")
