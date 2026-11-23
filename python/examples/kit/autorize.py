"""Autorize style access-control testing (offline implementation).

Two modes are supported:

* passive comparison of requests to the same endpoint carrying different
  session markers;
* active replay with a configured low-privilege header or cookie, using
  ``IBurpExtenderCallbacks.makeHttpRequest``.

Configure with extension settings, for example::

  blurp.kit.autorize.lowpriv.cookie=Session=lowprivvalue
  blurp.kit.autorize.lowpriv.header=Authorization: Bearer lowpriv
"""

from __future__ import annotations

from collections import OrderedDict

try:
    from .common import (body_of, bounded_add, bounded_put, enabled, raw_split, report,
                         setting, status_code, url_of)
except ImportError:
    from common import (body_of, bounded_add, bounded_put, enabled, raw_split, report,
                        setting, status_code, url_of)

from burp import IBurpExtender, IHttpListener

LOGIN_MARKERS = ("login", "signin", "unauthorized", "forbidden", "access denied", "log in")


def _session_markers(request: bytes) -> str:
    head, _, _ = raw_split(request)
    values = []
    for line in head.splitlines():
        name = line.split(b":", 1)[0].strip().lower()
        if name in {b"cookie", b"authorization", b"x-session", b"x-auth-token"}:
            values.append(line.strip().decode("latin-1", "replace").lower())
    return "|".join(values)


def _signature(response: bytes) -> tuple[int, int, str]:
    body = body_of(response).lower()
    return status_code(response), len(body), body[:120].decode("latin-1", "replace")


class BurpExtender(IBurpExtender, IHttpListener):
    TAG = "Autorize"

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.baseline = OrderedDict()
        self.reported = OrderedDict()
        self.replayed = OrderedDict()
        self.low_cookie = setting(callbacks, "autorize.lowpriv.cookie", "")
        self.low_header = setting(callbacks, "autorize.lowpriv.header", "")
        callbacks.setExtensionName("Blurp Autorize")
        if enabled(callbacks, "autorize", default=False):
            callbacks.registerHttpListener(self)
        else:
            report(callbacks, self.TAG, "disabled; set blurp.kit.autorize.enabled=true to enable")

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest or not messageInfo.getResponse():
            return
        request = messageInfo.getRequest()
        response = messageInfo.getResponse()
        url = url_of(request, messageInfo.getHttpService())
        key = url.split("?", 1)[0]
        marker = _session_markers(request)
        if not marker:
            return
        previous = self.baseline.get(key)
        if previous is None:
            bounded_put(self.baseline, key, (marker, _signature(response)))
            return
        if previous[0] == marker:
            return
        current = _signature(response)
        if (self._looks_allowed(current) and current[:2] == previous[1][:2]
                and bounded_add(self.reported, key)):
            report(self.callbacks, self.TAG,
                   f"same access with different session on {key}: "
                   f"{previous[1][0]}/{previous[1][1]}B vs {current[0]}/{current[1]}B")
        if bounded_add(self.replayed, key):
            self._active_replay(messageInfo, url)

    @staticmethod
    def _looks_allowed(signature) -> bool:
        code, _, preview = signature
        return 200 <= code < 400 and not any(word in preview for word in LOGIN_MARKERS)

    def _active_replay(self, messageInfo, url):
        if not (self.low_cookie or self.low_header):
            return
        request = messageInfo.getRequest()
        modified = self._replace_markers(request)
        if modified == request:
            return
        try:
            replay = self.callbacks.makeHttpRequest(messageInfo.getHttpService(), modified)
        except Exception as exc:
            report(self.callbacks, self.TAG, f"replay failed for {url}: {exc}")
            return
        signature = _signature(replay.getResponse() or b"")
        if self._looks_allowed(signature):
            report(self.callbacks, self.TAG,
                   f"low-privilege replay still allowed {url}: {signature[0]}/{signature[1]}B")

    def _replace_markers(self, request: bytes) -> bytes:
        head, marker, body = raw_split(request)
        if not marker:
            return request
        line_separator = b"\r\n" if marker == b"\r\n\r\n" else b"\n"
        lines = head.split(line_separator)
        kept = [lines[0]]
        for line in lines[1:]:
            name = line.split(b":", 1)[0].strip().lower()
            if name not in {b"cookie", b"authorization", b"x-session", b"x-auth-token"}:
                kept.append(line)
        if self.low_cookie:
            kept.append(b"Cookie: " + self.low_cookie.encode("latin-1", "replace"))
        if self.low_header:
            kept.append(self.low_header.encode("latin-1", "replace"))
        return line_separator.join(kept) + marker + body
