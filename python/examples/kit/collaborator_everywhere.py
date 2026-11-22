"""Collaborator Everywhere style OAST injection (offline implementation).

Injects locally generated Collaborator-style payloads into headers that are
commonly trusted by applications (``X-Forwarded-Host``, ``Referer``, etc.).
The bundled Collaborator is offline: payloads are generated locally and any
interaction must be observed in the Proxy history or an external listener
configured by the tester.
"""

from __future__ import annotations

from collections import OrderedDict

try:
    from .common import bounded_put, enabled, raw_split, report, setting, url_of
except ImportError:
    from common import bounded_put, enabled, raw_split, report, setting, url_of

from burp import IBurpExtender, IProxyListener

DEFAULT_HEADERS = ("X-Forwarded-Host", "Referer", "X-Original-URL", "X-Rewrite-URL")


class BurpExtender(IBurpExtender, IProxyListener):
    TAG = "CollaboratorEverywhere"

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.context = callbacks.createBurpCollaboratorClientContext()
        self.headers = [item.strip() for item in
                        setting(callbacks, "collab.headers", ",".join(DEFAULT_HEADERS)).split(",")
                        if item.strip()]
        self.payloads = OrderedDict()
        callbacks.setExtensionName("Blurp Collaborator Everywhere")
        if enabled(callbacks, "collab", default=False):
            callbacks.registerProxyListener(self)
        else:
            report(callbacks, self.TAG, "disabled; set blurp.kit.collab.enabled=true to enable")

    def processProxyMessage(self, messageIsRequest, message):
        if not messageIsRequest:
            return
        info = message.getMessageInfo()
        request = info.getRequest()
        if not request:
            return
        url = url_of(request, info.getHttpService())
        key = url.split("?", 1)[0]
        payload = self.payloads.get(key)
        if payload is None:
            payload = self.context.generatePayload(True)
            bounded_put(self.payloads, key, payload)
            report(self.callbacks, self.TAG, f"payload for {key}: {payload}")
        updated = self._inject(request, payload)
        if updated != request:
            info.setRequest(updated)

    def _inject(self, request: bytes, payload: str) -> bytes:
        head, marker, body = raw_split(request)
        if not marker:
            return request
        line_separator = b"\r\n" if marker == b"\r\n\r\n" else b"\n"
        lines = head.split(line_separator)
        existing = {line.split(b":", 1)[0].decode("latin-1", "replace").strip().lower()
                    for line in lines[1:]}
        for name in self.headers:
            if name.lower() not in existing:
                lines.append(f"{name}: {payload}".encode("latin-1", "replace"))
        return line_separator.join(lines) + marker + body
