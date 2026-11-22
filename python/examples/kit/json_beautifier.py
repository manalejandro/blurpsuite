"""JSON Beautifier style response formatter (offline implementation)."""

from __future__ import annotations

import json

try:
    from .common import body_of, enabled, replace_body, report, set_content_length, split_message
except ImportError:
    from common import body_of, enabled, replace_body, report, set_content_length, split_message

from burp import IBurpExtender, IHttpListener


class BurpExtender(IBurpExtender, IHttpListener):
    TAG = "JSONBeautifier"

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        callbacks.setExtensionName("Blurp JSON Beautifier")
        if enabled(callbacks, "jsonbeautifier"):
            callbacks.registerHttpListener(self)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            return
        response = messageInfo.getResponse()
        if not response:
            return
        start, headers, _ = split_message(response)
        if not any(header.lower().startswith("content-type:") and "json" in header.lower()
                   for header in headers):
            return
        body = body_of(response)
        if not body.strip().startswith((b"{", b"[")):
            return
        try:
            pretty = json.dumps(json.loads(body.decode("utf-8", "replace")),
                                indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8")
        except Exception:
            return
        updated = set_content_length(replace_body(response, pretty), len(pretty))
        if updated != response:
            messageInfo.setResponse(updated)
            report(self.callbacks, self.TAG, f"formatted {len(body)}B JSON body")

    @staticmethod
    def _set_length(response: bytes, length: int) -> bytes:
        return set_content_length(response, length)
