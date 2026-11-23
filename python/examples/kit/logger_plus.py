"""Logger++ style advanced traffic log and filter (offline implementation)."""

from __future__ import annotations

from collections import deque

try:
    from .common import (body_of, bounded, enabled, int_setting, report, setting, split_message,
                         status_code, url_of)
except ImportError:  # loaded as a standalone bridge script
    from common import (body_of, bounded, enabled, int_setting, report, setting, split_message,
                        status_code, url_of)

from burp import IBurpExtender, IHttpListener, IExtensionStateListener


class BurpExtender(IBurpExtender, IHttpListener, IExtensionStateListener):
    TAG = "Logger++"

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.limit = max(1, int_setting(callbacks, "logger.entries", 500))
        self.entries = deque()
        self.filters = [value for value in setting(callbacks, "logger.filters", "").split(",") if value]
        callbacks.setExtensionName("Blurp Logger++")
        if enabled(callbacks, "logger"):
            callbacks.registerHttpListener(self)
            callbacks.registerExtensionStateListener(self)
        else:
            report(callbacks, self.TAG, "disabled by extension setting")

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            return
        request = messageInfo.getRequest()
        response = messageInfo.getResponse()
        url = url_of(request, messageInfo.getHttpService())
        code = status_code(response)
        start, headers, _ = split_message(response)
        length = len(body_of(response))
        entry = {
            "url": url,
            "status": code,
            "length": length,
            "mime": next((h.split(":", 1)[1].strip() for h in headers
                          if h.lower().startswith("content-type:")), ""),
            "comment": messageInfo.getComment(),
            "tool": self.callbacks.getToolName(toolFlag),
        }
        bounded(self.entries, entry, self.limit)
        if self._matches(entry, response):
            report(self.callbacks, self.TAG,
                   f"{code} {length}B {entry['mime'] or '?'} {url}")

    def _matches(self, entry, response):
        if not self.filters:
            return False
        haystack = f"{entry['url']} {entry['status']} {entry['mime']} {body_of(response)[:512]!r}".lower()
        return any(term.strip().lower() in haystack for term in self.filters)

    def extensionUnloaded(self):
        report(self.callbacks, self.TAG,
               f"captured {len(self.entries)} responses; filters={self.filters or ['none']}")
