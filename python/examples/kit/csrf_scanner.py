"""CSRF Scanner style passive anti-CSRF token detection (offline implementation)."""

from __future__ import annotations

import re
from collections import OrderedDict

try:
    from .common import bounded_add, enabled, report, split_message, url_of
except ImportError:
    from common import bounded_add, enabled, report, split_message, url_of

from burp import IBurpExtender, IHttpListener

STATE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
TOKEN_NAMES = re.compile(
    r"(csrf|xsrf|antiforgery|__requestverificationtoken|_token|csrfmiddlewaretoken|nonce|state)",
    re.IGNORECASE)
TOKEN_HEADERS = re.compile(r"^(x-csrf-token|x-xsrf-token|anti-csrf|csrf-token)$", re.IGNORECASE)


class BurpExtender(IBurpExtender, IHttpListener):
    TAG = "CSRFScanner"

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.findings = OrderedDict()
        callbacks.setExtensionName("Blurp CSRF Scanner")
        if enabled(callbacks, "csrfscanner"):
            callbacks.registerHttpListener(self)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not messageIsRequest:
            return
        request = messageInfo.getRequest()
        if not request:
            return
        start, headers, _ = split_message(request)
        method = start.split(" ", 1)[0].upper()
        if method not in STATE_METHODS:
            return
        url = url_of(request, messageInfo.getHttpService())
        try:
            parameters = self.callbacks.getHelpers().analyzeRequest(request).getParameters()
        except Exception:
            parameters = []
        has_param = any(
            TOKEN_NAMES.search(str(
                parameter.getName() if hasattr(parameter, "getName") else parameter[0]))
            for parameter in parameters
        )
        has_header = any(
            TOKEN_HEADERS.match(line.split(":", 1)[0].strip()) for line in headers)
        key = (method, url.split("?", 1)[0])
        if not has_param and not has_header and bounded_add(self.findings, key):
            report(self.callbacks, self.TAG,
                   f"no anti-CSRF token in {method} {url.split('?', 1)[0]}")
