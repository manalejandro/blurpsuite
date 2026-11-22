"""Param Miner style hidden-parameter discovery (offline implementation).

Adds candidate parameter names to a copied request and compares the response
with the baseline. A different status code, body length, or body prefix is
reported as a candidate hidden parameter.
"""

from __future__ import annotations

from collections import OrderedDict

try:
    from .common import (body_of, bounded_put, enabled, int_setting, raw_split, report, setting,
                         status_code, text, url_of)
except ImportError:
    from common import (body_of, bounded_put, enabled, int_setting, raw_split, report, setting,
                        status_code, text, url_of)

from burp import IBurpExtender, IHttpListener

DEFAULT_WORDS = (
    "debug", "test", "admin", "source", "dev", "preview", "internal", "auth",
    "token", "role", "user", "id", "format", "callback", "redirect", "ajax",
)


def _signature(response: bytes):
    body = body_of(response)
    return status_code(response), len(body), text(body[:100])


def _add_param(request: bytes, name: str) -> bytes:
    head, separator, body = raw_split(request)
    if not separator:
        return request
    line_separator = b"\r\n" if separator == b"\r\n\r\n" else b"\n"
    lines = head.split(line_separator)
    parts = lines[0].decode("latin-1", "replace").split(" ", 2)
    if len(parts) != 3:
        return request
    method, target, version = parts
    if "?" in target:
        path, _, query = target.partition("?")
        target = f"{path}?{query}&{name}=1"
    else:
        target += f"?{name}=1"
    lines[0] = f"{method} {target} {version}".encode("latin-1", "replace")
    return line_separator.join(lines) + separator + body


class BurpExtender(IBurpExtender, IHttpListener):
    TAG = "ParamMiner"

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.words = [word.strip() for word in
                      setting(callbacks, "paramminer.words", ",".join(DEFAULT_WORDS)).split(",")
                      if word.strip()]
        self.limit = max(1, int_setting(callbacks, "paramminer.limit", 12))
        self.tested = OrderedDict()
        callbacks.setExtensionName("Blurp Param Miner")
        if enabled(callbacks, "paramminer", default=False):
            callbacks.registerHttpListener(self)
        else:
            report(callbacks, self.TAG, "disabled; set blurp.kit.paramminer.enabled=true to enable")

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest or not messageInfo.getResponse():
            return
        request = messageInfo.getRequest()
        url = url_of(request, messageInfo.getHttpService()).split("?", 1)[0]
        if self.tested.get(url, 0) >= self.limit:
            return
        baseline = _signature(messageInfo.getResponse())
        for name in self.words:
            if self.tested.get(url, 0) >= self.limit:
                break
            bounded_put(self.tested, url, self.tested.get(url, 0) + 1)
            modified = _add_param(request, name)
            try:
                replay = self.callbacks.makeHttpRequest(messageInfo.getHttpService(), modified)
            except Exception as exc:
                report(self.callbacks, self.TAG, f"probe {name} failed on {url}: {exc}")
                continue
            replay_response = replay.getResponse() or b""
            if not replay_response:
                report(self.callbacks, self.TAG,
                       f"probe {name} produced no response on {url}")
                continue
            candidate = _signature(replay_response)
            if candidate != baseline:
                report(self.callbacks, self.TAG,
                       f"hidden parameter candidate '{name}' on {url}: "
                       f"{candidate[0]}/{candidate[1]}B vs {baseline[0]}/{baseline[1]}B")
