"""Retire.js style offline detection of outdated JavaScript libraries.

The signature table is intentionally small and embedded: it demonstrates the
workflow without downloading a vulnerability feed or contacting third parties.
Add entries to ``LIBRARIES`` to extend coverage.
"""

from __future__ import annotations

import re
from collections import OrderedDict

try:
    from .common import body_of, bounded_add, enabled, report, setting
except ImportError:
    from common import body_of, bounded_add, enabled, report, setting

from burp import IBurpExtender, IHttpListener

# A version anywhere in the banner, including prerelease suffixes.
VERSION = r"(\d+(?:\.\d+)*(?:-[0-9A-Za-z.-]+)?)"

# name -> (version pattern, first safe version, source hint)
LIBRARIES = {
    "jquery": (re.compile(r"jQuery[^0-9\r\n]{0,40}v?" + VERSION, re.IGNORECASE),
               "3.5.0", "jquery.js"),
    "angular": (re.compile(r"AngularJS[^0-9\r\n]{0,40}v?" + VERSION, re.IGNORECASE),
                "1.8.0", "angular.js"),
    "bootstrap": (re.compile(r"Bootstrap[^0-9\r\n]{0,40}v?" + VERSION, re.IGNORECASE),
                  "4.3.1", "bootstrap.js"),
    "lodash": (re.compile(r"lodash[^0-9\r\n]{0,40}v?" + VERSION, re.IGNORECASE),
               "4.17.21", "lodash.js"),
    "react": (re.compile(r"React[^0-9\r\n]{0,40}v?" + VERSION, re.IGNORECASE),
              "16.14.0", "react.js"),
}


def _version_tuple(value: str) -> tuple[tuple[int, ...], bool]:
    """Return the numeric core and whether this is a final release."""
    match = re.match(r"(\d+(?:\.\d+)*)", value)
    if not match:
        return (0,), False
    core = tuple(int(piece) for piece in match.group(1).split("."))
    suffix = value[match.end():].lstrip("-._ ")
    return core, not suffix


def _outdated(version: str, safe: str) -> bool:
    found_core, found_release = _version_tuple(version)
    wanted_core, wanted_release = _version_tuple(safe)
    width = max(len(found_core), len(wanted_core))
    found_core += (0,) * (width - len(found_core))
    wanted_core += (0,) * (width - len(wanted_core))
    # A prerelease sorts before the corresponding final release.
    return (found_core, found_release) < (wanted_core, wanted_release)


class BurpExtender(IBurpExtender, IHttpListener):
    TAG = "RetireJS"

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.reported = OrderedDict()
        callbacks.setExtensionName("Blurp Retire.js (offline)")
        if enabled(callbacks, "retirejs"):
            callbacks.registerHttpListener(self)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            return
        response = messageInfo.getResponse()
        if not response:
            return
        body = body_of(response)
        if b"<script" not in body.lower() and b"function" not in body.lower():
            return
        preview = body[:200000].decode("utf-8", "replace")
        for name, (pattern, safe, hint) in LIBRARIES.items():
            for match in pattern.finditer(preview):
                version = match.group(1)
                if _outdated(version, safe):
                    key = (name, version)
                    if bounded_add(self.reported, key):
                        report(self.callbacks, self.TAG,
                               f"outdated {name} {version} (safe >= {safe}; {hint})")
