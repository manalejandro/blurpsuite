"""Test fixture: records Python HTTP and scope listener callbacks."""

import os

from burp import IBurpExtender, IHttpListener, IScopeChangeListener


class BurpExtender(IBurpExtender, IHttpListener, IScopeChangeListener):
    def registerExtenderCallbacks(self, callbacks):
        callbacks.setExtensionName("Python Listener Test (Python)")
        callbacks.registerHttpListener(self)
        callbacks.registerScopeChangeListener(self)
        callbacks.excludeFromScope("http://excluded.test/")

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        self._mark("http")

    def scopeChanged(self):
        self._mark("scope")

    @staticmethod
    def _mark(name):
        marker = os.environ.get("BLURP_LISTENER_MARKER")
        if marker:
            with open(f"{marker}.{name}", "a", encoding="utf-8") as handle:
                handle.write("1\n")
