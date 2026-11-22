"""Test fixture: writes a marker file when the host calls extensionUnloaded()."""

import json
import os

from burp import IBurpExtender, IExtensionStateListener


class BurpExtender(IBurpExtender, IExtensionStateListener):
    def __init__(self):
        self.calls = 0

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        callbacks.setExtensionName("State Listener Test (Python)")
        callbacks.registerExtensionStateListener(self)
        args_marker = os.environ.get("BLURP_TEST_ARGS")
        if args_marker:
            with open(args_marker, "w", encoding="utf-8") as handle:
                json.dump(callbacks.getCommandLineArguments(), handle)

    def extensionUnloaded(self):
        marker = os.environ.get("BLURP_TEST_MARKER")
        if marker:
            self.calls += 1
            with open(marker + ".python", "w", encoding="utf-8") as handle:
                handle.write(f"{self.calls}\n")
