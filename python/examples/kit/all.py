"""Loads every bundled offline extension with a single ``--extension`` flag.

Usage::

  java -cp build/classes com.blurpsuite.Main \
      --extension python/examples/kit/all.py
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from active_scan_plus import BurpExtender as ActiveScanPlus  # noqa: E402
from autorize import BurpExtender as Autorize  # noqa: E402
from backslash_scanner import BurpExtender as BackslashScanner  # noqa: E402
from collaborator_everywhere import BurpExtender as CollaboratorEverywhere  # noqa: E402
from csrf_scanner import BurpExtender as CsrfScanner  # noqa: E402
from json_beautifier import BurpExtender as JsonBeautifier  # noqa: E402
from logger_plus import BurpExtender as LoggerPlus  # noqa: E402
from param_miner import BurpExtender as ParamMiner  # noqa: E402
from retire_js import BurpExtender as RetireJs  # noqa: E402
from turbo_intruder import BurpExtender as TurboIntruder  # noqa: E402

from burp import IBurpExtender  # noqa: E402

MODULES = (
    ("Autorize", Autorize),
    ("ActiveScan++", ActiveScanPlus),
    ("Logger++", LoggerPlus),
    ("ParamMiner", ParamMiner),
    ("TurboIntruder", TurboIntruder),
    ("CollaboratorEverywhere", CollaboratorEverywhere),
    ("JSONBeautifier", JsonBeautifier),
    ("RetireJS", RetireJs),
    ("BackslashScanner", BackslashScanner),
    ("CSRFScanner", CsrfScanner),
)


class BurpExtender(IBurpExtender):
    def registerExtenderCallbacks(self, callbacks):
        self.modules = []
        for name, factory in MODULES:
            instance = factory()
            instance.registerExtenderCallbacks(callbacks)
            self.modules.append((name, instance))
        callbacks.setExtensionName("Blurp Extension Kit (10 modules)")
        callbacks.printOutput(
            "[kit] loaded: " + ", ".join(name for name, _ in self.modules))
