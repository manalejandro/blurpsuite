"""Regression checks for the Jython-style Python callback surface."""

from __future__ import annotations

import json
import re
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "python"))

import burp  # noqa: E402
from burp.api import BurpExtenderCallbacks  # noqa: E402


class ApiContractTests(unittest.TestCase):
    def test_all_published_callback_names_are_present(self):
        contract = json.loads((REPO_ROOT / "tools" / "api-contract.json").read_text(encoding="utf-8"))
        names = []
        for method in contract["IBurpExtenderCallbacks"]["methods"]:
            name = re.search(r"([A-Za-z_]\w*)\s*\(", method["signature"]).group(1)
            if name not in names:
                names.append(name)

        missing = [name for name in names if not hasattr(BurpExtenderCallbacks, name)]
        self.assertEqual(missing, [])
        self.assertEqual(len(names), 90)

    def test_rehook_action_constants_are_exported(self):
        expected = {
            "ACTION_FOLLOW_RULES_AND_REHOOK": 16,
            "ACTION_DO_INTERCEPT_AND_REHOOK": 17,
            "ACTION_DONT_INTERCEPT_AND_REHOOK": 18,
        }
        for name, value in expected.items():
            self.assertEqual(getattr(burp, name), value)
            self.assertEqual(getattr(burp.api, name), value)

    def test_missing_features_fail_loudly(self):
        method = BurpExtenderCallbacks.addScanIssue
        with self.assertRaises(NotImplementedError):
            method(None)


if __name__ == "__main__":
    unittest.main()
