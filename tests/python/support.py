"""Shared, dependency-free helpers for the Python bridge tests."""

from __future__ import annotations

import base64
import contextlib
import io
import json
import os
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from unittest import mock

# ``python3 -m unittest discover -s tests/python`` is run from the repository
# root, so the runtime package is not automatically importable.
REPO_ROOT = Path(__file__).resolve().parents[2]
PYTHON_HOME = REPO_ROOT / "python"
if str(PYTHON_HOME) not in sys.path:
    sys.path.insert(0, str(PYTHON_HOME))

from blurp import bridge  # noqa: E402  (path setup must happen first)


def encode(message: bytes) -> str:
    """Mirror the base64 framing used by the Java host."""

    return base64.b64encode(message).decode("ascii")


def frame(message: dict[str, Any]) -> str:
    return json.dumps(message, separators=(",", ":")) + "\n"


def parse_frames(output: str) -> list[dict[str, Any]]:
    lines = [line for line in output.splitlines() if line.strip()]
    return [json.loads(line) for line in lines]


@dataclass
class BridgeResult:
    returncode: int
    frames: list[dict[str, Any]]
    stderr: str
    stdout: str
    log: str
    script: Path


def run_bridge(extension_source: str, inbound: list[dict[str, Any]] | None = None,
               *, extension_args: str = "[]", extra_files: dict[str, str] | None = None,
               filename: str = "extension.py") -> BridgeResult:
    """Run ``blurp.bridge.main`` in-process against scripted host messages.

    stdin/stdout/stderr and argv are replaced for the duration of the call.  No
    Java process and no external packages are involved.
    """

    inbound = inbound or []
    with tempfile.TemporaryDirectory(prefix="blurp-bridge-test-") as directory:
        root = Path(directory)
        script = root / filename
        script.write_text(extension_source.lstrip(), encoding="utf-8")
        for name, content in (extra_files or {}).items():
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content.lstrip(), encoding="utf-8")
        log_path = root / "events.log"

        stdin = io.StringIO("".join(frame(message) for message in inbound))
        stdout = io.StringIO()
        stderr = io.StringIO()
        environment = {
            "BLURP_EXTENSION_ARGS": extension_args,
            "BLURP_TEST_LOG": str(log_path),
        }
        saved_path = sys.path[:]
        saved_modules = set(sys.modules)
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(sys, "argv", ["blurp.bridge", str(script)]))
            stack.enter_context(mock.patch.object(sys, "stdin", stdin))
            stack.enter_context(mock.patch.object(sys, "stdout", stdout))
            stack.enter_context(mock.patch.object(sys, "stderr", stderr))
            stack.enter_context(mock.patch.dict(os.environ, environment))
            try:
                returncode = bridge.main()
            finally:
                sys.path[:] = saved_path
                for name in set(sys.modules) - saved_modules:
                    loaded_from = getattr(sys.modules[name], "__file__", "") or ""
                    if (name.startswith("_blurp_extension_")
                            or str(root) in str(loaded_from)):
                        del sys.modules[name]

        log = log_path.read_text(encoding="utf-8") if log_path.exists() else ""
        return BridgeResult(returncode, parse_frames(stdout.getvalue()),
                            stderr.getvalue(), stdout.getvalue(), log, script)


def log_event() -> str:
    """Small helper embedded in test extensions to append one JSON line."""

    return (
        "import json, os\n"
        "def log(**values):\n"
        "    with open(os.environ['BLURP_TEST_LOG'], 'a', encoding='utf-8') as handle:\n"
        "        handle.write(json.dumps(values, sort_keys=True) + '\\n')\n"
    )
