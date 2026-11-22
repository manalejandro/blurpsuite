#!/usr/bin/env python3
"""JSON-RPC bridge that runs a Python extension inside Blurp Suite.

The Java host speaks line-delimited JSON on stdin/stdout.  All extension
output is redirected to stderr so it cannot corrupt the protocol stream.
"""

from __future__ import annotations

import base64
import importlib.util
import json
import os
import sys
import traceback
from pathlib import Path
from typing import Any

from .api import BurpExtenderCallbacks, HttpRequestResponse, InterceptedProxyMessage, HttpService, decode


class Transport:
    """Sends requests/notifications to the Java side."""

    def __init__(self) -> None:
        self._next_id = 1
        self._pending: dict[int, dict] = {}
        self._listeners: dict[str, Any] = {}
        self.closed = False

    def call(self, method: str, params: dict | None = None) -> dict:
        request_id = self._next_id
        self._next_id += 1
        message = {"jsonrpc": "2.0", "id": request_id, "method": method,
                   "params": params or {}}
        self._send(message)
        while request_id not in self._pending:
            self._read_one()
        result = self._pending.pop(request_id)
        if "error" in result:
            error = result["error"]
            # The Java host sends the error as a string; JSON-RPC also allows
            # an object with a "message" member.
            message = error.get("message", "RPC error") if isinstance(error, dict) else error
            raise RuntimeError(str(message))
        return result.get("result", {})

    def notify(self, method: str, params: dict) -> None:
        self._send({"jsonrpc": "2.0", "method": method, "params": params})

    def respond(self, request_id: Any, result: dict) -> None:
        self._send({"jsonrpc": "2.0", "id": request_id, "result": result})

    def error(self, request_id: Any, code: int, message: str) -> None:
        self._send({"jsonrpc": "2.0", "id": request_id,
                    "error": {"code": code, "message": message}})

    def register(self, name: str, handler) -> None:
        self._listeners[name] = handler

    def _send(self, message: dict) -> None:
        sys.stdout.write(json.dumps(message, separators=(",", ":")) + "\n")
        sys.stdout.flush()

    def _read_one(self) -> None:
        line = sys.stdin.readline()
        if not line:
            raise EOFError("Blurp Suite host closed the connection")
        message = json.loads(line)
        self._dispatch(message)

    def _dispatch(self, message: dict) -> None:
        # Replies to calls made by the extension have an id but no method.
        # Demultiplex them here so call() can wake up while a peer request is
        # being handled on the same stream.
        if "result" in message or "error" in message:
            if "id" in message:
                self._pending[message["id"]] = message
            return
        method = message.get("method", "")
        if "id" in message:
            handler = self._listeners.get(method)
            if handler is None:
                self.error(message["id"], -32601, "Unknown method: " + method)
                return
            try:
                self.respond(message["id"], handler(message.get("params") or {}))
            except Exception as exc:
                self.error(message["id"], -32000, str(exc))
        else:
            handler = self._listeners.get(method)
            if handler:
                handler(message.get("params") or {})

    def serve(self) -> None:
        while not self.closed:
            self._read_one()


def load_extension(path: Path):
    """Load a Python file as a module and return a fresh extension instance."""
    name = "_blurp_extension_" + str(abs(hash(str(path))))
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError("Cannot import extension: " + str(path))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    for attribute in ("BurpExtender", "Extension"):
        candidate = getattr(module, attribute, None)
        if isinstance(candidate, type):
            return candidate()
    raise TypeError("Extension must define a BurpExtender class")


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: python -m blurp.bridge <extension.py>", file=sys.stderr)
        return 2

    script = Path(sys.argv[1]).resolve()
    parent = str(script.parent)
    if parent not in sys.path:
        sys.path.insert(0, parent)

    transport = Transport()
    try:
        extension_args = json.loads(os.environ.get("BLURP_EXTENSION_ARGS", "[]"))
    except (TypeError, ValueError):
        extension_args = []
    callbacks = BurpExtenderCallbacks(transport, script.name, extension_args)
    extension = None
    state_notified = False

    def call_listener(listener, method_name, *args):
        try:
            getattr(listener, method_name)(*args)
        except Exception as exc:
            print(method_name + " listener failed: " + str(exc), file=sys.stderr)
            traceback.print_exc(file=sys.stderr)

    def notify_state_listeners():
        nonlocal state_notified
        if state_notified:
            return
        state_notified = True
        for listener in callbacks.state_listeners:
            call_listener(listener, "extensionUnloaded")

    def get_info(_params):
        return {
            "name": getattr(callbacks, "extensionName", "Python extension"),
            "proxyListeners": len(callbacks.proxy_listeners),
            "httpListeners": len(callbacks.http_listeners),
            "scopeListeners": len(callbacks.scope_listeners),
            "stateListeners": len(callbacks.state_listeners),
        }

    def proxy_message(params):
        is_request = bool(params.get("isRequest", True))
        raw = decode(params.get("message"))
        original_service = HttpService.from_dict(params.get("service"))
        info = HttpRequestResponse(raw if is_request else b"",
                                   b"" if is_request else raw, original_service,
                                   comment=params.get("comment", ""),
                                   highlight=params.get("highlight", ""),
                                   reference=int(params.get("reference", 0) or 0))
        intercepted = InterceptedProxyMessage(info, int(params.get("reference", 0) or 0),
                                              params.get("listener", ""),
                                              params.get("clientAddress", ""))
        for listener in callbacks.proxy_listeners:
            call_listener(listener, "processProxyMessage", is_request, intercepted)
        action = intercepted.getInterceptAction()
        result = {"action": action, "drop": action == 3}
        message = info.getRequest() if is_request else info.getResponse()
        if message != raw:
            result["message"] = base64.b64encode(message).decode("ascii")
        if info.getComment() != params.get("comment", ""):
            result["comment"] = info.getComment()
        if info.getHighlight() != params.get("highlight", ""):
            result["highlight"] = info.getHighlight()
        if info.getHttpService().to_dict() != original_service.to_dict():
            result["service"] = info.getHttpService().to_dict()
        return result

    def http_message(params):
        is_request = bool(params.get("isRequest", True))
        raw = decode(params.get("message"))
        original_service = HttpService.from_dict(params.get("service"))
        info = HttpRequestResponse(raw if is_request else b"",
                                   b"" if is_request else raw, original_service,
                                   comment=params.get("comment", ""),
                                   highlight=params.get("highlight", ""))
        for listener in callbacks.http_listeners:
            call_listener(listener, "processHttpMessage",
                          int(params.get("tool", 4)), is_request, info)
        result = {}
        message = info.getRequest() if is_request else info.getResponse()
        if message != raw:
            result["message"] = base64.b64encode(message).decode("ascii")
        if info.getComment() != params.get("comment", ""):
            result["comment"] = info.getComment()
        if info.getHighlight() != params.get("highlight", ""):
            result["highlight"] = info.getHighlight()
        if info.getHttpService().to_dict() != original_service.to_dict():
            result["service"] = info.getHttpService().to_dict()
        return result

    def unloaded(_params):
        notify_state_listeners()
        return {}

    def scope_changed(_params):
        for listener in callbacks.scope_listeners:
            call_listener(listener, "scopeChanged")
        return {}

    transport.register("get_extension_info", get_info)
    transport.register("on_proxy_message", proxy_message)
    transport.register("on_http_message", http_message)
    transport.register("on_unloaded", unloaded)
    transport.register("on_scope_changed", scope_changed)

    try:
        sys.stderr.write("[blurp] starting Python extension " + script.name + "\n")
        sys.stderr.flush()
        extension = load_extension(script)
        if hasattr(extension, "registerExtenderCallbacks"):
            extension.registerExtenderCallbacks(callbacks)
        sys.stderr.write("[blurp] extension registered as " + callbacks.extensionName + "\n")
        sys.stderr.flush()
        transport.serve()
        return 0
    except EOFError:
        return 0
    except Exception:
        traceback.print_exc(file=sys.stderr)
        return 1
    finally:
        if extension is not None:
            notify_state_listeners()


if __name__ == "__main__":
    raise SystemExit(main())
