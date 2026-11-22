"""Tests for the Python side of the line-delimited JSON-RPC connection."""

from __future__ import annotations

import io
import sys
import unittest
from typing import Any, Callable
from unittest import mock

from support import frame, parse_frames  # adds the runtime package to sys.path

from blurp.bridge import Transport


def with_streams(inbound: list[dict[str, Any]], action: Callable[[Transport], Any]):
    stdout = io.StringIO()
    stdin = io.StringIO("".join(frame(message) for message in inbound))
    with mock.patch.object(sys, "stdin", stdin), mock.patch.object(sys, "stdout", stdout):
        result = action(Transport())
    return result, parse_frames(stdout.getvalue()), stdout.getvalue()


class TransportFramingTests(unittest.TestCase):
    def test_call_sends_compact_request_and_matches_response_ids(self):
        # The reply to the second call arrives first; demultiplexing is by id.
        inbound = [
            {"id": 2, "result": {"second": True}},
            {"id": 1, "result": {"first": True}},
        ]

        def action(transport: Transport):
            first = transport.call("first", {"url": "http://example.test/"})
            second = transport.call("second")
            return first, second

        (first, second), sent, raw = with_streams(inbound, action)
        self.assertEqual(first, {"first": True})
        self.assertEqual(second, {"second": True})
        self.assertEqual(sent, [
            {"jsonrpc": "2.0", "id": 1, "method": "first",
             "params": {"url": "http://example.test/"}},
            {"jsonrpc": "2.0", "id": 2, "method": "second", "params": {}},
        ])
        self.assertEqual(raw.count("\n"), 2)
        self.assertNotIn('"id": 1', raw)  # compact frames, as JrpcConnection writes them

    def test_call_accepts_peer_requests_while_waiting_for_its_reply(self):
        seen: list[dict[str, Any]] = []

        def proxy_handler(params: dict[str, Any]) -> dict[str, Any]:
            seen.append(params)
            return {"action": 0, "drop": False}

        inbound = [
            {"jsonrpc": "2.0", "id": 41, "method": "on_proxy_message",
             "params": {"reference": 7}},
            {"id": 1, "result": {"value": True}},
        ]

        def action(transport: Transport):
            transport.register("on_proxy_message", proxy_handler)
            return transport.call("is_in_scope", {"url": "http://example.test/"})

        result, sent, _ = with_streams(inbound, action)
        self.assertEqual(result, {"value": True})
        self.assertEqual(seen, [{"reference": 7}])
        self.assertEqual(sent, [
            {"jsonrpc": "2.0", "id": 1, "method": "is_in_scope",
             "params": {"url": "http://example.test/"}},
            {"jsonrpc": "2.0", "id": 41, "result": {"action": 0, "drop": False}},
        ])

    def test_error_replies_raise_with_string_or_object_errors(self):
        for error, expected in [
            ("Python extension timed out on 'is_in_scope'", "Python extension timed out on 'is_in_scope'"),
            ({"code": -32603, "message": "host failed"}, "host failed"),
            ({"code": -32603}, "RPC error"),
        ]:
            with self.subTest(error=error):
                def action(transport: Transport):
                    return transport.call("is_in_scope", {})

                with self.assertRaises(RuntimeError) as caught:
                    with_streams([{"id": 1, "error": error}], action)
                self.assertEqual(str(caught.exception), expected)

    def test_notify_respond_and_error_use_expected_shapes(self):
        _, sent, _ = with_streams([], lambda transport: (
            transport.notify("print_output", {"message": "hello"}),
            transport.respond(3, {"action": 3, "drop": True}),
            transport.error(4, -32000, "broken listener"),
        ))
        self.assertEqual(sent, [
            {"jsonrpc": "2.0", "method": "print_output", "params": {"message": "hello"}},
            {"jsonrpc": "2.0", "id": 3, "result": {"action": 3, "drop": True}},
            {"jsonrpc": "2.0", "id": 4,
             "error": {"code": -32000, "message": "broken listener"}},
        ])

    def test_serve_dispatches_requests_notifications_and_method_not_found(self):
        seen: list[dict[str, Any]] = []

        def ping(params: dict[str, Any]) -> dict[str, Any]:
            seen.append(params)
            return {"pong": params.get("x", 0)}

        def explode(_params: dict[str, Any]) -> dict[str, Any]:
            raise ValueError("bad handler")

        inbound = [
            {"id": 11, "method": "ping", "params": {"x": 1}},
            {"id": 12, "method": "ping"},
            {"id": 13, "method": "explode"},
            {"id": 14, "method": "missing"},
            {"method": "notification", "params": {"note": 5}},
        ]

        def action(transport: Transport):
            transport.register("ping", ping)
            transport.register("explode", explode)
            try:
                transport.serve()
            except EOFError:
                pass  # the scripted stream ends here; main() does the same

        _, sent, _ = with_streams(inbound, action)
        self.assertEqual(seen, [{"x": 1}, {}])
        self.assertEqual(sent, [
            {"jsonrpc": "2.0", "id": 11, "result": {"pong": 1}},
            {"jsonrpc": "2.0", "id": 12, "result": {"pong": 0}},
            {"jsonrpc": "2.0", "id": 13, "error": {"code": -32000, "message": "bad handler"}},
            {"jsonrpc": "2.0", "id": 14,
             "error": {"code": -32601, "message": "Unknown method: missing"}},
        ])

    def test_eof_raises_when_host_closes_the_stream(self):
        with self.assertRaises(EOFError):
            with_streams([], lambda transport: transport.serve())


if __name__ == "__main__":
    unittest.main()
