"""Turbo Intruder style high-performance request engine (offline implementation).

Triggered per request with the header ``X-Blurp-Turbo: 1``. The request body or
query must contain ``%s``; each worker replaces it with a payload and sends the
request directly to the target socket. ``mode=race`` releases all workers from
a barrier at once to exercise race conditions.
"""

from __future__ import annotations

import socket
import ssl
import threading

try:
    from .common import enabled, header_value, int_setting, report, setting, split_message, url_of
except ImportError:
    from common import enabled, header_value, int_setting, report, setting, split_message, url_of

from burp import IBurpExtender, IHttpListener


class BurpExtender(IBurpExtender, IHttpListener):
    TAG = "TurboIntruder"

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.payloads = [value for value in
                         setting(callbacks, "turbo.payloads", "1,2,3").split(",") if value]
        self.workers = max(1, min(64, int_setting(callbacks, "turbo.workers", 8)))
        self.mode = setting(callbacks, "turbo.mode", "standard").lower()
        callbacks.setExtensionName("Blurp Turbo Intruder")
        if enabled(callbacks, "turbo"):
            callbacks.registerHttpListener(self)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not messageIsRequest:
            return
        request = messageInfo.getRequest()
        if not request or b"%s" not in request:
            return
        _, headers, _ = split_message(request)
        if header_value(headers, "X-Blurp-Turbo").strip() != "1":
            return
        service = messageInfo.getHttpService()
        url = url_of(request, service)
        barrier = threading.Barrier(self.workers) if self.mode == "race" else None
        results = []
        lock = threading.Lock()

        def worker(payload):
            message = request.replace(b"%s", payload.encode("latin-1"), 1)
            if barrier is not None:
                try:
                    barrier.wait(timeout=10)
                except threading.BrokenBarrierError:
                    pass
            try:
                answer = self._send(service, message)
                status = answer.split(b"\r\n", 1)[0].decode("latin-1", "replace")
            except Exception as exc:
                status = "ERROR " + str(exc)
            with lock:
                results.append((payload, status))

        threads = []
        for index in range(self.workers):
            payload = self.payloads[index % len(self.payloads)] if self.payloads else ""
            thread = threading.Thread(target=worker, args=(payload,), daemon=True)
            thread.start()
            threads.append(thread)
        for thread in threads:
            thread.join(timeout=15)

        for payload, status in sorted(results):
            report(self.callbacks, self.TAG, f"{url} payload={payload!r} -> {status}")

    @staticmethod
    def _send(service, request: bytes) -> bytes:
        host = service.getHost()
        protocol = (service.getProtocol() or "http").lower()
        with socket.create_connection((host, service.getPort()), timeout=10) as raw:
            if protocol == "https":
                context = ssl.create_default_context()
                with context.wrap_socket(raw, server_hostname=host) as sock:
                    sock.sendall(request)
                    return BurpExtender._read_response(sock)
            raw.sendall(request)
            return BurpExtender._read_response(raw)

    @staticmethod
    def _read_response(sock) -> bytes:
        chunks = []
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
            data = b"".join(chunks)
            head, separator, body = data.partition(b"\r\n\r\n")
            if not separator:
                head, separator, body = data.partition(b"\n\n")
            if not separator:
                continue
            lines = head.splitlines()
            length = None
            for line in lines:
                name, _, value = line.partition(b":")
                if name.strip().lower() == b"content-length":
                    try:
                        length = int(value.strip())
                    except ValueError:
                        pass
                    break
            if length is not None and len(body) >= length:
                return head + separator + body[:length]
            if length is None:
                return data
        return b"".join(chunks)
