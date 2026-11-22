"""Minimal origin server used by the end-to-end proxy test.

It echoes the request line and the two marker headers added by the bundled
Java and Python example extensions so the test can assert that both extension
hosts really modified the traffic.
"""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import sys


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler API
        body = (
            f"{self.command} {self.path} {self.request_version}\n"
            f"X-Blurp-Java: {self.headers.get('X-Blurp-Java', '')}\n"
            f"X-Blurp-Python: {self.headers.get('X-Blurp-Python', '')}\n"
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass


def main():
    port = int(sys.argv[1])
    print(f"origin listening on 127.0.0.1:{port}", flush=True)
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()


if __name__ == "__main__":
    main()
