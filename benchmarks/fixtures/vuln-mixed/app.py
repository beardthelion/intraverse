"""Fixture app: POST /import deserializes the request body with pickle;
GET /go redirects to a user-supplied target; GET /go-safe only redirects to
same-host relative paths."""

import os
import pickle
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs


def is_safe_redirect(target: str) -> bool:
    # only allow relative paths on this host
    return target.startswith("/") and not target.startswith("//")


class Handler(BaseHTTPRequestHandler):
    def _send(self, body: str, code: int = 200):
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(body.encode())

    def redirect(self, target: str):
        self.send_response(302)
        self.send_header("Location", target)
        self.end_headers()

    def do_GET(self):
        path = urlparse(self.path).path
        qs = parse_qs(urlparse(self.path).query)
        if path == "/go":
            target = qs.get("to", ["/"])[0]
            self.redirect(target)
        elif path == "/go-safe":
            target = qs.get("to", ["/"])[0]
            if not is_safe_redirect(target):
                self._send("forbidden", 403)
                return
            self.redirect(target)
        else:
            self._send("not found", 404)

    def do_POST(self):
        if self.path == "/import":
            n = int(self.headers.get("Content-Length", "0"))
            blob = self.rfile.read(n)
            obj = pickle.loads(blob)
            self._send(f"imported {type(obj).__name__}")
        else:
            self._send("not found", 404)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    HTTPServer(("127.0.0.1", port), Handler).serve_forever()
