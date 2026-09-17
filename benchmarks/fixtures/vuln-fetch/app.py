"""Fixture app: an outbound-fetch service. /fetch is unvalidated (SSRF);
/fetch-safe validates against an allowlist."""

import os
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

ALLOWED_HOSTS = {"example.com", "static.example.com", "localhost"}


def is_allowed_url(url: str) -> bool:
    host = urlparse(url).hostname or ""
    if host in ALLOWED_HOSTS:
        return True
    return False


class Handler(BaseHTTPRequestHandler):
    def _send(self, body: str, code: int = 200):
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self):
        path = urlparse(self.path).path
        qs = parse_qs(urlparse(self.path).query)
        if path == "/fetch":
            url = qs.get("url", [""])[0]
            try:
                data = urllib.request.urlopen(url, timeout=3).read()
            except Exception as e:
                self._send(f"error: {e}", 502)
                return
            self._send(data[:500].decode(errors="replace"))
        elif path == "/fetch-safe":
            url = qs.get("url", [""])[0]
            if not is_allowed_url(url):
                self._send("forbidden", 403)
                return
            data = urllib.request.urlopen(url, timeout=3).read()
            self._send(data[:200].decode(errors="replace"))
        elif path == "/status":
            self._send("ok")
        else:
            self._send("not found", 404)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    HTTPServer(("127.0.0.1", port), Handler).serve_forever()
