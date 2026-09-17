"""Fixture app with no planted vulnerabilities: every user input is validated
before it reaches a sink. Used to measure false-positive rate."""

import os
import shlex
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

ALLOWED_HOSTS = {"example.com"}
ALLOWED_FILES = {"readme.txt", "changelog.txt"}


def is_allowed_url(url: str) -> bool:
    host = urlparse(url).hostname or ""
    return host in ALLOWED_HOSTS


def is_allowed_file(name: str) -> bool:
    return name in ALLOWED_FILES


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
            if not is_allowed_url(url):
                self._send("forbidden", 403)
                return
            data = urllib.request.urlopen(url, timeout=3).read()
            self._send(data[:200].decode(errors="replace"))
        elif path == "/read":
            name = qs.get("name", [""])[0]
            if not is_allowed_file(name):
                self._send("forbidden", 403)
                return
            with open(f"files/{name}") as f:
                self._send(f.read())
        elif path == "/ping":
            host = qs.get("host", ["127.0.0.1"])[0]
            os.system(f"ping -c1 -W1 {shlex.quote(host)} > /dev/null 2>&1")
            self._send("ok")
        else:
            self._send("not found", 404)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    os.makedirs("files", exist_ok=True)
    with open("files/readme.txt", "w") as f:
        f.write("hello\n")
    with open("files/changelog.txt", "w") as f:
        f.write("v1\n")
    port = int(os.environ.get("PORT", "8080"))
    HTTPServer(("127.0.0.1", port), Handler).serve_forever()
