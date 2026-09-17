"""Fixture app: a ping service. /ping interpolates the host into a shell
command (command injection); /ping-safe validates the host allowlist and uses
shlex.quote."""

import os
import shlex
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

ALLOWED_HOSTS = {"127.0.0.1", "localhost"}


def is_allowed_host(host: str) -> bool:
    return host in ALLOWED_HOSTS


class Handler(BaseHTTPRequestHandler):
    def _send(self, body: str, code: int = 200):
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self):
        path = urlparse(self.path).path
        qs = parse_qs(urlparse(self.path).query)
        if path == "/ping":
            host = qs.get("host", [""])[0]
            rc = os.system(f"ping -c1 -W1 {host} > /tmp/sr_ping_out 2>&1")
            try:
                with open("/tmp/sr_ping_out") as f:
                    self._send(f.read())
            except OSError:
                self._send(f"rc={rc}")
        elif path == "/ping-safe":
            host = qs.get("host", [""])[0]
            if not is_allowed_host(host):
                self._send("forbidden", 403)
                return
            rc = os.system(f"ping -c1 -W1 {shlex.quote(host)} > /tmp/sr_ping_out 2>&1")
            self._send(f"rc={rc}")
        elif path == "/echo":
            msg = qs.get("msg", [""])[0]
            self._send(msg)
        else:
            self._send("not found", 404)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    HTTPServer(("127.0.0.1", port), Handler).serve_forever()
