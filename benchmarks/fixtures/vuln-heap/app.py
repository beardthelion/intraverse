"""Fixture app: a larger service with many endpoints — mostly guarded sinks,
with a few real vulnerabilities buried among them. Exists so path-selection
strategy measurably affects what gets found within an investigation budget.
"""

import os
import shlex
import sqlite3
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

DB = "heap.db"
ALLOWED_HOSTS = {"example.com", "api.example.com"}
ALLOWED_FILES = {"readme.txt", "changelog.txt", "manual.txt"}


def get_db():
    conn = sqlite3.connect(DB)
    conn.execute("CREATE TABLE IF NOT EXISTS docs (id INTEGER, title TEXT, body TEXT)")
    conn.execute("DELETE FROM docs")
    conn.executemany("INSERT INTO docs VALUES (?, ?, ?)",
                     [(1, "a", "x"), (2, "b", "y"), (3, "c", "z")])
    conn.commit()
    return conn


def is_allowed_url(url: str) -> bool:
    return (urlparse(url).hostname or "") in ALLOWED_HOSTS


def is_allowed_file(name: str) -> bool:
    return name in ALLOWED_FILES


def current_user(headers):
    return headers.get("X-User-Id", "")


def check_doc_owner(conn, uid: str, doc_id: int) -> bool:
    row = conn.execute("SELECT title FROM docs WHERE id = ?", (doc_id,)).fetchone()
    return row is not None and uid == str(doc_id)


class Handler(BaseHTTPRequestHandler):
    def _send(self, body: str, code: int = 200):
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self):
        path = urlparse(self.path).path
        qs = parse_qs(urlparse(self.path).query)
        conn = get_db()

        # --- guarded endpoints (safe candidates) ---
        if path == "/fetch1":
            url = qs.get("url", [""])[0]
            if not is_allowed_url(url):
                self._send("forbidden", 403)
                return
            self._send(urllib.request.urlopen(url, timeout=3).read()[:200].decode(errors="replace"))
        elif path == "/fetch2":
            url = qs.get("url", [""])[0]
            if not is_allowed_url(url):
                self._send("forbidden", 403)
                return
            self._send(urllib.request.urlopen(url, timeout=3).read()[:200].decode(errors="replace"))
        elif path == "/read1":
            name = qs.get("name", [""])[0]
            if not is_allowed_file(name):
                self._send("forbidden", 403)
                return
            with open(f"files/{name}") as f:
                self._send(f.read())
        elif path == "/read2":
            name = qs.get("name", [""])[0]
            if not is_allowed_file(name):
                self._send("forbidden", 403)
                return
            with open(f"files/{name}") as f:
                self._send(f.read())
        elif path == "/doc-safe":
            uid = current_user(self.headers)
            doc_id = int(qs.get("id", ["0"])[0])
            if not check_doc_owner(conn, uid, doc_id):
                self._send("forbidden", 403)
                return
            row = conn.execute("SELECT * FROM docs WHERE id = ?", (doc_id,)).fetchone()
            self._send(str(row))
        elif path == "/ping-safe":
            host = qs.get("host", [""])[0]
            os.system(f"ping -c1 -W1 {shlex.quote(host)} > /dev/null 2>&1")
            self._send("ok")
        elif path == "/go-safe":
            target = qs.get("to", ["/"])[0]
            if not target.startswith("/"):
                self._send("forbidden", 403)
                return
            self.send_response(302)
            self.send_header("Location", target)
            self.end_headers()

        # --- real vulnerabilities ---
        elif path == "/proxy":
            # BUG: SSRF — user-supplied URL fetched without validation
            url = qs.get("u", [""])[0]
            try:
                self._send(urllib.request.urlopen(url, timeout=3).read()[:500].decode(errors="replace"))
            except Exception as e:
                self._send(f"error: {e}", 502)
        elif path == "/file":
            # BUG: path traversal — arbitrary file read
            name = qs.get("f", [""])[0]
            try:
                with open(f"files/{name}") as f:
                    self._send(f.read())
            except OSError:
                self._send("not found", 404)
        elif path == "/doc":
            # BUG: SQLi — interpolated id, no ownership check
            doc_id = qs.get("id", ["0"])[0]
            row = conn.execute(
                f"SELECT * FROM docs WHERE id = {doc_id}"
            ).fetchone()
            self._send(str(row) if row else "none")
        elif path == "/diag":
            # BUG: command injection — host interpolated into shell command
            host = qs.get("h", [""])[0]
            os.system(f"ping -c1 -W1 {host} > /tmp/sr_heap_out 2>&1")
            try:
                with open("/tmp/sr_heap_out") as f:
                    self._send(f.read())
            except OSError:
                self._send("done")
        else:
            self._send("not found", 404)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    os.makedirs("files", exist_ok=True)
    for n in ALLOWED_FILES:
        with open(f"files/{n}", "w") as f:
            f.write("public\n")
    port = int(os.environ.get("PORT", "8080"))
    HTTPServer(("127.0.0.1", port), Handler).serve_forever()
