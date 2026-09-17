"""Fixture app: file download + account lookup. /download has a path traversal;
/account interpolates a user id into a SQL query with no authorization check;
/account-safe uses a parameterized query and checks ownership."""

import os
import sqlite3
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

DB = "app.db"


def get_db():
    conn = sqlite3.connect(DB)
    conn.execute("CREATE TABLE IF NOT EXISTS accounts (id INTEGER, owner TEXT, balance INTEGER)")
    conn.execute("DELETE FROM accounts")
    conn.executemany(
        "INSERT INTO accounts VALUES (?, ?, ?)",
        [(1, "alice", 100), (2, "bob", 250), (3, "carol", 75)],
    )
    conn.commit()
    return conn


def current_user_id(headers) -> int:
    # toy authn: a session header carries the user id
    try:
        return int(headers.get("X-User-Id", "0"))
    except ValueError:
        return 0


def check_account_owner(conn, uid: int, account_id: int) -> bool:
    row = conn.execute(
        "SELECT owner FROM accounts WHERE id = ?", (account_id,)
    ).fetchone()
    allowed = row is not None and uid == account_id
    return allowed


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
        if path == "/download":
            name = qs.get("name", [""])[0]
            try:
                with open(f"files/{name}") as f:
                    self._send(f.read())
            except OSError:
                self._send("not found", 404)
        elif path == "/account":
            uid = current_user_id(self.headers)
            if not uid:
                self._send("unauthorized", 401)
                return
            account_id = qs.get("id", ["0"])[0]
            # BUG: string interpolation into SQL, and no ownership check
            row = conn.execute(
                f"SELECT id, owner, balance FROM accounts WHERE id = {account_id}"
            ).fetchone()
            self._send(str(row) if row else "no such account")
        elif path == "/account-safe":
            uid = current_user_id(self.headers)
            if not uid:
                self._send("unauthorized", 401)
                return
            account_id = int(qs.get("id", ["0"])[0])
            if not check_account_owner(conn, uid, account_id):
                self._send("forbidden", 403)
                return
            row = conn.execute(
                "SELECT id, owner, balance FROM accounts WHERE id = ?", (account_id,)
            ).fetchone()
            self._send(str(row) if row else "no such account")
        elif path == "/health":
            self._send("ok")
        else:
            self._send("not found", 404)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    os.makedirs("files", exist_ok=True)
    with open("files/readme.txt", "w") as f:
        f.write("hello\n")
    port = int(os.environ.get("PORT", "8080"))
    HTTPServer(("127.0.0.1", port), Handler).serve_forever()
