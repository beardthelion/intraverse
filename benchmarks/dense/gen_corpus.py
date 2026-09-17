"""Generate the decoy-dense benchmark corpus.

Produces benchmarks/dense/fixtures/corpus-a/ — a runnable multi-file
http.server app with ~58 endpoints:

  easy vulns   unguarded tainted sinks (10)
  hard vulns   guarded-looking but bypassable sinks the stub falsifies (6)
  easy decoys  effectively guarded paths (30)
  medium decoys authz-guarded dead ends + FP traps + invisible guards (12)

Ground truth lands in benchmarks/dense/ground_truth/corpus-a.json with exact
sink file/function/line, outside the indexed fixture tree.
"""

import json
import shutil
from pathlib import Path

HERE = Path(__file__).resolve().parent
FIXTURE = HERE / "fixtures" / "corpus-a"
TRUTH = HERE / "ground_truth" / "corpus-a.json"


# ---------------------------------------------------------------- handlers
# Each pattern returns the body lines of `def handle_rNNN(h, q):` plus the
# index (into those lines) of the sink statement, and whether it is a real vuln.

def _easy_cmd(i):
    return ([f'    out = os.popen("echo " + q).read()',
             '    h._send(out)'], 0, True)

def _easy_sqli(i):
    return (["    rows = db.conn.execute(f\"SELECT * FROM docs WHERE title = '{q}'\").fetchall()",
             '    h._send(str(rows))'], 0, True)

def _easy_file(i):
    return (['    data = open("docs/" + q).read()',
             '    h._send(data[:200])'], 0, True)

def _easy_ssrf(i):
    return (['    try:',
             '        data = urllib.request.urlopen(q, timeout=3).read()',
             '        h._send(data[:200].decode(errors="replace"))',
             '    except Exception as e:',
             '        h._send(f"error: {e}", 502)'], 1, True)

def _easy_redirect(i):
    return (['    redirect(h, q)'], 0, True)

def _easy_deser(i):
    return (['    try:',
             '        obj = pickle.loads(bytes.fromhex(q))',
             '        h._send(repr(obj)[:200])',
             '    except Exception as e:',
             '        h._send(f"error: {e}", 502)'], 1, True)

def _hard_ssrf_local(i):
    return (['    if not is_allowed_fetch(q):',
             '        h._send("forbidden", 403)',
             '        return',
             '    try:',
             '        data = urllib.request.urlopen(q, timeout=3).read()',
             '        h._send(data[:200].decode(errors="replace"))',
             '    except Exception as e:',
             '        h._send(f"error: {e}", 502)'], 4, True)

def _hard_ssrf_block(i):
    return (['    if not is_safe_target(q):',
             '        h._send("forbidden", 403)',
             '        return',
             '    try:',
             '        data = urllib.request.urlopen(q, timeout=3).read()',
             '        h._send(data[:200].decode(errors="replace"))',
             '    except Exception as e:',
             '        h._send(f"error: {e}", 502)'], 4, True)

def _hard_trav(i):
    return (['    if not is_safe_name(q):',
             '        h._send("forbidden", 403)',
             '        return',
             '    data = open("docs/" + q).read()',
             '    h._send(data[:200])'], 3, True)

def _hard_cmd(i):
    return (['    if not is_safe_cmd(q):',
             '        h._send("forbidden", 403)',
             '        return',
             '    out = os.popen("cat /etc/hostname " + q).read()',
             '    h._send(out)'], 3, True)

def _hard_redirect(i):
    return (['    if not is_safe_url(q):',
             '        h._send("forbidden", 403)',
             '        return',
             '    redirect(h, q)'], 3, True)

def _hard_sqli(i):
    return (['    if not is_safe_term(q):',
             '        h._send("forbidden", 403)',
             '        return',
             "    rows = db.conn.execute(\"SELECT * FROM docs WHERE title = '\" + q + \"'\").fetchall()",
             '    h._send(str(rows))'], 3, True)

def _decoy_sqli_param(i):
    return (['    rows = db.conn.execute("SELECT * FROM docs WHERE title = ?", (q,)).fetchall()',
             '    h._send(str(rows))'], 0, False)

def _decoy_cmd_quote(i):
    return (['    out = os.popen("echo " + shlex.quote(q)).read()',
             '    h._send(out)'], 0, False)

def _decoy_file_base(i):
    return (['    data = open("docs/" + os.path.basename(q)).read()',
             '    h._send(data[:200])'], 0, False)

def _decoy_cmd_int(i):
    return (['    try:',
             '        n = int(q)',
             '    except ValueError:',
             '        h._send("bad input", 400)',
             '        return',
             '    out = os.popen("echo " + str(n)).read()',
             '    h._send(out)'], 5, False)

def _decoy_ssrf_allow(i):
    return (['    if not is_allowed_host(q):',
             '        h._send("forbidden", 403)',
             '        return',
             '    try:',
             '        data = urllib.request.urlopen(q, timeout=3).read()',
             '        h._send(data[:200].decode(errors="replace"))',
             '    except Exception as e:',
             '        h._send(f"error: {e}", 502)'], 4, False)

def _decoy_sqli_authz(i):
    return (['    if not check_owner(h, q):',
             '        h._send("forbidden", 403)',
             '        return',
             "    rows = db.conn.execute(\"SELECT * FROM docs WHERE owner = '\" + q + \"'\").fetchall()",
             '    h._send(str(rows))'], 3, False)

def _decoy_file_authz(i):
    return (['    if not check_access(h, q):',
             '        h._send("forbidden", 403)',
             '        return',
             '    data = open("docs/" + q).read()',
             '    h._send(data[:200])'], 3, False)

def _decoy_file_alnum(i):
    # guard is real but invisible to the graph (isalnum is not a sanitizer
    # name): stub+static-proof will falsely confirm this -> FP trap
    return (['    if not q.isalnum():',
             '        h._send("forbidden", 403)',
             '        return',
             '    data = open("docs/" + q).read()',
             '    h._send(data[:200])'], 3, False)

def _decoy_cmd_len(i):
    # tainted but bounded: len() output is a digit string -> FP trap
    return (['    out = os.popen("echo " + str(len(q))).read()',
             '    h._send(out)'], 0, False)

def _decoy_file_hash(i):
    # tainted but bounded: sha256 hex digest -> FP trap
    return (['    try:',
             '        data = open("docs/" + hashlib.sha256(q.encode()).hexdigest()[:16] + ".txt").read()',
             '        h._send(data[:200])',
             '    except OSError:',
             '        h._send("not found", 404)'], 1, False)


PATTERNS = [
    # (generator_fn, count, vuln_class, note)
    (_easy_cmd,        2, "command_execution", "unguarded os.popen with tainted arg"),
    (_easy_sqli,       2, "raw_query",         "f-string/format SQL interpolation"),
    (_easy_file,       2, "file_access",       "unguarded open() on tainted name"),
    (_easy_ssrf,       2, "outbound_request",  "unguarded urlopen on tainted url"),
    (_easy_redirect,   1, "open_redirect",     "unguarded redirect target"),
    (_easy_deser,      1, "unsafe_deserialization", "pickle.loads on tainted bytes"),
    (_hard_ssrf_local, 1, "outbound_request",  "allowlist contains 'localhost'"),
    (_hard_ssrf_block, 1, "outbound_request",  "blocklist only covers metadata IPs"),
    (_hard_trav,       1, "file_access",       "guard blocks '/' prefix only, '..' passes"),
    (_hard_cmd,        1, "command_execution", "blacklist blocks | & ` but not ;"),
    (_hard_redirect,   1, "open_redirect",     "guard accepts any http:// URL"),
    (_hard_sqli,       1, "raw_query",         "blacklist blocks drop/delete only"),
    (_decoy_sqli_param, 6, None, "parameterized query"),
    (_decoy_cmd_quote, 6, None, "shlex.quote"),
    (_decoy_file_base, 6, None, "os.path.basename"),
    (_decoy_cmd_int,   6, None, "int() cast"),
    (_decoy_ssrf_allow,6, None, "real allowlist (no localhost)"),
    (_decoy_sqli_authz,4, None, "owner membership check before query"),
    (_decoy_file_authz,2, None, "access check before read"),
    (_decoy_file_alnum,2, None, "isalnum guard, invisible to graph"),
    (_decoy_cmd_len,   2, None, "len() bounded output"),
    (_decoy_file_hash, 2, None, "sha256 hex digest filename"),
]


SERVER_HEAD = '''"""Generated fixture: route dispatch only. Handlers live in routes_*.py."""

import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

from routes_a import *
from routes_b import *
from routes_c import *


class Handler(BaseHTTPRequestHandler):
    def _send(self, body: str, code: int = 200):
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self):
        path = urlparse(self.path).path
        qs = parse_qs(urlparse(self.path).query)
        q = qs.get("q", [""])[0]
'''

SERVER_TAIL = '''        self._send("not found", 404)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    HTTPServer(("127.0.0.1", port), Handler).serve_forever()
'''

GUARDS = '''"""Generated validators and helpers. Some are real guards, some look real
but are bypassable (that is the point of the corpus)."""

import os
from urllib.parse import urlparse

ALLOWED_HOSTS = {"api.example.com", "cdn.example.com"}
ALLOWED_FETCH = {"api.example.com", "localhost"}
BLOCKED_HOSTS = {"169.254.169.254", "metadata.google.internal"}
OWNER_IDS = {"u1", "u2", "u3"}
ACCESS_IDS = {"readme", "notes"}


def redirect(h, url):
    h.send_response(302)
    h.send_header("Location", url)
    h.end_headers()


def is_allowed_host(url: str) -> bool:
    return (urlparse(url).hostname or "") in ALLOWED_HOSTS


def is_allowed_fetch(url: str) -> bool:
    # allowlist that wrongly trusts localhost
    return (urlparse(url).hostname or "") in ALLOWED_FETCH


def is_safe_target(url: str) -> bool:
    # blocklist: metadata IPs only; loopback and everything else passes
    if (urlparse(url).hostname or "") in BLOCKED_HOSTS:
        return False
    return True


def is_safe_name(name: str) -> bool:
    if name.startswith("/") or "\\\\" in name:
        return False
    return True


def is_safe_cmd(arg: str) -> bool:
    if "|" in arg or "&" in arg or "`" in arg:
        return False
    return True


def is_safe_url(url: str) -> bool:
    if url.startswith("http://") or url.startswith("https://") or url.startswith("/"):
        return True
    return False


def is_safe_term(term: str) -> bool:
    if "drop" in term.lower() or "delete" in term.lower():
        return False
    return True


def check_owner(h, q) -> bool:
    return q in OWNER_IDS


def check_access(h, q) -> bool:
    return q in ACCESS_IDS
'''

DB = '''"""Generated sqlite store."""

import sqlite3

conn = sqlite3.connect("app.db", check_same_thread=False)
conn.execute("CREATE TABLE IF NOT EXISTS docs (id INTEGER, title TEXT, owner TEXT, body TEXT)")
if not conn.execute("SELECT COUNT(*) FROM docs").fetchone()[0]:
    conn.executemany(
        "INSERT INTO docs VALUES (?, ?, ?, ?)",
        [(1, "hello", "u1", "first doc"), (2, "notes", "u2", "second doc")],
    )
    conn.commit()
'''

ROUTE_IMPORTS = '''import hashlib
import os
import pickle
import shlex
import urllib.request

import db
from guards import (
    redirect, is_allowed_host, is_allowed_fetch, is_safe_target, is_safe_name,
    is_safe_cmd, is_safe_url, is_safe_term, check_owner, check_access,
)

'''


def main() -> None:
    if FIXTURE.exists():
        shutil.rmtree(FIXTURE)
    (FIXTURE / "docs").mkdir(parents=True)
    (FIXTURE / "docs" / "readme.txt").write_text("seed doc\n")

    routes = {"routes_a.py": [], "routes_b.py": [], "routes_c.py": []}
    route_files = list(routes)
    truth = []
    dispatch = []
    n = 0
    for fn, count, vuln, note in PATTERNS:
        for _ in range(count):
            n += 1
            name = f"handle_r{n:03d}"
            route = f"/r{n:03d}"
            body, sink_idx, is_vuln = fn(n)
            target = route_files[n % 3]
            lines = routes[target]
            base = len(lines)
            lines.append(f"def {name}(h, q):")
            lines.extend(body)
            lines.append("")
            if is_vuln:
                # file line (1-based) of the sink statement: header lines, then
                # the def line, then sink_idx body lines
                sink_line = len(ROUTE_IMPORTS.splitlines()) + base + 2 + sink_idx
                truth.append({
                    "class": vuln,
                    "sink_file": target,
                    "sink_function": name,
                    "sink_line": sink_line,
                    "note": note,
                    "route": route,
                })
            dispatch.append(
                ("        if" if not dispatch else "        elif")
                + f' path == "{route}":\n            return {name}(self, q)'
            )

    for fname, lines in routes.items():
        (FIXTURE / fname).write_text(ROUTE_IMPORTS + "\n".join(lines) + "\n")
    (FIXTURE / "guards.py").write_text(GUARDS)
    (FIXTURE / "db.py").write_text(DB)
    (FIXTURE / "server.py").write_text(
        SERVER_HEAD + "\n".join(dispatch) + "\n" + SERVER_TAIL
    )

    TRUTH.parent.mkdir(parents=True, exist_ok=True)
    TRUTH.write_text(json.dumps(truth, indent=2) + "\n")
    print(f"{n} routes, {len(truth)} real vulns -> {FIXTURE}")
    print(f"ground truth -> {TRUTH}")


if __name__ == "__main__":
    main()
