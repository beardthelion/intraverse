import hashlib
import os
import pickle
import shlex
import urllib.request

import db
from guards import (
    redirect, is_allowed_host, is_allowed_fetch, is_safe_target, is_safe_name,
    is_safe_cmd, is_safe_url, is_safe_term, check_owner, check_access,
)

def handle_r001(h, q):
    out = os.popen("echo " + q).read()
    h._send(out)

def handle_r004(h, q):
    rows = db.conn.execute(f"SELECT * FROM docs WHERE title = '{q}'").fetchall()
    h._send(str(rows))

def handle_r007(h, q):
    try:
        data = urllib.request.urlopen(q, timeout=3).read()
        h._send(data[:200].decode(errors="replace"))
    except Exception as e:
        h._send(f"error: {e}", 502)

def handle_r010(h, q):
    try:
        obj = pickle.loads(bytes.fromhex(q))
        h._send(repr(obj)[:200])
    except Exception as e:
        h._send(f"error: {e}", 502)

def handle_r013(h, q):
    if not is_safe_name(q):
        h._send("forbidden", 403)
        return
    data = open("docs/" + q).read()
    h._send(data[:200])

def handle_r016(h, q):
    if not is_safe_term(q):
        h._send("forbidden", 403)
        return
    rows = db.conn.execute("SELECT * FROM docs WHERE title = '" + q + "'").fetchall()
    h._send(str(rows))

def handle_r019(h, q):
    rows = db.conn.execute("SELECT * FROM docs WHERE title = ?", (q,)).fetchall()
    h._send(str(rows))

def handle_r022(h, q):
    rows = db.conn.execute("SELECT * FROM docs WHERE title = ?", (q,)).fetchall()
    h._send(str(rows))

def handle_r025(h, q):
    out = os.popen("echo " + shlex.quote(q)).read()
    h._send(out)

def handle_r028(h, q):
    out = os.popen("echo " + shlex.quote(q)).read()
    h._send(out)

def handle_r031(h, q):
    data = open("docs/" + os.path.basename(q)).read()
    h._send(data[:200])

def handle_r034(h, q):
    data = open("docs/" + os.path.basename(q)).read()
    h._send(data[:200])

def handle_r037(h, q):
    try:
        n = int(q)
    except ValueError:
        h._send("bad input", 400)
        return
    out = os.popen("echo " + str(n)).read()
    h._send(out)

def handle_r040(h, q):
    try:
        n = int(q)
    except ValueError:
        h._send("bad input", 400)
        return
    out = os.popen("echo " + str(n)).read()
    h._send(out)

def handle_r043(h, q):
    if not is_allowed_host(q):
        h._send("forbidden", 403)
        return
    try:
        data = urllib.request.urlopen(q, timeout=3).read()
        h._send(data[:200].decode(errors="replace"))
    except Exception as e:
        h._send(f"error: {e}", 502)

def handle_r046(h, q):
    if not is_allowed_host(q):
        h._send("forbidden", 403)
        return
    try:
        data = urllib.request.urlopen(q, timeout=3).read()
        h._send(data[:200].decode(errors="replace"))
    except Exception as e:
        h._send(f"error: {e}", 502)

def handle_r049(h, q):
    if not check_owner(h, q):
        h._send("forbidden", 403)
        return
    rows = db.conn.execute("SELECT * FROM docs WHERE owner = '" + q + "'").fetchall()
    h._send(str(rows))

def handle_r052(h, q):
    if not check_access(h, q):
        h._send("forbidden", 403)
        return
    data = open("docs/" + q).read()
    h._send(data[:200])

def handle_r055(h, q):
    out = os.popen("echo " + str(len(q))).read()
    h._send(out)

def handle_r058(h, q):
    try:
        data = open("docs/" + hashlib.sha256(q.encode()).hexdigest()[:16] + ".txt").read()
        h._send(data[:200])
    except OSError:
        h._send("not found", 404)

