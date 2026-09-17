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

def handle_r003(h, q):
    rows = db.conn.execute(f"SELECT * FROM docs WHERE title = '{q}'").fetchall()
    h._send(str(rows))

def handle_r006(h, q):
    data = open("docs/" + q).read()
    h._send(data[:200])

def handle_r009(h, q):
    redirect(h, q)

def handle_r012(h, q):
    if not is_safe_target(q):
        h._send("forbidden", 403)
        return
    try:
        data = urllib.request.urlopen(q, timeout=3).read()
        h._send(data[:200].decode(errors="replace"))
    except Exception as e:
        h._send(f"error: {e}", 502)

def handle_r015(h, q):
    if not is_safe_url(q):
        h._send("forbidden", 403)
        return
    redirect(h, q)

def handle_r018(h, q):
    rows = db.conn.execute("SELECT * FROM docs WHERE title = ?", (q,)).fetchall()
    h._send(str(rows))

def handle_r021(h, q):
    rows = db.conn.execute("SELECT * FROM docs WHERE title = ?", (q,)).fetchall()
    h._send(str(rows))

def handle_r024(h, q):
    out = os.popen("echo " + shlex.quote(q)).read()
    h._send(out)

def handle_r027(h, q):
    out = os.popen("echo " + shlex.quote(q)).read()
    h._send(out)

def handle_r030(h, q):
    data = open("docs/" + os.path.basename(q)).read()
    h._send(data[:200])

def handle_r033(h, q):
    data = open("docs/" + os.path.basename(q)).read()
    h._send(data[:200])

def handle_r036(h, q):
    try:
        n = int(q)
    except ValueError:
        h._send("bad input", 400)
        return
    out = os.popen("echo " + str(n)).read()
    h._send(out)

def handle_r039(h, q):
    try:
        n = int(q)
    except ValueError:
        h._send("bad input", 400)
        return
    out = os.popen("echo " + str(n)).read()
    h._send(out)

def handle_r042(h, q):
    if not is_allowed_host(q):
        h._send("forbidden", 403)
        return
    try:
        data = urllib.request.urlopen(q, timeout=3).read()
        h._send(data[:200].decode(errors="replace"))
    except Exception as e:
        h._send(f"error: {e}", 502)

def handle_r045(h, q):
    if not is_allowed_host(q):
        h._send("forbidden", 403)
        return
    try:
        data = urllib.request.urlopen(q, timeout=3).read()
        h._send(data[:200].decode(errors="replace"))
    except Exception as e:
        h._send(f"error: {e}", 502)

def handle_r048(h, q):
    if not check_owner(h, q):
        h._send("forbidden", 403)
        return
    rows = db.conn.execute("SELECT * FROM docs WHERE owner = '" + q + "'").fetchall()
    h._send(str(rows))

def handle_r051(h, q):
    if not check_access(h, q):
        h._send("forbidden", 403)
        return
    data = open("docs/" + q).read()
    h._send(data[:200])

def handle_r054(h, q):
    if not q.isalnum():
        h._send("forbidden", 403)
        return
    data = open("docs/" + q).read()
    h._send(data[:200])

def handle_r057(h, q):
    try:
        data = open("docs/" + hashlib.sha256(q.encode()).hexdigest()[:16] + ".txt").read()
        h._send(data[:200])
    except OSError:
        h._send("not found", 404)

