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

def handle_r002(h, q):
    out = os.popen("echo " + q).read()
    h._send(out)

def handle_r005(h, q):
    data = open("docs/" + q).read()
    h._send(data[:200])

def handle_r008(h, q):
    try:
        data = urllib.request.urlopen(q, timeout=3).read()
        h._send(data[:200].decode(errors="replace"))
    except Exception as e:
        h._send(f"error: {e}", 502)

def handle_r011(h, q):
    if not is_allowed_fetch(q):
        h._send("forbidden", 403)
        return
    try:
        data = urllib.request.urlopen(q, timeout=3).read()
        h._send(data[:200].decode(errors="replace"))
    except Exception as e:
        h._send(f"error: {e}", 502)

def handle_r014(h, q):
    if not is_safe_cmd(q):
        h._send("forbidden", 403)
        return
    out = os.popen("cat /etc/hostname " + q).read()
    h._send(out)

def handle_r017(h, q):
    rows = db.conn.execute("SELECT * FROM docs WHERE title = ?", (q,)).fetchall()
    h._send(str(rows))

def handle_r020(h, q):
    rows = db.conn.execute("SELECT * FROM docs WHERE title = ?", (q,)).fetchall()
    h._send(str(rows))

def handle_r023(h, q):
    out = os.popen("echo " + shlex.quote(q)).read()
    h._send(out)

def handle_r026(h, q):
    out = os.popen("echo " + shlex.quote(q)).read()
    h._send(out)

def handle_r029(h, q):
    data = open("docs/" + os.path.basename(q)).read()
    h._send(data[:200])

def handle_r032(h, q):
    data = open("docs/" + os.path.basename(q)).read()
    h._send(data[:200])

def handle_r035(h, q):
    try:
        n = int(q)
    except ValueError:
        h._send("bad input", 400)
        return
    out = os.popen("echo " + str(n)).read()
    h._send(out)

def handle_r038(h, q):
    try:
        n = int(q)
    except ValueError:
        h._send("bad input", 400)
        return
    out = os.popen("echo " + str(n)).read()
    h._send(out)

def handle_r041(h, q):
    if not is_allowed_host(q):
        h._send("forbidden", 403)
        return
    try:
        data = urllib.request.urlopen(q, timeout=3).read()
        h._send(data[:200].decode(errors="replace"))
    except Exception as e:
        h._send(f"error: {e}", 502)

def handle_r044(h, q):
    if not is_allowed_host(q):
        h._send("forbidden", 403)
        return
    try:
        data = urllib.request.urlopen(q, timeout=3).read()
        h._send(data[:200].decode(errors="replace"))
    except Exception as e:
        h._send(f"error: {e}", 502)

def handle_r047(h, q):
    if not check_owner(h, q):
        h._send("forbidden", 403)
        return
    rows = db.conn.execute("SELECT * FROM docs WHERE owner = '" + q + "'").fetchall()
    h._send(str(rows))

def handle_r050(h, q):
    if not check_owner(h, q):
        h._send("forbidden", 403)
        return
    rows = db.conn.execute("SELECT * FROM docs WHERE owner = '" + q + "'").fetchall()
    h._send(str(rows))

def handle_r053(h, q):
    if not q.isalnum():
        h._send("forbidden", 403)
        return
    data = open("docs/" + q).read()
    h._send(data[:200])

def handle_r056(h, q):
    out = os.popen("echo " + str(len(q))).read()
    h._send(out)

