"""Localhost sandbox validator for runnable Python HTTP fixture apps.

Launches the target app on an ephemeral 127.0.0.1 port, crafts one exploit
request derived from the confirmed path (route + tainted parameter + vuln-class
payload), and checks for an observable marker. For SSRF it runs a canary
listener on a second localhost port and watches for the inbound request.

Safety bounds: everything stays on 127.0.0.1; payloads are read-only markers
(``echo`` of a canary string, traversal to /etc/hostname, a same-host canary
URL). Nothing here contacts an external host.
"""

from __future__ import annotations

import re
import socket
import subprocess
import sys
import threading
import time
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from ..models import AttackPath, InvestigationReport, NodeType
from ..graph.code_graph import CodeGraph
from .base import ValidationResult, Validator

MARKER = "SRVLT_MARKER_9173"


class _Canary(BaseHTTPRequestHandler):
    hits: list[str] = []

    def do_GET(self):
        _Canary.hits.append(self.path)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _route_and_param(graph: CodeGraph, path: AttackPath) -> tuple[str, str]:
    """Pull the concrete route and tainted query param from the entry node."""
    entry = graph.nodes.get(path.nodes[0]) if path.nodes else None
    route, param = "/", ""
    if not entry:
        return route, param
    try:
        src = (Path(graph.root) / entry.location.file).read_text(errors="replace")
    except OSError:
        return route, param
    # route literal from startswith/== comparisons or decorator arg
    if entry.attrs.get("route") and entry.attrs["route"] not in ("GET", "POST", "PUT", "DELETE"):
        route = entry.attrs["route"]
    else:
        # route dispatch idioms: path == "/x", self.path == "/x", .startswith("/x").
        # choose the comparison nearest above the sink line so multi-route
        # handlers resolve to the branch that contains the sink.
        sink_line = 0
        sink_node = graph.nodes.get(path.nodes[-1]) if path.nodes else None
        if sink_node:
            sink_line = sink_node.location.line_start
        matches = list(re.finditer(
            r'(?:self\.path|\bpath)\s*(?:==\s*|\.startswith\()\s*["\']([^"\']+)', src
        ))
        best = None
        for m in matches:
            line = src[: m.start()].count("\n") + 1
            if line <= sink_line and (best is None or line > best[0]):
                best = (line, m.group(1))
        if best is None and matches:
            best = (0, matches[0].group(1))
        if best:
            route = best[1]
    # tainted param name from user_input nodes on the path; search within the
    # dispatch branch region (route line .. sink line) when known
    region = src
    if sink_line:
        route_line = 0
        for m in re.finditer(
            r'(?:self\.path|\bpath)\s*(?:==\s*|\.startswith\()\s*["\']([^"\']+)', src
        ):
            ln = src[: m.start()].count("\n") + 1
            if ln <= sink_line:
                route_line = ln
        region = "\n".join(src.splitlines()[max(0, route_line - 1): sink_line])
    for nid in path.nodes:
        n = graph.nodes.get(nid)
        if n and n.type == NodeType.USER_INPUT:
            var = n.attrs.get("var", "")
            m = re.search(rf'{re.escape(var)}\s*=\s*[^\n]*get\(["\']([^"\']+)', region)
            if m:
                param = m.group(1)
                break
            m = re.search(rf'{re.escape(var)}\s*=\s*\w+\[["\']([^"\']+)', region)
            if m:
                param = m.group(1)
                break
    if not param:
        m = re.search(r'\.get\(["\']([a-zA-Z_][a-zA-Z0-9_]*)["\']', region)
        if m:
            param = m.group(1)
    return route, param


class HttpSandboxValidator(Validator):
    name = "http-sandbox"

    def __init__(self, repo_root: str, entry_file: str | None = None,
                 timeout: float = 15.0):
        self.repo_root = Path(repo_root).resolve()
        self.entry_file = entry_file
        self.timeout = timeout

    def _find_app(self) -> Path | None:
        if self.entry_file:
            p = self.repo_root / self.entry_file
            return p if p.exists() else None
        for py in sorted(self.repo_root.rglob("*.py")):
            try:
                if "HTTPServer" in py.read_text(errors="replace"):
                    return py
            except OSError:
                continue
        return None

    def validate(
        self,
        path: AttackPath,
        report: InvestigationReport,
        graph: CodeGraph,
    ) -> ValidationResult:
        sink = graph.nodes.get(path.nodes[-1]) if path.nodes else None
        vuln = sink.attrs.get("vuln", "") if sink else ""
        app = self._find_app()
        if not app:
            return ValidationResult(False, self.name, detail="no runnable app found")
        app = app.resolve()
        route, param = _route_and_param(graph, path)

        port = _free_port()
        canary_port = _free_port()
        canary = HTTPServer(("127.0.0.1", canary_port), _Canary)
        _Canary.hits = []
        t = threading.Thread(target=canary.serve_forever, daemon=True)
        t.start()

        proc = subprocess.Popen(
            [sys.executable, str(app)],
            cwd=str(app.parent),
            env={"PATH": "/usr/bin:/bin:/usr/local/bin", "PORT": str(port)},
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            if not self._wait_ready(port):
                return ValidationResult(False, self.name,
                                        detail="app did not start on localhost")
            return self._exploit(vuln, port, canary_port, route, param)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
            canary.shutdown()

    def _wait_ready(self, port: int) -> bool:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=1)
                return True
            except urllib.error.HTTPError:
                return True  # any HTTP response means the server is up
            except Exception:
                time.sleep(0.15)
        return False

    def _exploit(self, vuln: str, port: int, canary_port: int,
                 route: str, param: str) -> ValidationResult:
        if not param:
            return ValidationResult(False, self.name,
                                    detail="could not derive tainted parameter")
        canary_url = f"http://127.0.0.1:{canary_port}/hit"
        if vuln == "outbound_request":
            payload = canary_url
            self._request(port, route, param, payload)
            hit = bool(_Canary.hits)
            return ValidationResult(
                verified=hit, method=self.name,
                reproduction=f"GET {route}?{param}=<canary-url> caused server-side fetch",
                evidence=_Canary.hits[:],
                detail="canary listener observed inbound request" if hit
                else "no canary hit",
            )
        payloads = {
            "command_execution": f"; echo {MARKER}",
            "file_access": "../../../../../../../../etc/hostname",
            "file_delete": "../../../../../../../../tmp/nonexistent",
            "raw_query": "' OR '1'='1' --",
            "open_redirect": canary_url,
            "template_injection": "{{7*7}}",
        }
        payload = payloads.get(vuln)
        if payload is None:
            return ValidationResult(False, self.name,
                                    detail=f"no live-repro payload for {vuln}")
        status, body, headers = self._request(port, route, param, payload)
        verified = False
        obs = ""
        if vuln == "command_execution":
            verified = MARKER in body
            obs = f"marker in response body: {verified}"
        elif vuln in ("file_access", "file_delete"):
            verified = bool(body.strip()) and status == 200 and "not found" not in body.lower()
            obs = f"file content returned: {body[:80]!r}"
        elif vuln == "raw_query":
            verified = status == 200 and len(body.strip()) > 0
            obs = f"query response: {body[:80]!r}"
        elif vuln == "open_redirect":
            verified = headers.get("Location", "") == payload or status in (301, 302, 303, 307, 308) and payload in headers.get("Location", "")
            obs = f"Location: {headers.get('Location')}"
        elif vuln == "template_injection":
            verified = "49" in body
            obs = f"template evaluated: {body[:80]!r}"
        return ValidationResult(
            verified=verified, method=self.name,
            reproduction=f"GET {route}?{param}={payload}",
            evidence=[obs, f"HTTP {status}", body[:200]],
            detail=obs,
        )

    def _request(self, port: int, route: str, param: str, payload: str) -> tuple[int, str, dict]:
        url = f"http://127.0.0.1:{port}{route}?{param}={urllib.request.quote(payload)}"
        try:
            req = urllib.request.Request(url)
            opener = urllib.request.build_opener(_NoRedirect())
            with opener.open(req, timeout=self.timeout) as resp:
                return resp.status, resp.read().decode(errors="replace"), dict(resp.headers)
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode(errors="replace"), dict(e.headers)
        except Exception as e:
            return 0, "", {"error": str(e)}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **kw):
        return None
