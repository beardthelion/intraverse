"""Generated fixture: route dispatch only. Handlers live in routes_*.py."""

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
        if path == "/r001":
            return handle_r001(self, q)
        elif path == "/r002":
            return handle_r002(self, q)
        elif path == "/r003":
            return handle_r003(self, q)
        elif path == "/r004":
            return handle_r004(self, q)
        elif path == "/r005":
            return handle_r005(self, q)
        elif path == "/r006":
            return handle_r006(self, q)
        elif path == "/r007":
            return handle_r007(self, q)
        elif path == "/r008":
            return handle_r008(self, q)
        elif path == "/r009":
            return handle_r009(self, q)
        elif path == "/r010":
            return handle_r010(self, q)
        elif path == "/r011":
            return handle_r011(self, q)
        elif path == "/r012":
            return handle_r012(self, q)
        elif path == "/r013":
            return handle_r013(self, q)
        elif path == "/r014":
            return handle_r014(self, q)
        elif path == "/r015":
            return handle_r015(self, q)
        elif path == "/r016":
            return handle_r016(self, q)
        elif path == "/r017":
            return handle_r017(self, q)
        elif path == "/r018":
            return handle_r018(self, q)
        elif path == "/r019":
            return handle_r019(self, q)
        elif path == "/r020":
            return handle_r020(self, q)
        elif path == "/r021":
            return handle_r021(self, q)
        elif path == "/r022":
            return handle_r022(self, q)
        elif path == "/r023":
            return handle_r023(self, q)
        elif path == "/r024":
            return handle_r024(self, q)
        elif path == "/r025":
            return handle_r025(self, q)
        elif path == "/r026":
            return handle_r026(self, q)
        elif path == "/r027":
            return handle_r027(self, q)
        elif path == "/r028":
            return handle_r028(self, q)
        elif path == "/r029":
            return handle_r029(self, q)
        elif path == "/r030":
            return handle_r030(self, q)
        elif path == "/r031":
            return handle_r031(self, q)
        elif path == "/r032":
            return handle_r032(self, q)
        elif path == "/r033":
            return handle_r033(self, q)
        elif path == "/r034":
            return handle_r034(self, q)
        elif path == "/r035":
            return handle_r035(self, q)
        elif path == "/r036":
            return handle_r036(self, q)
        elif path == "/r037":
            return handle_r037(self, q)
        elif path == "/r038":
            return handle_r038(self, q)
        elif path == "/r039":
            return handle_r039(self, q)
        elif path == "/r040":
            return handle_r040(self, q)
        elif path == "/r041":
            return handle_r041(self, q)
        elif path == "/r042":
            return handle_r042(self, q)
        elif path == "/r043":
            return handle_r043(self, q)
        elif path == "/r044":
            return handle_r044(self, q)
        elif path == "/r045":
            return handle_r045(self, q)
        elif path == "/r046":
            return handle_r046(self, q)
        elif path == "/r047":
            return handle_r047(self, q)
        elif path == "/r048":
            return handle_r048(self, q)
        elif path == "/r049":
            return handle_r049(self, q)
        elif path == "/r050":
            return handle_r050(self, q)
        elif path == "/r051":
            return handle_r051(self, q)
        elif path == "/r052":
            return handle_r052(self, q)
        elif path == "/r053":
            return handle_r053(self, q)
        elif path == "/r054":
            return handle_r054(self, q)
        elif path == "/r055":
            return handle_r055(self, q)
        elif path == "/r056":
            return handle_r056(self, q)
        elif path == "/r057":
            return handle_r057(self, q)
        elif path == "/r058":
            return handle_r058(self, q)
        self._send("not found", 404)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    HTTPServer(("127.0.0.1", port), Handler).serve_forever()
