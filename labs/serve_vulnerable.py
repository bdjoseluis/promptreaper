"""Sirve el bot vulnerable por HTTP para probar la ruta HttpTarget end-to-end.

Uso:  python labs/serve_vulnerable.py [puerto]
POST /  con  {"message": "..."}  ->  {"reply": "..."}
"""

from __future__ import annotations

import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

# Permite ejecutar como script (python labs/serve_vulnerable.py) o como modulo.
try:
    from labs.vulnerable_bot import respond
except ImportError:  # pragma: no cover
    import os
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from labs.vulnerable_bot import respond


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8", errors="replace")
        try:
            msg = json.loads(body).get("message", "")
        except ValueError:
            msg = body
        reply = respond(msg)
        payload = json.dumps({"reply": reply}, ensure_ascii=False).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):  # silencia el log de acceso
        pass


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8799
    srv = HTTPServer(("127.0.0.1", port), Handler)
    print(f"Bot vulnerable HTTP en http://127.0.0.1:{port}/ (Ctrl+C para parar)")
    srv.serve_forever()


if __name__ == "__main__":
    main()
