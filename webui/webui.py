#!/usr/bin/env python3
"""Local web UI for servers.db.

Serves a small static page plus the existing servers.db file. The page
loads that file into a WebAssembly core (core.wasm), so all filtering,
sorting and row formatting happen in the browser at native-ish speed while
the server only hands out bytes.

Run:

    python webui/webui.py
    python webui/webui.py --db /path/to/servers.db --port 8080
    python webui/webui.py --no-browser

The page is read-only: "Refresh" reloads servers.db from disk. Nothing in
the web UI starts a scan or sync, and the server never creates a copy.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
STATIC = os.path.join(HERE, "static")
DEFAULT_DB = os.path.join(os.path.dirname(HERE), "servers.db")

# exact static files the page needs; no directory traversal
STATIC_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
    "/core.js": ("core.js", "text/javascript; charset=utf-8"),
    "/core.wasm": ("core.wasm", "application/wasm"),
}

class Handler(BaseHTTPRequestHandler):
    server_version = "mc-webui/1.0"

    def log_message(self, fmt: str, *args) -> None:
        # Keep the console quiet.
        pass

    def _send(self, status: int, body: bytes, content_type: str,
              extra: dict | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        if extra:
            for key, value in extra.items():
                self.send_header(key, value)
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _json(self, status: int, payload: dict) -> None:
        self._send(status, json.dumps(payload).encode("utf-8"),
                   "application/json; charset=utf-8")

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path in ("/servers.db", "/servers.db-wal"):
            file_path = self.server.db_path
            if path == "/servers.db-wal":
                file_path += "-wal"
            try:
                with open(file_path, "rb") as f:
                    body = f.read()
            except FileNotFoundError:
                self._send(404, b"not found", "text/plain; charset=utf-8")
                return
            except Exception as exc:
                print(f"could not read {file_path}: {exc}",
                      file=sys.stderr, flush=True)
                self._send(500, f"could not read database: {exc}".encode(),
                           "text/plain; charset=utf-8")
                return
            self._send(200, body, "application/octet-stream")
            return

        if path == "/api/info":
            db = os.path.abspath(self.server.db_path)
            self._json(200, {
                "db": db,
                "db_name": os.path.basename(db),
                "exists": os.path.isfile(db),
            })
            return

        entry = STATIC_FILES.get(path)
        if not entry:
            self._send(404, b"not found", "text/plain; charset=utf-8")
            return
        filename, content_type = entry
        full = os.path.join(STATIC, filename)
        try:
            with open(full, "rb") as f:
                body = f.read()
        except OSError:
            self._send(500, f"missing {filename}; run webui/build.sh".encode(),
                       "text/plain; charset=utf-8")
            return
        self._send(200, body, content_type)

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="local web UI for servers.db")
    parser.add_argument("--db", default=DEFAULT_DB,
                        help=f"database file (default: {DEFAULT_DB})")
    parser.add_argument("--host", default="127.0.0.1",
                        help="bind address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8080,
                        help="port (default: 8080)")
    parser.add_argument("--no-browser", action="store_true",
                        help="do not open a browser window")
    parser.add_argument("--tls-cert", default="",
                        help="PEM certificate chain for https://")
    parser.add_argument("--tls-key", default="",
                        help="PEM private key for https://")
    args = parser.parse_args(argv)

    db_path = os.path.abspath(os.path.expanduser(args.db))
    if not os.path.isfile(db_path):
        print(f"error: no database at {db_path}", file=sys.stderr)
        return 1
    for name in ("index.html", "app.js", "style.css", "core.js", "core.wasm"):
        if not os.path.isfile(os.path.join(STATIC, name)):
            print(f"error: missing webui/static/{name}; run webui/build.sh",
                  file=sys.stderr)
            return 1

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    server.db_path = db_path  # type: ignore[attr-defined]

    tls_cert, tls_key = args.tls_cert, args.tls_key
    if not (tls_cert and tls_key):
        # Same zero-config convention as dbserver.py.
        if os.path.isfile("cert.pem") and os.path.isfile("privkey.pem"):
            tls_cert, tls_key = "cert.pem", "privkey.pem"
    scheme = "http"
    if tls_cert and tls_key:
        import ssl
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(tls_cert, tls_key)
        except Exception as exc:
            print(f"error: could not load TLS cert/key ({tls_cert}, {tls_key}): {exc}",
                  file=sys.stderr)
            server.server_close()
            return 1
        server.socket = context.wrap_socket(server.socket, server_side=True)
        scheme = "https"
        print(f"TLS enabled ({tls_cert}, {tls_key})")
    elif tls_cert or tls_key:
        print("error: --tls-cert and --tls-key must be given together",
              file=sys.stderr)
        server.server_close()
        return 1

    url = f"{scheme}://{args.host}:{args.port}/"
    print(f"serving {db_path}")
    print(f"open {url}  (Ctrl-C to stop)")

    if not args.no_browser:
        threading.Thread(
            target=lambda: (time.sleep(0.4), webbrowser.open(url)),
            daemon=True,
        ).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
