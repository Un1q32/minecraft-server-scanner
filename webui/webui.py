#!/usr/bin/env python3
"""Local web UI for servers.db.

Serves a small static page plus a SQLite snapshot of the scanner database.
The page loads the snapshot into a WebAssembly core (core.wasm), so all
filtering, sorting and row formatting happen in the browser at native-ish
speed while the server only hands out bytes.

Run:

    python webui/webui.py
    python webui/webui.py --db /path/to/servers.db --port 8080
    python webui/webui.py --no-browser

The page is read-only: "Refresh" reloads the current servers.db snapshot
(including changes made by a scanner running elsewhere). Nothing in the web
UI starts a scan or sync.
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
import tempfile
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

_snapshot_lock = threading.Lock()
_snapshot = {"key": None, "path": None}


def _db_files(db_path: str) -> list[str]:
    return [db_path, db_path + "-wal", db_path + "-shm"]


def _db_key(db_path: str):
    key = []
    for path in _db_files(db_path):
        try:
            st = os.stat(path)
            key.append((st.st_mtime_ns, st.st_size))
        except OSError:
            key.append(None)
    return tuple(key)


def make_snapshot(db_path: str) -> str:
    """Copy the live DB (including its WAL) to a consistent temp file."""
    if not os.path.isfile(db_path):
        raise FileNotFoundError(db_path)
    key = _db_key(db_path)
    with _snapshot_lock:
        if _snapshot["key"] == key and _snapshot["path"] and os.path.exists(_snapshot["path"]):
            return _snapshot["path"]
        old = _snapshot["path"]
        fd, path = tempfile.mkstemp(prefix="mc-webui-", suffix=".db")
        os.close(fd)
        try:
            source = sqlite3.connect(db_path, timeout=10)
            try:
                dest = sqlite3.connect(path)
                try:
                    source.backup(dest)
                    dest.execute("PRAGMA journal_mode=DELETE")
                finally:
                    dest.close()
            finally:
                source.close()
        except Exception:
            try:
                os.unlink(path)
            except OSError:
                pass
            raise
        _snapshot["key"] = key
        _snapshot["path"] = path
        if old and old != path:
            try:
                os.unlink(old)
            except OSError:
                pass
        return path


def invalidate_snapshot() -> None:
    with _snapshot_lock:
        if _snapshot["path"]:
            try:
                os.unlink(_snapshot["path"])
            except OSError:
                pass
        _snapshot["key"] = None
        _snapshot["path"] = None


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
        if path == "/servers.db":
            try:
                snapshot = make_snapshot(self.server.db_path)
                with open(snapshot, "rb") as f:
                    body = f.read()
            except Exception as exc:
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
    url = f"http://{args.host}:{args.port}/"
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
        invalidate_snapshot()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
