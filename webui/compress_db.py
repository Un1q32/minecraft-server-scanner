#!/usr/bin/env python3
"""Keep a zstd-compressed snapshot of servers.db for the static web viewer.

The web viewer downloads ``servers.db.zst`` instead of the raw SQLite file
when it exists, so a refresh transfers roughly a third as many bytes.  This
helper creates a consistent snapshot with ``VACUUM INTO`` (no live WAL
needed), compresses it, and atomically replaces the output file.

Run it forever next to the database::

    python3 webui/compress_db.py \
        --db /srv/mc-scanner/servers.db \
        --out /srv/mc-scanner/servers.db.zst

or once from cron / a systemd timer with ``--once``.

Python 3.14's ``compression.zstd`` is used when available; otherwise the
``zstd`` command-line tool is required.  No pip packages are needed.
"""

from __future__ import annotations

import argparse
import os
import shutil
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time

try:
    from compression import zstd as _zstd   # Python 3.14+
except ImportError:
    _zstd = None


def _zstd_level(level):
    return max(1, min(int(level), 19))


def _compress(src, dst, level):
    """Compress ``src`` to ``dst`` atomically, streaming the file."""
    tmp = dst + ".tmp"
    try:
        if _zstd is not None:
            comp = _zstd.ZstdCompressor(level=level)
            with open(src, "rb") as fi, open(tmp, "wb") as fo:
                while True:
                    chunk = fi.read(4 * 1024 * 1024)
                    if not chunk:
                        break
                    fo.write(comp.compress(
                        chunk, _zstd.ZstdCompressor.CONTINUE))
                fo.write(comp.flush(_zstd.ZstdCompressor.FLUSH_FRAME))
        else:
            exe = shutil.which("zstd")
            if not exe:
                raise RuntimeError(
                    "zstd not available: install the zstd tool or use "
                    "Python 3.14+")
            subprocess.run(
                [exe, "-q", "-f", f"-{level}", "-T0", src, "-o", tmp],
                check=True)
        try:
            os.chmod(tmp, 0o644)
        except OSError:
            pass
        os.replace(tmp, dst)
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def _snapshot(db_path, out_dir):
    """Consistent SQLite snapshot -> temp path (caller deletes it)."""
    fd, snap = tempfile.mkstemp(prefix=".servers-snapshot-", suffix=".db",
                                dir=out_dir)
    os.close(fd)
    os.unlink(snap)          # VACUUM INTO refuses an existing file
    uri = f"file:{os.path.abspath(db_path)}?mode=ro"
    con = sqlite3.connect(uri, uri=True, timeout=30)
    try:
        con.execute("VACUUM INTO ?", (snap,))
    finally:
        con.close()
    return snap


def _state(db_path):
    parts = []
    # -shm changes with reader/writer locks and would force a rewrite on
    # every interval even when no data changed.
    for suffix in ("", "-wal"):
        try:
            st = os.stat(db_path + suffix)
            parts.append((st.st_mtime_ns, st.st_size))
        except OSError:
            parts.append(None)
    return tuple(parts)


def _run_once(db_path, out_path, level, quiet=False):
    if not os.path.isfile(db_path):
        if not quiet:
            print(f"compress_db: waiting for {db_path}", flush=True)
        return False
    out_dir = os.path.dirname(os.path.abspath(out_path)) or "."
    os.makedirs(out_dir, exist_ok=True)
    started = time.monotonic()
    snap = None
    try:
        snap = _snapshot(db_path, out_dir)
        before = os.path.getsize(snap)
        _compress(snap, out_path, level)
        after = os.path.getsize(out_path)
        if not quiet:
            print(f"compress_db: {os.path.basename(out_path)} "
                  f"{before / 1048576:.1f} MB -> {after / 1048576:.1f} MB "
                  f"in {time.monotonic() - started:.1f}s", flush=True)
        return True
    finally:
        if snap:
            try:
                os.unlink(snap)
            except OSError:
                pass


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Continuously write a zstd snapshot of servers.db for "
                    "the static web viewer.")
    parser.add_argument("--db", default="servers.db",
                        help="SQLite database to snapshot (default: servers.db)")
    parser.add_argument("--out", default=None,
                        help="compressed output (default: <db>.zst)")
    parser.add_argument("--interval", type=float, default=120,
                        help="seconds between updates (default: 120)")
    parser.add_argument("--level", type=int, default=3,
                        help="zstd level 1-19 (default: 3)")
    parser.add_argument("--once", action="store_true",
                        help="write one snapshot and exit")
    parser.add_argument("--quiet", action="store_true",
                        help="only print errors")
    args = parser.parse_args(argv)

    db_path = os.path.abspath(args.db)
    out_path = os.path.abspath(args.out or (db_path + ".zst"))
    level = _zstd_level(args.level)

    stopping = {"value": False}

    def stop(_signum, _frame):
        stopping["value"] = True

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, stop)
        except Exception:
            pass

    last_state = None
    while not stopping["value"]:
        state = _state(db_path)
        if state == last_state and os.path.isfile(out_path):
            if args.once:
                break
            deadline = time.monotonic() + max(1.0, args.interval)
            while not stopping["value"] and time.monotonic() < deadline:
                time.sleep(min(1.0, deadline - time.monotonic()))
            continue
        try:
            if _run_once(db_path, out_path, level, quiet=args.quiet):
                last_state = state
        except Exception as exc:
            if not args.quiet:
                print(f"compress_db: {exc}", file=sys.stderr, flush=True)
        if args.once:
            break
        deadline = time.monotonic() + max(1.0, args.interval)
        while not stopping["value"] and time.monotonic() < deadline:
            time.sleep(min(1.0, deadline - time.monotonic()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
