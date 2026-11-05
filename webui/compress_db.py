#!/usr/bin/env python3
"""Keep a zstd-compressed snapshot of servers.db for the static web viewer.

The web viewer downloads ``servers.db.zst`` instead of the raw SQLite file
when it exists, so a refresh transfers roughly a third as many bytes.  This
helper creates a consistent snapshot with ``VACUUM INTO`` (no live WAL
needed), compresses it, and atomically replaces the output.

Run it forever next to the database::

    python3 webui/compress_db.py \
        --db /srv/mc-scanner/servers.db \
        --out /srv/mc-scanner/servers.db.zst

or once from cron / a systemd timer with ``--once``.  The shared
``dbserver.py`` can also maintain this file itself; see
``--web-db-zst``.
"""

from __future__ import annotations

import argparse
import os
import signal
import sys
import time

# This script lives in webui/; the shared helper is one level up.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from db_zstd import DEFAULT_LEVEL, snapshot_and_compress, zstd_available  # noqa: E402


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
    try:
        before, after, seconds = snapshot_and_compress(
            db_path, out_path, level=level)
    except Exception as exc:
        if not quiet:
            print(f"compress_db: {exc}", file=sys.stderr, flush=True)
        return False
    if not quiet:
        print(f"compress_db: {os.path.basename(out_path)} "
              f"{before / 1048576:.1f} MB -> {after / 1048576:.1f} MB "
              f"in {seconds:.1f}s", flush=True)
    return True


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
    parser.add_argument("--level", type=int, default=DEFAULT_LEVEL,
                        help=f"zstd level 1-19 (default: {DEFAULT_LEVEL})")
    parser.add_argument("--once", action="store_true",
                        help="write one snapshot and exit")
    parser.add_argument("--quiet", action="store_true",
                        help="only print errors")
    args = parser.parse_args(argv)

    if not zstd_available():
        print("compress_db: zstd is not available (install zstd or use "
              "Python 3.14+)", file=sys.stderr)
        return 2

    db_path = os.path.abspath(args.db)
    out_path = os.path.abspath(args.out or (db_path + ".zst"))

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
        if _run_once(db_path, out_path, args.level, quiet=args.quiet):
            last_state = state
        if args.once:
            break
        deadline = time.monotonic() + max(1.0, args.interval)
        while not stopping["value"] and time.monotonic() < deadline:
            time.sleep(min(1.0, deadline - time.monotonic()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
