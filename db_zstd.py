"""Consistent zstd snapshots of a live SQLite database.

Shared by ``dbserver.py`` and ``webui/compress_db.py``.  A live SQLite file
cannot be copied safely while writes are in flight (especially in WAL mode),
so this takes a ``VACUUM INTO`` snapshot, compresses it, and atomically
replaces the output.

Python 3.14's ``compression.zstd`` is used when available; otherwise the
``zstd`` command-line tool is required.  No pip packages.
"""

from __future__ import annotations

import os
import shutil
import sqlite3
import subprocess
import tempfile
import time

try:
    from compression import zstd as _zstd   # Python 3.14+
except ImportError:
    _zstd = None

DEFAULT_LEVEL = 1


def zstd_available() -> bool:
    return _zstd is not None or shutil.which("zstd") is not None


def db_state(db_path: str):
    """Comparable (mtime_ns, size) tuple for the DB and its WAL.

    -shm changes with reader/writer locks and would force needless work.
    """
    parts = []
    for suffix in ("", "-wal"):
        try:
            st = os.stat(db_path + suffix)
            # An empty WAL carries no data; its mtime can change on
            # checkpoint even though the snapshot is still current.
            parts.append(None if (suffix == "-wal" and st.st_size == 0)
                         else (st.st_mtime_ns, st.st_size))
        except OSError:
            parts.append(None)
    return tuple(parts)


def _level(value) -> int:
    try:
        return max(1, min(int(value), 19))
    except Exception:
        return DEFAULT_LEVEL


def _compress_file(src: str, dst: str, level: int):
    """Stream ``src`` to ``dst``; the caller handles the atomic replace."""
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


def snapshot_and_compress(db_path: str, out_path: str,
                          level: int = DEFAULT_LEVEL,
                          timeout: float = 30.0):
    """Write a consistent compressed snapshot. Returns (db_bytes, zst_bytes,
    seconds). Raises on failure; the previous output is left untouched."""
    db_path = os.path.abspath(db_path)
    out_path = os.path.abspath(out_path)
    if not os.path.isfile(db_path):
        raise FileNotFoundError(db_path)
    out_dir = os.path.dirname(out_path) or "."
    os.makedirs(out_dir, exist_ok=True)
    started = time.monotonic()
    fd, snap = tempfile.mkstemp(prefix=".db-snapshot-", suffix=".db",
                                dir=out_dir)
    os.close(fd)
    os.unlink(snap)          # VACUUM INTO refuses an existing file
    try:
        uri = f"file:{db_path}?mode=ro"
        con = sqlite3.connect(uri, uri=True, timeout=timeout)
        try:
            con.execute("VACUUM INTO ?", (snap,))
        finally:
            con.close()
        before = os.path.getsize(snap)
        _compress_file(snap, out_path, _level(level))
        after = os.path.getsize(out_path)
        return before, after, time.monotonic() - started
    finally:
        try:
            os.unlink(snap)
        except OSError:
            pass
