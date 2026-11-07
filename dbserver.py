#!/usr/bin/env python3
"""Shared network DB server for the Minecraft Server Scanner.

Multiple scanner clients push their local ``servers.db`` rows here and pull
rows found by other clients with a single "Sync DB" press (Servers tab).

Run on a box you port-forward to the public internet:

    python3 dbserver.py --port 8777

The first run generates a random token, saves it (mode 0600) to
``.dbserver_token`` next to the database (or picks up a ``token.txt`` you
placed there yourself), and prints it.  Clients only need
two fields: the server URL (``http://your-host:8777``) and that token.

Security model (deliberately simple for non-technical users):

* EVERY ``/api/*`` endpoint requires authentication.  No reading or writing
  without it.  Unauthenticated requests get 401 and reveal nothing.
* Two auth schemes, same token (client GUI uses HMAC automatically):
    - ``Authorization: Bearer <token>`` -- trivial to use with curl.
    - HMAC challenge-response -- the token never travels on the wire:
      ``Authorization: HMAC <hex>`` plus ``X-Auth-Timestamp`` (unix seconds)
      and ``X-Auth-Nonce`` (random hex).  The signature is::

          HMAC-SHA256(token, METHOD + "\\n" + PATH + "\\n"
                             + TIMESTAMP + "\\n" + NONCE + "\\n"
                             + SHA256_HEX(body))

      PATH is the request path including query string (e.g. ``/api/sync``).
      Timestamps must be within +/- 300 s and nonces are single-use, which
      defeats passive replay.  The GUI client always uses this scheme.
* Brute-force throttle: 5 bad auth attempts from one IP within a minute
  triggers HTTP 429 for a minute.  Failed attempts are logged; the token
  itself is never logged.
* Request bodies are capped (default 25 MB) and every field is validated and
  length-capped before touching SQLite.
* Plain HTTP keeps setup trivial (no certificates for normies), but anyone
  on the path can SEE the traffic.  HMAC protects the *token* from passive
  sniffing, but a full active MITM on HTTP could still steal/replay *data*.
  If your server list is sensitive, put this behind HTTPS: drop cert.pem +
  privkey.pem in the server's working directory (auto-detected, then clients
  use ``https://...``), pass ``--tls-cert/--tls-key`` explicitly, or run
  behind a reverse proxy (Caddy/nginx) / Tailscale.

Protocol
--------
JSON replies are zstd- or gzip-compressed when the request advertises them
(zstd uses Python 3.14+ `compression.zstd`, else the `zstd` CLI when present;
gzip is the fallback).

* ``GET  /api/health``               -> ``{"ok": true, "servers": N, "notes": M, "format": 5, "now": T}``
* ``GET  /api/db``                   -> consistent compact SQLite snapshot
  (the whole database file, optionally zstd/gzip-compressed); the client
  derives row count/seq/format by opening it.  Used by
  ``mcscan.py --download-db``.
* ``GET  /api/servers?since=<ts>``   -> ``{"servers": [...], "now": T, "total": N}``
* ``POST /api/continuous`` ``{"node": "<id>"}``
  registers a continuous scanner for automatic sharding and returns its
  1-based shard index and the current node count::

      {"ok": true, "index": I, "total": N, "ttl": 30}

  Send ``"leave": true`` for an immediate clean-shutdown unregister.

* ``POST /api/sync`` ``{"servers": [...], "since": <ts>, "format": 5}``
  merges the upload, then returns rows with ``last_seen > since``. Formats
  older than 5 are rejected with HTTP 409 so every node updates its
  scanner/database before syncing again::

      {"servers": [...deltas...], "now": T, "merged": M, "total": N}

  Clients that know the seq protocol pass ``since_seq`` instead (and for
  ``GET``, ``?since_seq=N``): every insert/change bumps the row's ``seq``,
  so paging ``seq > since_seq`` can never miss rows that arrived with old
  ``last_seen`` timestamps. Replies carry ``"has_seq": true``.

* ``POST /api/history/sync``
  ``{"history": [...], "players": [...], "history_since": N, "player_since": N}``
  merges uploaded sightings and returns new shared rows with rowid
  cursors, so each client can page through the complete history::

      {"history": [...], "players": [...],
       "history_seq": N, "player_seq": N, "has_history": true}

  Each history row carries its sampled ``players`` roster blob.  The
  separate ``players`` event list remains only for old clients; their
  events are folded into the matching history row's blob.
  A missing endpoint on older servers is treated as "history unsupported";
  clients keep their rows unsynced for a later server upgrade.

* ``GET  /api/notes/db``             -> consistent SQLite snapshot of the
  separate notes database (same auth/compression as ``/api/db``).
* ``POST /api/notes/sync`` ``{"notes": [...], "since_seq": N}``
  uploads new notes/tombstones and returns notes with ``seq > since_seq``.
  The reply also includes the current state of every uploaded note id, so
  a client that attempted an edit or resurrection is corrected immediately.
  Note rows are ``{"id": "<uuid>", "ip_port": "...", "text": "..."|null,
  "created_at": T, "updated_at": T, "seq": N}``. Notes are write-once:
  different text for an existing id is ignored, and ``text=null`` is a
  permanent tombstone that cannot be resurrected by stale clients.

Row shape (mirrors the client's ``servers.db``)::

    {"ip_port": "1.2.3.4:25565", "host": "1.2.3.4", "port": 25565,
     "motd": "...", "players_online": 3, "max_players": 20,
     "version": "1.21", "protocol": 767, "cracked": 1,
     "whitelist": "...", "first_seen": 123.0, "last_seen": 456.0,
     "times_seen": 2, "last_source": "scan",
     "players_now": ["Alice"], "players_ever": ["Alice", "Bob"]}

Merge rule (both directions): ``first_seen`` = oldest non-zero,
``last_seen`` = newest.  The DB stores sightings in ``server_history`` and
derives those two fields in the ``servers`` view; sync endpoints are merged
into that history.  Mutable display fields (motd/players/version/...)
come from whichever side saw the server most recently, and a cracked
verdict only changes when a client runs an explicit cracked check or
whitelist probe; a plain status ping never changes an existing verdict.
``cracked`` is 1 / 0 / NULL (unset or unknown). ``times_seen`` = max + 1
when the incoming sighting is newer.
``players_now`` follows the newer sighting; ``players_ever`` is the union
of both sides (capped at 500 names per server).

Stdlib only -- no pip dependencies.
"""

import argparse
import gzip
import zlib
try:
    from compression import zstd as _zstd   # Python 3.14+
except ImportError:
    _zstd = None
import hashlib
import hmac
import ipaddress
import json
import math
import os
import re
import secrets
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

import db_format
import db_zstd

IP_PORT_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}:\d{1,5}$")
MAX_BODY_BYTES = 25 * 1024 * 1024
MAX_DECOMPRESSED_BODY_BYTES = 64 * 1024 * 1024
MAX_SERVERS_PER_REQUEST = 20000
MAX_SERVERS_PER_RESPONSE = 50000
MAX_HISTORY_PER_REQUEST = 100000
MAX_HISTORY_PER_RESPONSE = 100000
SQLITE_MAX_INT = 2 ** 63 - 1     # larger ints overflow the sqlite3 binding
MAX_TIMESTAMP = 1e18             # far beyond any real epoch, still finite
TIMESTAMP_SKEW = 300
NONCE_CACHE_MAX = 20000

PLAYERS_EVER_MAX = 500  # per-server cap on the ever-seen name list
PLAYER_NAME_MAX_LEN = 32
MAX_VARINT_VALUE = 0x7FFFFFFF
CONTINUOUS_TTL = 30.0        # seconds without a heartbeat before a node expires
CONTINUOUS_HEARTBEAT = 10.0  # suggested client heartbeat interval
MAX_NOTES_PER_REQUEST = 20000
MAX_NOTES_PER_RESPONSE = 50000
MAX_NOTE_CHARS = 4000

NOTES_SCHEMA = (
    "CREATE TABLE IF NOT EXISTS notes ("
    " id TEXT PRIMARY KEY,"
    " ip_port TEXT NOT NULL,"
    " text TEXT,"
    " created_at REAL DEFAULT 0,"
    " updated_at REAL DEFAULT 0,"
    " seq INTEGER DEFAULT 0"
    ")"
)

_db_lock = threading.Lock()
_continuous_lock = threading.Lock()
_continuous_nodes = {}  # node id -> monotonic last heartbeat
_nonce_lock = threading.Lock()
_seen_nonces = {}  # nonce -> expiry timestamp
_fail_lock = threading.Lock()
_auth_failures = {}  # ip -> {"count": int, "window_start": float, "banned_until": float}


def _utcnow():
    return time.time()


def register_continuous(node_id, leave=False):
    """Register/heartbeat a continuous scanner; return its 1-based shard.

    Nodes are ordered by registration time: adding a node appends a slot and
    does not disturb existing indices. Removing one compacts the slots after
    it, so the remaining shards still cover 1..N. Expired nodes are pruned
    first. Returns {"index", "total"} (or {"left": ...} on leave).
    """
    now = time.monotonic()
    with _continuous_lock:
        expired = [node for node, last in _continuous_nodes.items()
                   if now - last > CONTINUOUS_TTL]
        for node in expired:
            _continuous_nodes.pop(node, None)
        if leave:
            left = _continuous_nodes.pop(node_id, None) is not None
            total = len(_continuous_nodes)
            return {"left": left, "index": 0, "total": total}
        _continuous_nodes[node_id] = now
        nodes = list(_continuous_nodes)
        total = len(nodes)
        index = nodes.index(node_id) + 1
    return {"index": index, "total": total}


# --------------------------------------------------------------------------- #
# Token handling
# --------------------------------------------------------------------------- #

def _read_token_file(path):
    """First non-empty line of a token file, or None."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                tok = line.strip()
                if tok:
                    return tok
    except OSError:
        pass
    return None


def load_or_create_token(token_file, explicit=None):
    """Return the shared secret, creating+persisting one on first run.

    Precedence: --token flag, $DBSERVER_TOKEN, the --token-file value when
    it exists, token.txt when found (auto-detected, read-only), then the
    --token-file value with a freshly generated token.
    Returns (token, source-description).
    """
    if explicit:
        return explicit.strip(), "--token flag"
    env = os.environ.get("DBSERVER_TOKEN", "").strip()
    if env:
        return env, "$DBSERVER_TOKEN"
    if token_file:
        tok = _read_token_file(token_file) if os.path.exists(token_file) else None
        if tok:
            return tok, token_file
    if os.path.exists("token.txt"):
        tok = _read_token_file("token.txt")
        if tok:
            return tok, "token.txt"
    tok = secrets.token_urlsafe(32)
    if token_file:
        try:
            fd = os.open(token_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(tok + "\n")
            try:
                os.chmod(token_file, 0o600)
            except OSError:
                pass
        except OSError as exc:
            print(f"WARNING: could not persist token to {token_file}: {exc}",
                  file=sys.stderr)
    return tok, f"{token_file} (generated)"


# --------------------------------------------------------------------------- #
# Database
# --------------------------------------------------------------------------- #

def db_connect(db_path):
    con = sqlite3.connect(db_path, timeout=10)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA synchronous=NORMAL")
    return con


_SQL_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _safe_sql_ident(name):
    """Identifier for DDL interpolation: bare [A-Za-z0-9_] only.

    SQLite cannot bind table/column names, so anything interpolated into
    PRAGMA/ALTER must be whitelisted, never escaped.
    """
    text = str(name or "")
    if not _SQL_IDENT_RE.match(text):
        raise ValueError(f"unsafe SQL identifier: {name!r}")
    return text


def _add_column_if_missing(con, column, ddl):
    """Migration helper; see _safe_sql_ident (migrations are not user input)."""
    try:
        column = _safe_sql_ident(column)
        ddl = str(ddl or "")
        if not re.fullmatch(r"[A-Za-z0-9_ ()\[\]'.,+-]+", ddl):
            return
        base = db_format.base_table(con)
        existing = {row[1] for row in con.execute(f"PRAGMA table_info({base})")}
        if column not in existing:
            con.execute(f"ALTER TABLE {base} ADD COLUMN {column} {ddl}")
            return True
    except Exception:
        pass
    return False


def cleanup_stale_snapshots(db_path):
    """Remove snapshot temps left by a previous killed/crashed process."""
    directory = os.path.dirname(os.path.abspath(db_path)) or "."
    try:
        names = os.listdir(directory)
    except OSError:
        return
    for name in names:
        if not name.startswith(".mc-netdb-"):
            continue
        try:
            os.unlink(os.path.join(directory, name))
        except OSError:
            pass


def init_db(db_path):
    cleanup_stale_snapshots(db_path)
    con = db_connect(db_path)
    try:
        # Creates the current state table/history, or migrates an older DB.
        db_format.ensure_format(con)
        base = db_format.base_table(con)
        # Transport cursor for sync: every insert/change gets a fresh seq, so
        # clients page by seq (not wall-clock) and can never miss rows that
        # arrived with old last_seen timestamps.
        added = _add_column_if_missing(con, "seq", "INTEGER DEFAULT 0")
        added |= _add_column_if_missing(con, "players_now", "TEXT DEFAULT '[]'")
        added |= _add_column_if_missing(con, "players_ever", "TEXT DEFAULT '[]'")
        try:
            con.execute(f"UPDATE {base} SET seq=rowid"
                        " WHERE seq IS NULL OR seq=0")
        except Exception:
            pass
        con.execute(f"CREATE INDEX IF NOT EXISTS idx_server_state_seq"
                    f" ON {base}(seq ASC)")
        # The server is the sync source; its history must not be marked as
        # pending upload when a client downloads the DB file.
        try:
            con.execute("UPDATE server_history SET synced=1 WHERE synced=0")
        except Exception:
            pass
        db_format.ensure_view(con, recreate=added)
        con.commit()
        # Server DBs live on a fast host; reclaim pages freed by index
        # migration there.  Do not do this in the shared helper: scanner
        # nodes (Raspberry Pi/SD cards) would stall at sync startup.
        db_format.vacuum_if_bloated(con)
    finally:
        con.close()


def notes_db_connect(db_path):
    con = db_connect(db_path)
    try:
        con.execute("PRAGMA secure_delete=ON")
    except Exception:
        pass
    return con


def init_notes_db(db_path):
    cleanup_stale_snapshots(db_path)
    con = notes_db_connect(db_path)
    try:
        con.execute(NOTES_SCHEMA)
        con.execute("CREATE INDEX IF NOT EXISTS idx_notes_seq "
                    "ON notes(seq ASC)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_notes_ip "
                    "ON notes(ip_port)")
        con.commit()
        # Reclaim any text left behind by tombstones or old deletes.
        try:
            con.execute("VACUUM")
        except Exception:
            pass
    finally:
        con.close()
    try:
        os.chmod(db_path, 0o600)
    except OSError:
        pass


def _canonical_uuid(value):
    try:
        return str(uuid.UUID(str(value or "").strip()))
    except Exception:
        return None


def sanitize_note(raw):
    """Validate one note. text=None is a deletion tombstone."""
    if not isinstance(raw, dict):
        return None
    note_id = _canonical_uuid(raw.get("id"))
    if not note_id:
        return None
    ip_port = str(raw.get("ip_port", "")).strip()
    if not IP_PORT_RE.match(ip_port):
        return None
    try:
        ipaddress.ip_address(ip_port.rsplit(":", 1)[0])
        port = int(ip_port.rsplit(":", 1)[1])
        if not 0 < port < 65536:
            return None
    except Exception:
        return None
    text = raw.get("text", None)
    if text is not None:
        text = str(text)[:MAX_NOTE_CHARS].strip()
        if not text:
            return None
    now = _utcnow()

    def ts(value, default):
        try:
            value = float(value or 0)
        except Exception:
            return default
        if value <= 0 or value > now + 86400:
            return default
        return value

    return {
        "id": note_id,
        "ip_port": ip_port,
        "text": text,
        "created_at": ts(raw.get("created_at"), now),
        "updated_at": ts(raw.get("updated_at"), now),
    }


def merge_note(con, note):
    """Upsert one note. Existing text is immutable; deletion is final."""
    old = con.execute(
        "SELECT ip_port, text, updated_at FROM notes WHERE id=?",
        (note["id"],)).fetchone()
    if old is None:
        con.execute(
            "INSERT INTO notes (id, ip_port, text, created_at, updated_at,"
            " seq) VALUES (?, ?, ?, ?, ?,"
            " (SELECT COALESCE(MAX(seq), 0) + 1 FROM notes))",
            (note["id"], note["ip_port"], note["text"],
             note["created_at"], note["updated_at"]))
        return True
    old_ip, old_text, old_updated = old[0], old[1], old[2]
    if old_ip != note["ip_port"]:
        return False
    if old_text is None:
        # A deleted note can never be resurrected by an outdated client.
        return False
    if note["text"] is not None:
        # Notes are write-once.  A different text is an edit attempt; the
        # first stored copy wins.
        return False
    try:
        updated = max(float(old_updated or 0), float(note["updated_at"] or 0))
    except Exception:
        updated = note["updated_at"]
    con.execute(
        "UPDATE notes SET text=NULL, updated_at=?,"
        " seq=(SELECT COALESCE(MAX(seq), 0) + 1 FROM notes)"
        " WHERE id=?", (updated, note["id"]))
    return True


def _clamp_seq(value):
    """Query cursor -> [0, sqlite INTEGER max], or None when unparseable."""
    try:
        v = int(value)
    except Exception:
        return None
    return max(0, min(v, SQLITE_MAX_INT))


def _clamp_ts(value):
    """Query timestamp -> finite non-negative float (0.0 when unusable)."""
    try:
        v = float(value)
    except Exception:
        return 0.0
    if math.isnan(v) or math.isinf(v):
        return 0.0
    return max(0.0, min(v, MAX_TIMESTAMP))


def _clamp_str(value, limit):
    """Server text -> stored text. Preserve every character; cap length.

    Display hardening (control/ANSI/bidi escaping, newline flattening) is
    the viewer's job so synced rows are stored byte-for-byte as reported.
    """
    s = "" if value is None else str(value)
    return s[:limit]


def decode_request_body(raw, encoding):
    """Decode a gzip request body with a hard decompressed-size limit."""
    encoding = (encoding or "").strip().lower()
    if not encoding or encoding == "identity":
        return raw
    if encoding != "gzip":
        raise ValueError(f"unsupported Content-Encoding: {encoding}")
    dec = zlib.decompressobj(16 + zlib.MAX_WBITS)
    out = dec.decompress(raw, MAX_DECOMPRESSED_BODY_BYTES + 1)
    if len(out) > MAX_DECOMPRESSED_BODY_BYTES or dec.unconsumed_tail:
        raise ValueError("request body too large")
    out += dec.flush()
    if len(out) > MAX_DECOMPRESSED_BODY_BYTES:
        raise ValueError("request body too large")
    return out


def _clean_player_name(value):
    try:
        s = "" if value is None else str(value)
        s = s[:PLAYER_NAME_MAX_LEN]
        if s and db_format.is_spoofed_player_name(s):
            return ""
        return s
    except Exception:
        return ""


def _clean_player_list(value):
    """Incoming players_now/players_ever (list or JSON string) -> JSON string.

    Sorted, unique, capped. Never raises.
    """
    try:
        if isinstance(value, str):
            parsed = json.loads(value) if value.strip() else []
        else:
            parsed = value
        if not isinstance(parsed, list):
            return None
        names = sorted({_clean_player_name(n) for n in parsed} -
                       {""}, key=str.lower)
        if not names:
            return None
        return json.dumps(names[:PLAYERS_EVER_MAX], ensure_ascii=False)
    except Exception:
        return None


def _merge_player_lists(old, new):
    """Union of two stored JSON lists, capped. Never raises.

    Established (old) names always win: newcomers only fill remaining
    slots, so a flood of junk names can never evict names already known.
    """
    try:
        old_list = json.loads(old or "[]")
        new_list = json.loads(new or "[]")
        if not isinstance(old_list, list):
            old_list = []
        if not isinstance(new_list, list):
            new_list = []
        seen = set(old_list)
        merged = list(old_list)
        for name in sorted(set(new_list) - seen, key=str.lower):
            if len(merged) >= PLAYERS_EVER_MAX:
                break
            merged.append(name)
        return _clean_player_list(merged)
    except Exception:
        return None


def _valid_ip_port(value):
    ip_port = str(value or "").strip()
    if not IP_PORT_RE.match(ip_port):
        return None
    try:
        host, raw_port = ip_port.rsplit(":", 1)
        ipaddress.ip_address(host)
        port = int(raw_port)
        if not 0 < port < 65536:
            return None
    except Exception:
        return None
    return ip_port


def _history_count(value):
    if value is None or value == "":
        return None
    try:
        return max(0, min(int(value), 1000000))
    except Exception:
        return None


def sanitize_history_row(raw, now=None, cutoff=None):
    """Validate one uploaded sighting. Returns dict or None."""
    if not isinstance(raw, dict):
        return None
    ip_port = _valid_ip_port(raw.get("ip_port"))
    if not ip_port:
        return None
    try:
        seen_at = float(raw.get("seen_at", 0) or 0)
    except Exception:
        return None
    now = now or _utcnow()
    if seen_at <= 0 or seen_at > now + 86400:
        return None
    if cutoff is not None and seen_at < cutoff:
        return None
    return {
        "ip_port": ip_port,
        "seen_at": seen_at,
        "players_online": _history_count(raw.get("players_online")),
        "max_players": _history_count(raw.get("max_players")),
        "players": db_format.encode_player_blob(raw.get("players")),
    }


def sanitize_player_event(raw, now=None, cutoff=None):
    """Validate one uploaded player sighting. Returns dict or None."""
    if not isinstance(raw, dict):
        return None
    ip_port = _valid_ip_port(raw.get("ip_port"))
    name = _clean_player_name(raw.get("player_name")).strip()
    if (not ip_port or not name
            or db_format.is_anonymous_player_name(name)):
        return None
    try:
        seen_at = float(raw.get("seen_at", 0) or 0)
    except Exception:
        return None
    now = now or _utcnow()
    if seen_at <= 0 or seen_at > now + 86400:
        return None
    if cutoff is not None and seen_at < cutoff:
        return None
    return {"ip_port": ip_port, "player_name": name, "seen_at": seen_at}


def sanitize_row(raw):
    """Validate + normalize one incoming row. Returns dict or None."""
    if not isinstance(raw, dict):
        return None
    ip_port = str(raw.get("ip_port", "")).strip()
    if not IP_PORT_RE.match(ip_port):
        return None
    try:
        parts = ip_port.rsplit(":", 1)
        ipaddress.ip_address(parts[0])
        port = int(parts[1])
        if not 0 < port < 65536:
            return None
    except Exception:
        return None
    try:
        port = int(raw.get("port", port))
        if not 0 < port < 65536:
            port = int(ip_port.rsplit(":", 1)[1])
    except Exception:
        port = int(ip_port.rsplit(":", 1)[1])
    try:
        online = max(0, int(raw.get("players_online", 0)))
    except Exception:
        online = 0
    try:
        maximum = max(0, int(raw.get("max_players", 0)))
    except Exception:
        maximum = 0
    try:
        protocol = raw.get("protocol")
        protocol = None if protocol is None else int(protocol)
        if protocol is not None and not (0 <= protocol <= MAX_VARINT_VALUE):
            protocol = None
    except Exception:
        protocol = None
    try:
        first_seen = float(raw.get("first_seen", 0) or 0)
    except Exception:
        first_seen = 0.0
    try:
        last_seen = float(raw.get("last_seen", 0) or 0)
    except Exception:
        last_seen = 0.0
    now = _utcnow()
    # Reject absurd timestamps (far future); clamp negatives to 0.
    if first_seen < 0:
        first_seen = 0.0
    if last_seen < 0:
        last_seen = 0.0
    if first_seen > now + 86400 or last_seen > now + 86400:
        return None
    try:
        times_seen = max(1, int(raw.get("times_seen", 1)))
    except Exception:
        times_seen = 1
    return {
        "ip_port": ip_port,
        "host": None,
        "port": port,
        "motd": _clamp_str(raw.get("motd", ""), 500),
        "players_online": min(online, 1000000),
        "max_players": min(maximum, 1000000),
        "version": _clamp_str(raw.get("version", ""), 100),
        "protocol": protocol,
        "cracked": db_format.cracked_state(raw.get("cracked")),
        "whitelist": _clamp_str(raw.get("whitelist", ""), 200),
        "first_seen": first_seen,
        "last_seen": last_seen,
        "times_seen": min(times_seen, 1000000000),
        "last_source": _clamp_str(raw.get("last_source", ""), 64),
        "players_now": _clean_player_list(raw.get("players_now")),
        "players_ever": _clean_player_list(raw.get("players_ever")),
    }


def merge_row(con, row):
    """Upsert one sanitized row. Returns True if it created/advanced state."""
    cur = con.execute(
        "SELECT motd, players_online, max_players, version, protocol,"
        " cracked, whitelist, first_seen, last_seen, times_seen, last_source,"
        " players_now, players_ever"
        " FROM servers WHERE ip_port=?", (row["ip_port"],))
    old = cur.fetchone()
    if old is None:
        con.execute(
            "INSERT INTO server_state (ip_port, host, port, motd,"
            " players_online, max_players, version, protocol, cracked,"
            " whitelist, times_seen, last_source, players_now, players_ever,"
            " seq)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,"
            " (SELECT COALESCE(MAX(seq), 0) + 1 FROM server_state))",
            (row["ip_port"], None, row["port"], row["motd"],
             row["players_online"], row["max_players"], row["version"],
             row["protocol"],
             row["cracked"] if row["last_source"] == "cracked" else None,
             row["whitelist"],
             row["times_seen"], row["last_source"],
             row["players_now"], row["players_ever"]))
        fallback_now = _utcnow()
        db_format.insert_range(
            con, row["ip_port"],
            row["first_seen"] or row["last_seen"] or fallback_now,
            row["last_seen"] or row["first_seen"] or fallback_now,
            row["players_online"], row["max_players"],
            db_format.name_list(row["players_now"]), (), synced=1)
        return True
    (o_motd, o_on, o_max, o_ver, o_proto, o_cracked, o_wl,
     o_first, o_last, o_times, o_src, o_now, o_ever) = old
    try:
        o_first = float(o_first or 0)
    except Exception:
        o_first = 0.0
    try:
        o_last = float(o_last or 0)
    except Exception:
        o_last = 0.0
    try:
        o_times = int(o_times or 1)
    except Exception:
        o_times = 1
    incoming_newer = row["last_seen"] > o_last
    first_seen = row["first_seen"] or o_first
    if o_first and row["first_seen"]:
        first_seen = min(o_first, row["first_seen"])
    elif o_first:
        first_seen = o_first
    last_seen = max(o_last, row["last_seen"])
    if incoming_newer:
        motd, online, maximum = row["motd"], row["players_online"], row["max_players"]
        version, protocol = row["version"], row["protocol"]
        src = row["last_source"] or o_src
    else:
        motd, online, maximum = o_motd, o_on, o_max
        version, protocol = o_ver, o_proto
        src = o_src
        if protocol is None:
            protocol = row["protocol"]
    # Only an explicit cracked check or a whitelist probe may change an
    # existing verdict.  A plain sighting never changes it, in either
    # direction.  New rows still take the incoming value below.
    authoritative = db_format.source_is_cracked_verdict(
        row.get("last_source"))
    if authoritative and incoming_newer:
        cracked = row["cracked"]
    else:
        # Keep 0, 1, and the unset/NULL state.
        cracked = o_cracked
    if (db_format.source_is_cracked_verdict(o_src)
            and not db_format.source_is_cracked_verdict(src)):
        src = o_src
    if incoming_newer and row["whitelist"]:
        whitelist = row["whitelist"]
    else:
        whitelist = o_wl or row["whitelist"]
    times_seen = max(o_times, row["times_seen"])
    if incoming_newer:
        times_seen += 1
    # Player lists: current roster follows the newer sighting; ever-seen is
    # the union of both sides (capped). Fold each side's current roster into
    # its ever list first, so no observed name is ever lost.
    now = row["players_now"] if incoming_newer else (o_now or None)
    ever = _merge_player_lists(
        _merge_player_lists(o_ever, o_now), _merge_player_lists(row["players_ever"], row["players_now"]))
    if (motd, online, maximum, version, protocol, cracked, whitelist,
            first_seen, last_seen, times_seen, src, now, ever) == (
            o_motd, o_on, o_max, o_ver, o_proto, o_cracked, o_wl,
            o_first, o_last, o_times, o_src, o_now, o_ever):
        return False
    con.execute(
        "UPDATE server_state SET host=?, port=?, motd=?, players_online=?,"
        " max_players=?, version=?, protocol=?, cracked=?, whitelist=?,"
        " times_seen=?, last_source=?, players_now=?, players_ever=?,"
        " seq=(SELECT COALESCE(MAX(seq), 0) + 1 FROM server_state)"
        " WHERE ip_port=?",
        (None, row["port"], motd, online, maximum, version, protocol,
         cracked, whitelist, times_seen, src,
         now, ever, row["ip_port"]))
    db_format.insert_range(
        con, row["ip_port"], row["first_seen"], row["last_seen"],
        row["players_online"], row["max_players"],
        db_format.name_list(row["players_now"]), (), synced=1)
    return True


# --------------------------------------------------------------------------- #
# Auth
# --------------------------------------------------------------------------- #

def _client_ip(handler):
    try:
        return handler.client_address[0]
    except Exception:
        return "?"


def _throttled(ip):
    now = _utcnow()
    with _fail_lock:
        st = _auth_failures.get(ip)
        if not st:
            return False
        if st.get("banned_until", 0) > now:
            return True
        # Expire old windows.
        if now - st.get("window_start", now) > 60:
            _auth_failures.pop(ip, None)
            return False
        return False


def _record_auth_result(ip, ok):
    now = _utcnow()
    with _fail_lock:
        if ok:
            _auth_failures.pop(ip, None)
            return
        st = _auth_failures.get(ip)
        if not st or now - st.get("window_start", now) > 60:
            st = {"count": 0, "window_start": now, "banned_until": 0}
        st["count"] += 1
        if st["count"] >= 5:
            st["banned_until"] = now + 60
        _auth_failures[ip] = st


def _prune_nonces():
    now = _utcnow()
    with _nonce_lock:
        if len(_seen_nonces) > NONCE_CACHE_MAX:
            expired = [k for k, exp in _seen_nonces.items() if exp < now]
            for k in expired:
                _seen_nonces.pop(k, None)
            # Still too big: drop oldest.
            while len(_seen_nonces) > NONCE_CACHE_MAX:
                _seen_nonces.pop(next(iter(_seen_nonces)))
        else:
            for k in [k for k, exp in list(_seen_nonces.items()) if exp < now]:
                _seen_nonces.pop(k, None)


_ZSTD_CLI = shutil.which("zstd")
_ZSTD_WORKERS = min(4, max(1, os.cpu_count() or 1))


def _zstd_available():
    return _zstd is not None or bool(_ZSTD_CLI)


def _zstd_options(size):
    workers = _ZSTD_WORKERS if size >= (1 << 20) else 1
    return {
        _zstd.CompressionParameter.compression_level: 3,
        _zstd.CompressionParameter.nb_workers: workers,
    }


def _zstd_cli_run(args, data=None):
    kwargs = {}
    if os.name == "nt":
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    return subprocess.run(
        [_ZSTD_CLI] + args, input=data, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, check=True, timeout=60, **kwargs).stdout


def _zstd_compress_bytes(data):
    if _zstd is not None:
        return _zstd.compress(data, options=_zstd_options(len(data)))
    workers = _ZSTD_WORKERS if len(data) >= (1 << 20) else 1
    return _zstd_cli_run(["-3", "-q", f"-T{workers}", "-c"], data)


def _zstd_compress_file(src, dst):
    size = os.path.getsize(src)
    if _zstd is not None:
        with open(src, "rb") as fin:
            with _zstd.ZstdFile(dst, "w", options=_zstd_options(size)) as fout:
                shutil.copyfileobj(fin, fout, length=1024 * 1024)
    else:
        workers = _ZSTD_WORKERS if size >= (1 << 20) else 1
        _zstd_cli_run(["-3", "-q", "-f", f"-T{workers}", "-o", dst, src])


def _pick_encoding(accept_header):
    """Best response compression this Python/host and the client both support."""
    accept = (accept_header or "").lower()
    if _zstd_available() and "zstd" in accept:
        return "zstd"
    if "gzip" in accept:
        return "gzip"
    return None


def check_auth(handler, body, token):
    """Validate Bearer or HMAC auth. Returns (ok, scheme)."""
    if not token:
        return False, "none"
    auth = (handler.headers.get("Authorization") or "").strip()
    if auth.startswith("Bearer "):
        given = auth[len("Bearer "):].strip()
        ok = bool(given) and hmac.compare_digest(given, token)
        return ok, "bearer"
    if auth.startswith("HMAC "):
        sig = auth[len("HMAC "):].strip()
        ts_raw = (handler.headers.get("X-Auth-Timestamp") or "").strip()
        nonce = (handler.headers.get("X-Auth-Nonce") or "").strip()
        try:
            ts = float(ts_raw)
        except Exception:
            return False, "hmac"
        now = _utcnow()
        if abs(now - ts) > TIMESTAMP_SKEW:
            return False, "hmac"
        if not nonce or len(nonce) > 128 or not re.fullmatch(r"[0-9a-fA-F]+", nonce):
            return False, "hmac"
        _prune_nonces()
        with _nonce_lock:
            if nonce in _seen_nonces:
                return False, "hmac"
        body_hash = hashlib.sha256(body or b"").hexdigest()
        # PATH includes query string so signed GETs can't be retargeted.
        path = handler.path.split(" ", 1)[0]
        msg = "\n".join([handler.command.upper(), path, ts_raw, nonce, body_hash])
        expect = hmac.new(token.encode("utf-8"), msg.encode("utf-8"),
                          hashlib.sha256).hexdigest()
        ok = bool(sig) and hmac.compare_digest(sig.lower(), expect.lower())
        if ok:
            with _nonce_lock:
                _seen_nonces[nonce] = now + TIMESTAMP_SKEW + 60
        return ok, "hmac"
    return False, "none"


# --------------------------------------------------------------------------- #
# HTTP handler
# --------------------------------------------------------------------------- #

class ZstdSnapshotWriter:
    """Keep a compressed snapshot current without blocking request handlers.

    Writers only call notify(); a background thread coalesces bursts (the
    continuous scanners write constantly) and writes the snapshot after a
    short quiet period, with a maximum delay so a busy server still gets
    fresh files.
    """

    def __init__(self, db_path, out_path, level=1, debounce=2.0,
                 max_wait=30.0):
        self.db_path = os.path.abspath(db_path)
        self.out_path = os.path.abspath(out_path)
        self.level = level
        self.debounce = max(0.2, float(debounce))
        self.max_wait = max(self.debounce, float(max_wait))
        self._event = threading.Event()
        self._stop = threading.Event()
        self._thread = None
        self._available = db_zstd.zstd_available()
        self._last_error = ""
        self.meta_path = self.out_path + ".json"

    def _history_seq(self):
        try:
            con = db_connect(self.db_path)
            try:
                return int(con.execute(
                    "SELECT COALESCE(MAX(rowid), 0)"
                    " FROM server_history").fetchone()[0] or 0)
            finally:
                con.close()
        except Exception:
            return 0

    def _write_meta(self, meta):
        tmp = self.meta_path + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(meta, f, separators=(",", ":"))
            try:
                os.chmod(tmp, 0o644)
            except OSError:
                pass
            os.replace(tmp, self.meta_path)
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass

    def start(self):
        if not self._available:
            print("web db snapshot: zstd not available; compression disabled",
                  file=sys.stderr)
            return
        self._thread = threading.Thread(
            target=self._run, name="db-zstd-snapshot", daemon=True)
        self._thread.start()
        self.notify()

    def notify(self):
        if self._available:
            self._event.set()

    def stop(self):
        self._stop.set()
        self._event.set()
        if self._thread is not None:
            try:
                self._thread.join(timeout=5.0)
            except Exception:
                pass
            self._thread = None

    def _run(self):
        while not self._stop.is_set():
            if not self._event.wait(1.0):
                continue
            self._event.clear()
            quiet_start = time.monotonic()
            # Coalesce a burst of writes, but never defer forever while a
            # continuous scanner is uploading every few seconds.
            while not self._stop.is_set():
                if self._event.wait(self.debounce):
                    self._event.clear()
                    if time.monotonic() - quiet_start >= self.max_wait:
                        break
                    continue
                break
            if self._stop.is_set():
                break
            try:
                try:
                    removed = prune_database_history(self.db_path)
                    if removed:
                        print(f"web db snapshot: pruned {removed} old "
                              f"sighting(s)", flush=True)
                except Exception as exc:
                    print(f"web db snapshot: history prune failed: {exc}",
                          file=sys.stderr, flush=True)
                source_state = db_zstd.db_state(self.db_path)
                history_seq = self._history_seq()
                before, after, seconds = db_zstd.snapshot_and_compress(
                    self.db_path, self.out_path, level=self.level)
                self._write_meta({
                    "db_state": source_state,
                    "history_seq": history_seq,
                    "player_seq": 0,
                    "db_size": before,
                    "zst_size": after,
                    "created": time.time(),
                })
                self._last_error = ""
                print(f"web db snapshot: {os.path.basename(self.out_path)} "
                      f"{before / 1048576:.1f} MB -> "
                      f"{after / 1048576:.1f} MB in {seconds:.1f}s",
                      flush=True)
            except Exception as exc:
                msg = str(exc)
                if msg != self._last_error:
                    self._last_error = msg
                    print(f"web db snapshot: {msg}", file=sys.stderr,
                          flush=True)


HISTORY_PRUNE_INTERVAL = 3600
_last_history_prune = 0.0
_history_prune_lock = threading.Lock()


def prune_database_history(db_path, force=False):
    """Drop sighting history beyond the 4-day retention window.

    Seen names live on server_state.players_ever and are untouched.  The
    snapshot writer calls this hourly in the background.
    """
    global _last_history_prune
    now = time.time()
    if not force and now - _last_history_prune < HISTORY_PRUNE_INTERVAL:
        return 0
    with _history_prune_lock:
        now = time.time()
        if not force and now - _last_history_prune < HISTORY_PRUNE_INTERVAL:
            return 0
        with _db_lock:
            con = db_connect(db_path)
            try:
                if _last_history_prune == 0.0:
                    # One-time cleanup of legacy high-resolution rows.
                    stats = db_format.prune_activity(con)
                    removed = (int(stats.get("removed_old", 0))
                               + int(stats.get("thinned", 0)))
                else:
                    removed = db_format.prune_history(con)
                con.commit()
            finally:
                con.close()
        _last_history_prune = time.time()
        return removed


def dedupe_database(db_path):
    """Merge same-host duplicate ports and compact the shared DB."""
    with _db_lock:
        con = db_connect(db_path)
        try:
            stats = db_format.deduplicate_ports(con, mark_dirty=False)
            con.commit()
        except Exception:
            con.rollback()
            raise
        finally:
            con.close()
        if stats.get("removed_state"):
            con = db_connect(db_path)
            try:
                con.execute("VACUUM")
            finally:
                con.close()
    return stats


class PortDeduper:
    """Keep the shared DB compact without blocking request handlers forever."""

    def __init__(self, db_path, interval, writer=None):
        self.db_path = db_path
        self.interval = max(1.0, float(interval))
        self.writer = writer
        self._stop = threading.Event()
        self._thread = None

    def start(self):
        self._thread = threading.Thread(
            target=self._run, name="db-port-deduper", daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread is not None:
            try:
                self._thread.join(timeout=10.0)
            except Exception:
                pass
            self._thread = None

    def _run(self):
        while not self._stop.is_set():
            try:
                stats = dedupe_database(self.db_path)
                if stats.get("removed_state"):
                    print(
                        f"port dedupe: {stats['groups']} groups, "
                        f"{stats['removed_state']} server rows, "
                        f"{stats['removed_history']} history rows removed",
                        flush=True)
                    if self.writer is not None:
                        self.writer.notify()
            except Exception as exc:
                print(f"port dedupe failed: {exc}", file=sys.stderr,
                      flush=True)
            if self._stop.wait(self.interval):
                break


class Handler(BaseHTTPRequestHandler):
    server_version = "MCNetDB/1.0"

    def log_message(self, fmt, *args):
        try:
            text = fmt % args
        except Exception:
            text = str(fmt)
        if "Bad request version" in text or "Bad request syntax" in text:
            text = "400 bad request (non-HTTP or TLS on the HTTP port)"
        # Never send raw request bytes to the journal: a TLS ClientHello or
        # malformed request would otherwise show up as [blob data] noise.
        text = re.sub(r"[^\x20-\x7e]", "?", text)
        text = text.replace("\n", " ").replace("\r", " ")[:300]
        sys.stderr.write("%s - %s\n" % (_client_ip(self), text))

    def _send_json(self, code, obj):
        raw = json.dumps(obj).encode("utf-8")
        encoding = _pick_encoding(self.headers.get("Accept-Encoding"))
        if len(raw) >= 1024 and encoding:
            try:
                if encoding == "zstd":
                    raw = _zstd_compress_bytes(raw)
                else:
                    raw = gzip.compress(raw, 6)
            except Exception:
                if encoding == "zstd":
                    try:
                        raw = gzip.compress(raw, 6)
                        encoding = "gzip"
                    except Exception:
                        encoding = None
                else:
                    encoding = None
        else:
            encoding = None
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        if encoding:
            self.send_header("Content-Encoding", encoding)
            self.send_header("Vary", "Accept-Encoding")
        self.end_headers()
        try:
            self.wfile.write(raw)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _read_body(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except Exception:
            length = 0
        if length <= 0:
            return b""
        if length > MAX_BODY_BYTES:
            return None
        remaining = length
        chunks = []
        while remaining > 0:
            chunk = self.rfile.read(min(remaining, 65536))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def _require_sync_format(self, payload):
        """Reject sync clients that predate the current DB format."""
        try:
            client_format = int(payload.get("format", 0) or 0)
        except Exception:
            client_format = 0
        if client_format >= db_format.CURRENT_FORMAT:
            return True
        self._send_json(409, {
            "error": (f"shared DB format {db_format.CURRENT_FORMAT} required; "
                      "update the scanner and run 'mcscan.py "
                      "--download-db' before syncing"),
            "format": db_format.CURRENT_FORMAT,
            "client_format": client_format,
        })
        return False

    def _require_auth(self, body):
        ip = _client_ip(self)
        if _throttled(ip):
            self._send_json(429, {"error": "too many failed attempts, try again later"})
            return False
        ok, _scheme = check_auth(self, body, self.server.shared_token)
        _record_auth_result(ip, ok)
        if not ok:
            self.send_response(401)
            self.send_header("WWW-Authenticate", "Bearer")
            self.send_header("Content-Type", "application/json")
            raw = b'{"error": "unauthorized"}'
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            try:
                self.wfile.write(raw)
            except (BrokenPipeError, ConnectionResetError):
                pass
            return False
        return True

    def _cached_db_snapshot(self, db_path):
        """Metadata for a fresh precompressed servers snapshot, or None."""
        cached = getattr(self.server, "web_db_zst", "")
        if not cached:
            return None
        try:
            if os.path.abspath(db_path) != os.path.abspath(self.server.db_path):
                return None
        except Exception:
            return None
        accept = (self.headers.get("Accept-Encoding") or "").lower()
        if "zstd" not in accept:
            return None
        try:
            if not os.path.isfile(cached):
                return None
            with open(cached + ".json", "r", encoding="utf-8") as f:
                meta = json.load(f)
            zst_size = int(meta.get("zst_size") or 0)
            if zst_size <= 0 or os.path.getsize(cached) != zst_size:
                return None
            saved = meta.get("db_state")
            if saved is not None:
                saved = tuple(tuple(x) if x is not None else None
                              for x in saved)
            if saved != db_zstd.db_state(db_path):
                return None
            meta["zst_size"] = zst_size
            meta["history_seq"] = int(meta.get("history_seq") or 0)
            meta["player_seq"] = int(meta.get("player_seq") or 0)
            meta["db_size"] = int(meta.get("db_size") or 0)
            return meta
        except Exception:
            return None

    def _send_sqlite_snapshot(self, db_path, filename):
        cached = self._cached_db_snapshot(db_path)
        if cached is not None:
            cached_path = self.server.web_db_zst
            try:
                f = open(cached_path, "rb")
                try:
                    size = int(cached.get("zst_size") or 0)
                    self.send_response(200)
                    self.send_header("Content-Type",
                                     "application/octet-stream")
                    self.send_header("Content-Length", str(size))
                    self.send_header(
                        "Content-Disposition",
                        f'attachment; filename="{filename}"')
                    self.send_header("Cache-Control", "no-store")
                    self.send_header(
                        "X-History-Seq",
                        str(int(cached.get("history_seq") or 0)))
                    self.send_header(
                        "X-Player-Seq",
                        str(int(cached.get("player_seq") or 0)))
                    self.send_header(
                        "X-DB-Size", str(int(cached.get("db_size") or 0)))
                    self.send_header("Content-Encoding", "zstd")
                    self.send_header("Vary", "Accept-Encoding")
                    self.end_headers()
                    shutil.copyfileobj(f, self.wfile, length=1024 * 1024)
                    return
                finally:
                    f.close()
            except (BrokenPipeError, ConnectionResetError):
                return
            except Exception:
                # Snapshot disappeared/raced; use the on-demand path below.
                pass
        tmp = gz_tmp = None
        try:
            fd, tmp = tempfile.mkstemp(
                prefix=".mc-netdb-", suffix=".sqlite3",
                dir=os.path.dirname(db_path) or None)
            os.close(fd)
            os.unlink(tmp)
            # VACUUM INTO gives a consistent, compact snapshot (it reads
            # through the WAL) without the client doing row-by-row sync.
            history_seq = player_seq = 0
            with _db_lock:
                src = db_connect(db_path)
                try:
                    try:
                        history_seq = int(src.execute(
                            "SELECT COALESCE(MAX(rowid), 0)"
                            " FROM server_history").fetchone()[0] or 0)
                    except Exception:
                        history_seq = 0
                    src.execute("VACUUM INTO ?", (tmp,))
                finally:
                    src.close()
                try:
                    os.chmod(tmp, 0o600)
                except OSError:
                    pass
            db_size = os.path.getsize(tmp)
            payload = tmp
            encoding = _pick_encoding(self.headers.get("Accept-Encoding"))
            if encoding:
                try:
                    suffix = (".sqlite3.zst" if encoding == "zstd"
                              else ".sqlite3.gz")
                    fd, gz_tmp = tempfile.mkstemp(
                        prefix=".mc-netdb-", suffix=suffix,
                        dir=os.path.dirname(db_path) or None)
                    os.close(fd)
                    if encoding == "zstd":
                        _zstd_compress_file(tmp, gz_tmp)
                    else:
                        with open(tmp, "rb") as fin, open(gz_tmp, "wb") as fout:
                            with gzip.GzipFile(fileobj=fout, mode="wb",
                                               compresslevel=6, mtime=0) as gz:
                                shutil.copyfileobj(fin, gz, length=1024 * 1024)
                    payload = gz_tmp
                    # The compressed copy is what we send; drop the
                    # uncompressed temp immediately.
                    try:
                        os.unlink(tmp)
                        tmp = None
                    except OSError:
                        pass
                except Exception:
                    if gz_tmp:
                        try:
                            os.unlink(gz_tmp)
                        except OSError:
                            pass
                        gz_tmp = None
                    payload = tmp
                    encoding = None
            payload_size = os.path.getsize(payload)
            payload_file = open(payload, "rb")
            try:
                try:
                    # On Unix the file stays readable while open; unlinking it
                    # now means killed/crashed sends cannot leave 200+ MB
                    # snapshot files behind.
                    os.unlink(payload)
                except OSError:
                    pass
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(payload_size))
                self.send_header("Content-Disposition",
                                 f'attachment; filename="{filename}"')
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-History-Seq", str(history_seq))
                self.send_header("X-Player-Seq", str(player_seq))
                self.send_header("X-DB-Size", str(db_size))
                if encoding:
                    self.send_header("Content-Encoding", encoding)
                    self.send_header("Vary", "Accept-Encoding")
                self.end_headers()
                shutil.copyfileobj(payload_file, self.wfile, length=1024 * 1024)
            finally:
                payload_file.close()
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as exc:
            try:
                self._send_json(500, {"error": f"db snapshot failed: {exc}"})
            except Exception:
                pass
        finally:
            for path in (gz_tmp, tmp):
                if path:
                    try:
                        os.unlink(path)
                    except OSError:
                        pass

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/":
            raw = b"MC scanner netdb. Use the scanner's Servers tab (Sync DB) with your URL + token."
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            try:
                self.wfile.write(raw)
            except (BrokenPipeError, ConnectionResetError):
                pass
            return
        if parsed.path == "/api/db":
            if not self._require_auth(b""):
                return
            self._send_sqlite_snapshot(
                self.server.db_path, "servers.db")
            return
        if parsed.path == "/api/notes/db":
            if not self._require_auth(b""):
                return
            self._send_sqlite_snapshot(
                self.server.notes_db_path, "servers-notes.sqlite3")
            return
        if parsed.path in ("/api/health", "/api/servers"):
            if not self._require_auth(b""):
                return
            if parsed.path == "/api/health":
                with _db_lock:
                    con = db_connect(self.server.db_path)
                    try:
                        n = con.execute("SELECT COUNT(*) FROM servers").fetchone()[0]
                        db_format_value = db_format.detect_format(con)
                    finally:
                        con.close()
                    try:
                        ncon = db_connect(self.server.notes_db_path)
                        try:
                            notes_n = ncon.execute(
                                "SELECT COUNT(*) FROM notes"
                                " WHERE text IS NOT NULL").fetchone()[0]
                        finally:
                            ncon.close()
                    except Exception:
                        notes_n = 0
                self._send_json(200, {"ok": True, "servers": n,
                                      "notes": notes_n,
                                      "format": db_format_value,
                                      "compressed_requests": True,
                                      "history_sync": True,
                                      "now": _utcnow()})
                return
            qs = parse_qs(parsed.query or "")
            raw_seq = (qs.get("since_seq") or [None])[0]
            since_seq = None if raw_seq is None else _clamp_seq(raw_seq)
            since = _clamp_ts((qs.get("since") or ["0"])[0])
            try:
                limit = int((qs.get("limit") or [str(MAX_SERVERS_PER_RESPONSE)])[0])
            except Exception:
                limit = MAX_SERVERS_PER_RESPONSE
            limit = max(1, min(limit, MAX_SERVERS_PER_RESPONSE))
            with _db_lock:
                con = db_connect(self.server.db_path)
                try:
                    con.row_factory = sqlite3.Row
                    if since_seq is not None:
                        cur = con.execute(
                            "SELECT * FROM servers WHERE seq > ?"
                            " ORDER BY seq ASC LIMIT ?", (since_seq, limit))
                    else:
                        cur = con.execute(
                            "SELECT * FROM servers WHERE last_seen > ?"
                            " ORDER BY last_seen ASC LIMIT ?", (since, limit))
                    rows = [dict(r) for r in cur.fetchall()]
                    total = con.execute("SELECT COUNT(*) FROM servers").fetchone()[0]
                finally:
                    con.close()
            self._send_json(200, {"servers": rows, "now": _utcnow(), "total": total,
                                  "has_seq": True})
            return
        self._send_json(404, {"error": "not found"})

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path not in ("/api/sync", "/api/continuous",
                               "/api/notes/sync", "/api/history/sync"):
            self._send_json(404, {"error": "not found"})
            return
        body = self._read_body()
        if body is None:
            self._send_json(413, {"error": "body too large"})
            return
        if not self._require_auth(body):
            return
        try:
            body = decode_request_body(
                body, self.headers.get("Content-Encoding"))
            payload = json.loads(body.decode("utf-8")) if body else {}
        except Exception:
            self._send_json(400, {"error": "invalid request body"})
            return
        if not isinstance(payload, dict):
            self._send_json(400, {"error": "invalid JSON"})
            return
        if (parsed.path in ("/api/sync", "/api/history/sync")
                and not self._require_sync_format(payload)):
            return
        if parsed.path == "/api/continuous":
            node = str(payload.get("node", "") or "").strip()
            if (not node or len(node) > 128
                    or not re.fullmatch(r"[A-Za-z0-9._:-]+", node)):
                self._send_json(400, {"error": "bad node id"})
                return
            leave = bool(payload.get("leave", False))
            shard = register_continuous(node, leave=leave)
            self._send_json(200, {
                "ok": True,
                "node": node,
                "left": shard.get("left", False),
                "index": shard["index"],
                "total": shard["total"],
                "ttl": CONTINUOUS_TTL,
                "heartbeat": CONTINUOUS_HEARTBEAT,
                "now": _utcnow(),
            })
            return
        if parsed.path == "/api/notes/sync":
            incoming = payload.get("notes", [])
            if (not isinstance(incoming, list)
                    or len(incoming) > MAX_NOTES_PER_REQUEST):
                self._send_json(400, {"error": "bad 'notes' list"})
                return
            since_seq = _clamp_seq(payload.get("since_seq", 0) or 0) or 0
            merged = 0
            deleted = 0
            uploaded_ids = set()
            with _db_lock:
                con = notes_db_connect(self.server.notes_db_path)
                try:
                    for raw_note in incoming:
                        note = sanitize_note(raw_note)
                        if note is None:
                            continue
                        uploaded_ids.add(note["id"])
                        try:
                            if merge_note(con, note):
                                merged += 1
                                if note["text"] is None:
                                    deleted += 1
                        except Exception:
                            continue
                    con.commit()
                    if deleted:
                        # Tombstones are small; VACUUM drops the old text
                        # payload and shrinks the notes file immediately.
                        try:
                            con.execute("VACUUM")
                        except Exception:
                            pass
                    con.row_factory = sqlite3.Row
                    cur = con.execute(
                        "SELECT * FROM notes WHERE seq > ?"
                        " ORDER BY seq ASC LIMIT ?",
                        (since_seq, MAX_NOTES_PER_RESPONSE))
                    by_id = {str(r["id"]): dict(r) for r in cur.fetchall()}
                    # Also return the current state of everything the client
                    # just tried to upload.  If an edit/delete was rejected
                    # (immutability, tombstone), this corrects the client.
                    ids = sorted(uploaded_ids)
                    for start in range(0, len(ids), 500):
                        chunk = ids[start:start + 500]
                        marks = ",".join("?" * len(chunk))
                        rows = con.execute(
                            f"SELECT * FROM notes WHERE id IN ({marks})",
                            chunk).fetchall()
                        for r in rows:
                            by_id[str(r["id"])] = dict(r)
                    notes = list(by_id.values())
                    total = con.execute(
                        "SELECT COUNT(*) FROM notes").fetchone()[0]
                finally:
                    con.close()
            self._send_json(200, {"notes": notes, "now": _utcnow(),
                                  "merged": merged, "total": total,
                                  "has_seq": True})
            return
        if parsed.path == "/api/history/sync":
            history_in = payload.get("history", [])
            players_in = payload.get("players", [])
            if (not isinstance(history_in, list)
                    or len(history_in) > MAX_HISTORY_PER_REQUEST):
                self._send_json(400, {"error": "bad 'history' list"})
                return
            if (not isinstance(players_in, list)
                    or len(players_in) > MAX_HISTORY_PER_REQUEST):
                self._send_json(400, {"error": "bad 'players' list"})
                return
            history_since = _clamp_seq(
                payload.get("history_since", 0) or 0) or 0
            player_since = _clamp_seq(
                payload.get("player_since", 0) or 0) or 0
            try:
                limit = int(payload.get("limit", MAX_HISTORY_PER_RESPONSE)
                            or MAX_HISTORY_PER_RESPONSE)
            except Exception:
                limit = MAX_HISTORY_PER_RESPONSE
            limit = max(1, min(limit, MAX_HISTORY_PER_RESPONSE))
            download = bool(payload.get("download", True))
            now = _utcnow()
            cutoff = now - db_format.HISTORY_RETENTION_SECONDS
            history_by_key = {}
            for raw_row in history_in:
                row = sanitize_history_row(raw_row, now, cutoff)
                if row is None:
                    continue
                key = (row["ip_port"], row["seen_at"])
                existing = history_by_key.get(key)
                if existing is None:
                    history_by_key[key] = [
                        row["players_online"], row["max_players"],
                        row["players"]]
                else:
                    existing[2] = db_format.merge_player_blobs(
                        existing[2], row["players"])
            history_values = [
                (ip, seen, vals[0], vals[1], vals[2])
                for (ip, seen), vals in history_by_key.items()]
            # Old clients still upload player events separately.  Fold them
            # into the roster blob on the matching sighting.
            player_groups = {}
            for raw_row in players_in:
                row = sanitize_player_event(raw_row, now, cutoff)
                if row is not None:
                    player_groups.setdefault(
                        (row["ip_port"], row["seen_at"]), []).append(
                            row["player_name"])
            rejected_history = rejected_players = 0
            merged_history = merged_players = 0
            try:
                prune_database_history(self.server.db_path)
            except Exception as exc:
                print(f"history sync: prune failed: {exc}",
                      file=sys.stderr, flush=True)
            with _db_lock:
                con = db_connect(self.server.db_path)
                try:
                    before = con.total_changes
                    for (ip_port, seen_at), vals in sorted(
                            history_by_key.items()):
                        online, maximum, players = vals
                        exact = con.execute(
                            "SELECT 1 FROM server_history"
                            " WHERE ip_port=? AND seen_at=? LIMIT 1",
                            (ip_port, seen_at)).fetchone()
                        if exact:
                            con.execute(
                                "INSERT INTO server_history"
                                " (ip_port, seen_at, players_online,"
                                " max_players, players, synced)"
                                " VALUES (?, ?, ?, ?, ?, 1)"
                                " ON CONFLICT(ip_port, seen_at) DO UPDATE SET"
                                " players=COALESCE(server_history.players,"
                                " excluded.players)",
                                (ip_port, seen_at, online, maximum, players))
                            continue
                        has_players = ((online or 0) > 0 or bool(players))
                        gap = (db_format.ACTIVITY_PLAYER_GAP_SECONDS
                               if has_players
                               else db_format.ACTIVITY_EMPTY_GAP_SECONDS)
                        near = con.execute(
                            "SELECT 1 FROM server_history"
                            " WHERE ip_port=? AND seen_at > ? AND seen_at < ?"
                            " LIMIT 1",
                            (ip_port, seen_at - gap,
                             seen_at + gap)).fetchone()
                        if near is not None:
                            rejected_history += 1
                            continue
                        con.execute(
                            "INSERT INTO server_history"
                            " (ip_port, seen_at, players_online, max_players,"
                            " players, synced) VALUES (?, ?, ?, ?, ?, 1)",
                            (ip_port, seen_at, online, maximum, players))
                    merged_history = con.total_changes - before
                    before = con.total_changes
                    for (ip_port, seen_at), names in sorted(
                            player_groups.items()):
                        row = con.execute(
                            "SELECT players FROM server_history"
                            " WHERE ip_port=? AND seen_at=?",
                            (ip_port, seen_at)).fetchone()
                        merged = db_format.merge_player_blobs(
                            row[0] if row else None, names)
                        if row is None:
                            near = con.execute(
                                "SELECT 1 FROM server_history"
                                " WHERE ip_port=? AND seen_at > ?"
                                " AND seen_at < ? LIMIT 1",
                                (ip_port,
                                 seen_at - db_format.ACTIVITY_PLAYER_GAP_SECONDS,
                                 seen_at + db_format.ACTIVITY_PLAYER_GAP_SECONDS)
                            ).fetchone()
                            if near is not None:
                                rejected_players += 1
                                continue
                            con.execute(
                                "INSERT OR IGNORE INTO server_history"
                                " (ip_port, seen_at, players_online,"
                                " max_players, players, synced)"
                                " VALUES (?, ?, NULL, NULL, ?, 1)",
                                (ip_port, seen_at, merged))
                        elif merged != row[0]:
                            con.execute(
                                "UPDATE server_history SET players=?,"
                                " synced=1 WHERE ip_port=? AND seen_at=?",
                                (merged, ip_port, seen_at))
                    merged_players = con.total_changes - before
                    con.commit()
                    if history_values or player_groups:
                        writer = getattr(self.server, "zstd_writer", None)
                        if writer is not None:
                            writer.notify()
                    if download:
                        con.row_factory = sqlite3.Row
                        cur = con.execute(
                            "SELECT rowid AS seq, ip_port, seen_at,"
                            " players_online, max_players, players"
                            " FROM server_history WHERE rowid > ?"
                            " ORDER BY rowid ASC LIMIT ?",
                            (history_since, limit))
                        history_out = [dict(r) for r in cur.fetchall()]
                        players_out = []
                        history_seq = max(
                            [history_since] +
                            [int(r.get("seq", 0) or 0) for r in history_out])
                        player_seq = player_since
                    else:
                        history_out = []
                        players_out = []
                        history_seq = history_since
                        player_seq = player_since
                finally:
                    con.close()
            self._send_json(200, {
                "history": history_out,
                "players": players_out,
                "history_seq": history_seq,
                "player_seq": player_seq,
                "merged_history": merged_history,
                "merged_players": merged_players,
                "rejected_history": rejected_history,
                "rejected_players": rejected_players,
                "has_history": True,
                "now": _utcnow(),
            })
            return
        # A missing format means a legacy client (format 1); new clients
        # send 2. Rows are converted at this boundary either way.
        try:
            client_format = int(payload.get("format", 1) or 1)
        except Exception:
            client_format = 1
        # Format 2 and 3 share the row wire shape; anything unknown is a
        # legacy caller and gets the format-1 compatibility payload.
        client_format = 2 if client_format >= 2 else 1
        incoming = payload.get("servers", [])
        if not isinstance(incoming, list) or len(incoming) > MAX_SERVERS_PER_REQUEST:
            self._send_json(400, {"error": "bad 'servers' list"})
            return
        raw_seq = payload.get("since_seq", None)
        since_seq = None if raw_seq is None else _clamp_seq(raw_seq)
        since = _clamp_ts(payload.get("since", 0) or 0)
        try:
            page_limit = int(payload.get("limit", MAX_SERVERS_PER_RESPONSE)
                             or MAX_SERVERS_PER_RESPONSE)
        except Exception:
            page_limit = MAX_SERVERS_PER_RESPONSE
        page_limit = max(1, min(page_limit, MAX_SERVERS_PER_RESPONSE))
        merged = 0
        with _db_lock:
            con = db_connect(self.server.db_path)
            try:
                for raw_row in incoming:
                    row = sanitize_row(raw_row)
                    if row is None:
                        continue
                    try:
                        if merge_row(con, row):
                            merged += 1
                    except Exception:
                        continue
                con.commit()
                if merged:
                    writer = getattr(self.server, "zstd_writer", None)
                    if writer is not None:
                        writer.notify()
                con.row_factory = sqlite3.Row
                if since_seq is not None:
                    cur = con.execute(
                        "SELECT * FROM servers WHERE seq > ?"
                        " ORDER BY seq ASC LIMIT ?",
                        (since_seq, page_limit))
                else:
                    cur = con.execute(
                        "SELECT * FROM servers WHERE last_seen > ?"
                        " ORDER BY last_seen ASC LIMIT ?",
                        (since, page_limit))
                deltas = [db_format.row_for_format(dict(r), client_format)
                          for r in cur.fetchall()]
                total = con.execute("SELECT COUNT(*) FROM servers").fetchone()[0]
            finally:
                con.close()
        self._send_json(200, {"servers": deltas, "now": _utcnow(),
                              "merged": merged, "total": total,
                              "format": db_format.CURRENT_FORMAT,
                              "client_format": client_format,
                              "has_seq": True})


def main(argv=None):
    ap = argparse.ArgumentParser(description="Shared network DB for the MC scanner")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8777)
    ap.add_argument("--db", default="servers.db")
    ap.add_argument("--notes-db", default="",
                    help="separate notes database (default: <db>-notes.sqlite3)")
    ap.add_argument("--token", default="",
                    help="Shared secret (else $DBSERVER_TOKEN, else token file).")
    ap.add_argument("--token-file", default=".dbserver_token",
                    help="Token file (mode 0600). A token.txt in the working "
                         "directory is used when this file is absent.")
    ap.add_argument("--tls-cert", default="", help="PEM chain for https://")
    ap.add_argument("--tls-key", default="", help="PEM private key for https://")
    ap.add_argument("--web-db-zst", default=None, metavar="PATH",
                    help="write a consistent zstd snapshot here after DB "
                         "writes, for the static web viewer "
                         "(default: <db>.zst; use --no-web-db-zst to disable)")
    ap.add_argument("--no-web-db-zst", action="store_true",
                    help="do not maintain the default <db>.zst snapshot")
    ap.add_argument("--web-db-zst-level", type=int, default=1, metavar="N",
                    help="zstd level for --web-db-zst (default: 1)")
    ap.add_argument("--dedupe", action="store_true",
                    help="merge same-host duplicate ports, compact servers.db, "
                         "then exit")
    ap.add_argument("--dedupe-every", type=float, default=900.0, metavar="SECS",
                    help="merge duplicate ports in the background every SECS "
                         "seconds (0 disables; default: 900)")
    args = ap.parse_args(argv)

    try:
        sys.stdout.reconfigure(line_buffering=True)
    except Exception:
        pass
    init_db(args.db)
    web_db_zst = args.web_db_zst
    if args.no_web_db_zst:
        web_db_zst = ""
    elif web_db_zst is None:
        web_db_zst = os.path.abspath(args.db) + ".zst"
    elif not str(web_db_zst).strip():
        web_db_zst = ""
    else:
        web_db_zst = os.path.abspath(web_db_zst)
    if args.dedupe:
        stats = dedupe_database(args.db)
        print(f"dedupe complete: {stats['groups']} groups, "
              f"{stats['removed_state']} server rows, "
              f"{stats['removed_history']} history rows removed")
        return
    notes_db = (args.notes_db.strip() or
                os.path.splitext(os.path.abspath(args.db))[0] + "-notes.sqlite3")
    init_notes_db(notes_db)
    token, token_source = load_or_create_token(args.token_file, args.token or None)
    if token_source.endswith("(generated)"):
        print(f"Generated new shared token (saved to {args.token_file}, mode 0600):")
        print(token)
        print("Give this token to every scanner client together with your server URL.")
    else:
        print(f"Using shared token from {token_source}.")
    try:
        st = os.stat(args.token_file)
        if st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
            print(f"WARNING: {args.token_file} is group/other-readable; "
                  f"run: chmod 600 {args.token_file}", file=sys.stderr)
    except OSError:
        pass

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    server.db_path = os.path.abspath(args.db)
    server.notes_db_path = os.path.abspath(notes_db)
    server.shared_token = token
    server.daemon_threads = True
    server.zstd_writer = None
    server.web_db_zst = web_db_zst
    writer = None
    if web_db_zst:
        writer = ZstdSnapshotWriter(
            server.db_path, web_db_zst,
            level=args.web_db_zst_level)
        server.zstd_writer = writer
    scheme = "http"
    tls_cert, tls_key = args.tls_cert, args.tls_key
    if not (tls_cert and tls_key):
        # Zero-config TLS: drop cert.pem + privkey.pem next to the server.
        if os.path.isfile("cert.pem") and os.path.isfile("privkey.pem"):
            tls_cert, tls_key = "cert.pem", "privkey.pem"
    if tls_cert and tls_key:
        import ssl
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(tls_cert, tls_key)
        except Exception as exc:
            print(f"ERROR: could not load TLS cert/key ({tls_cert}, {tls_key}): {exc}",
                  file=sys.stderr)
            sys.exit(2)
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
        scheme = "https"
        print(f"TLS enabled ({tls_cert}, {tls_key}) -- clients must use https:// URLs.")
    print(f"Serving netdb on {scheme}://{args.host}:{args.port} "
          f"(db={server.db_path}, notes={server.notes_db_path})")
    if writer is not None:
        print(f"Web DB snapshot: {web_db_zst} "
              f"(zstd level {args.web_db_zst_level})")
        writer.start()
    deduper = None
    if args.dedupe_every > 0:
        deduper = PortDeduper(server.db_path, args.dedupe_every, writer)
        deduper.start()
        print(f"Port dedupe: every {args.dedupe_every:.0f}s")
    if scheme == "http":
        print("NOTE: plain HTTP -- clients auth with HMAC so the token itself "
              "is never sent in cleartext, but drop cert.pem + privkey.pem in "
              "this directory (or use --tls-cert/--tls-key / a reverse proxy) "
              "if your list is sensitive.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        if deduper is not None:
            deduper.stop()
        if writer is not None:
            writer.stop()


if __name__ == "__main__":
    main()
