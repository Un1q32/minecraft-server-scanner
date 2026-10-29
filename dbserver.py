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
* ``GET  /api/health``               -> ``{"ok": true, "servers": N, "now": T}``
* ``GET  /api/servers?since=<ts>``   -> ``{"servers": [...], "now": T, "total": N}``
* ``POST /api/sync`` ``{"servers": [...], "since": <ts>}``
  merges the upload, then returns rows with ``last_seen > since``::

      {"servers": [...deltas...], "now": T, "merged": M, "total": N}

  Clients that know the seq protocol pass ``since_seq`` instead (and for
  ``GET``, ``?since_seq=N``): every insert/change bumps the row's ``seq``,
  so paging ``seq > since_seq`` can never miss rows that arrived with old
  ``last_seen`` timestamps. Replies carry ``"has_seq": true``.

Row shape (mirrors the client's ``servers.db``)::

    {"ip_port": "1.2.3.4:25565", "host": "1.2.3.4", "port": 25565,
     "motd": "...", "players_online": 3, "max_players": 20,
     "version": "1.21", "protocol": 767, "cracked": "Yes/No",
     "whitelist": "...", "first_seen": 123.0, "last_seen": 456.0,
     "times_seen": 2, "last_source": "scan",
     "players_now": ["Alice"], "players_ever": ["Alice", "Bob"]}

Merge rule (both directions): ``first_seen`` = oldest non-zero,
``last_seen`` = newest, mutable display fields (motd/players/version/...)
come from whichever side saw the server most recently, and a confirmed
cracked verdict (``Yes`` / ``Yes (cached)``) is never downgraded by a plain
status ping.  ``times_seen`` = max + 1 when the incoming sighting is newer.
``players_now`` follows the newer sighting; ``players_ever`` is the union
of both sides (capped at 500 names per server).

Stdlib only -- no pip dependencies.
"""

import argparse
import hashlib
import hmac
import ipaddress
import json
import math
import os
import re
import secrets
import sqlite3
import stat
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

IP_PORT_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}:\d{1,5}$")
MAX_BODY_BYTES = 25 * 1024 * 1024
MAX_SERVERS_PER_REQUEST = 20000
MAX_SERVERS_PER_RESPONSE = 50000
SQLITE_MAX_INT = 2 ** 63 - 1     # larger ints overflow the sqlite3 binding
MAX_TIMESTAMP = 1e18             # far beyond any real epoch, still finite
TIMESTAMP_SKEW = 300
NONCE_CACHE_MAX = 20000

SCHEMA = (
    "CREATE TABLE IF NOT EXISTS servers ("
    " ip_port TEXT PRIMARY KEY,"
    " host TEXT DEFAULT '',"
    " port INTEGER DEFAULT 25565,"
    " motd TEXT DEFAULT '',"
    " players_online INTEGER DEFAULT 0,"
    " max_players INTEGER DEFAULT 0,"
    " version TEXT DEFAULT '',"
    " protocol INTEGER,"
    " cracked TEXT DEFAULT '',"
    " whitelist TEXT DEFAULT '',"
    " first_seen REAL DEFAULT 0,"
    " last_seen REAL DEFAULT 0,"
    " times_seen INTEGER DEFAULT 1,"
    " last_source TEXT DEFAULT '',"
    " players_now TEXT DEFAULT '[]',"
    " players_ever TEXT DEFAULT '[]',"
    " seq INTEGER DEFAULT 0"
    ")"
)

PLAYERS_EVER_MAX = 500  # per-server cap on the ever-seen name list
PLAYER_NAME_MAX_LEN = 32

_db_lock = threading.Lock()
_nonce_lock = threading.Lock()
_seen_nonces = {}  # nonce -> expiry timestamp
_fail_lock = threading.Lock()
_auth_failures = {}  # ip -> {"count": int, "window_start": float, "banned_until": float}


def _utcnow():
    return time.time()


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
        existing = {row[1] for row in con.execute("PRAGMA table_info(servers)")}
        if column not in existing:
            con.execute(f"ALTER TABLE servers ADD COLUMN {column} {ddl}")
    except Exception:
        pass


def init_db(db_path):
    con = db_connect(db_path)
    try:
        con.execute(SCHEMA)
        con.execute("CREATE INDEX IF NOT EXISTS idx_servers_last_seen "
                    "ON servers(last_seen DESC)")
        # Transport cursor for sync: every insert/change gets a fresh seq, so
        # clients page by seq (not wall-clock) and can never miss rows that
        # arrived with old last_seen timestamps.
        _add_column_if_missing(con, "seq", "INTEGER DEFAULT 0")
        _add_column_if_missing(con, "players_now", "TEXT DEFAULT '[]'")
        _add_column_if_missing(con, "players_ever", "TEXT DEFAULT '[]'")
        try:
            con.execute("UPDATE servers SET seq=rowid WHERE seq IS NULL OR seq=0")
        except Exception:
            pass
        con.execute("CREATE INDEX IF NOT EXISTS idx_servers_seq ON servers(seq ASC)")
        con.commit()
    finally:
        con.close()


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
    s = "" if value is None else str(value)
    s = re.sub(r"\s+", " ", s.replace("\r", " ").replace("\n", " ")).strip()
    return s[:limit]


def _clean_player_name(value):
    try:
        s = "" if value is None else str(value)
        s = re.sub(r"\s+", " ", s.replace("\r", " ").replace("\n", " ")).strip()
        return s[:PLAYER_NAME_MAX_LEN].strip()
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
            return "[]"
        names = sorted({_clean_player_name(n) for n in parsed} -
                       {""}, key=str.lower)
        return json.dumps(names[:PLAYERS_EVER_MAX], ensure_ascii=False)
    except Exception:
        return "[]"


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
        return "[]"


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
    host = _clamp_str(raw.get("host") or ip_port.rsplit(":", 1)[0], 253)
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
        "host": host,
        "port": port,
        "motd": _clamp_str(raw.get("motd", ""), 500),
        "players_online": min(online, 1000000),
        "max_players": min(maximum, 1000000),
        "version": _clamp_str(raw.get("version", ""), 100),
        "protocol": protocol,
        "cracked": _clamp_str(raw.get("cracked", ""), 32),
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
            "INSERT INTO servers (ip_port, host, port, motd, players_online,"
            " max_players, version, protocol, cracked, whitelist,"
            " first_seen, last_seen, times_seen, last_source,"
            " players_now, players_ever,"
            " seq)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,"
            " (SELECT COALESCE(MAX(seq), 0) + 1 FROM servers))",
            (row["ip_port"], row["host"], row["port"], row["motd"],
             row["players_online"], row["max_players"], row["version"],
             row["protocol"], row["cracked"], row["whitelist"],
             row["first_seen"] or row["last_seen"] or _utcnow(),
             row["last_seen"] or row["first_seen"] or _utcnow(),
             row["times_seen"], row["last_source"],
             row["players_now"], row["players_ever"]))
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
    # Never downgrade a confirmed cracked verdict via an older/plain sighting.
    if o_cracked in ("Yes", "Yes (cached)"):
        cracked = o_cracked
    elif incoming_newer and row["cracked"]:
        cracked = row["cracked"]
    else:
        cracked = o_cracked or row["cracked"]
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
    now = row["players_now"] if incoming_newer else (o_now or "[]")
    ever = _merge_player_lists(
        _merge_player_lists(o_ever, o_now), _merge_player_lists(row["players_ever"], row["players_now"]))
    if (motd, online, maximum, version, protocol, cracked, whitelist,
            first_seen, last_seen, times_seen, src, now, ever) == (
            o_motd, o_on, o_max, o_ver, o_proto, o_cracked, o_wl,
            o_first, o_last, o_times, o_src, o_now, o_ever):
        return False
    con.execute(
        "UPDATE servers SET host=?, port=?, motd=?, players_online=?,"
        " max_players=?, version=?, protocol=?, cracked=?, whitelist=?,"
        " first_seen=?, last_seen=?, times_seen=?, last_source=?,"
        " players_now=?, players_ever=?,"
        " seq=(SELECT COALESCE(MAX(seq), 0) + 1 FROM servers)"
        " WHERE ip_port=?",
        (row["host"], row["port"], motd, online, maximum, version, protocol,
         cracked, whitelist, first_seen, last_seen, times_seen, src,
         now, ever, row["ip_port"]))
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

class Handler(BaseHTTPRequestHandler):
    server_version = "MCNetDB/1.0"

    def log_message(self, fmt, *args):
        sys.stderr.write("%s - %s\n" % (_client_ip(self), fmt % args))

    def _send_json(self, code, obj):
        raw = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
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
        if parsed.path in ("/api/health", "/api/servers"):
            if not self._require_auth(b""):
                return
            if parsed.path == "/api/health":
                with _db_lock:
                    con = db_connect(self.server.db_path)
                    try:
                        n = con.execute("SELECT COUNT(*) FROM servers").fetchone()[0]
                    finally:
                        con.close()
                self._send_json(200, {"ok": True, "servers": n, "now": _utcnow()})
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
        if parsed.path != "/api/sync":
            self._send_json(404, {"error": "not found"})
            return
        body = self._read_body()
        if body is None:
            self._send_json(413, {"error": "body too large"})
            return
        if not self._require_auth(body):
            return
        try:
            payload = json.loads(body.decode("utf-8")) if body else {}
        except Exception:
            self._send_json(400, {"error": "invalid JSON"})
            return
        if not isinstance(payload, dict):
            self._send_json(400, {"error": "invalid JSON"})
            return
        incoming = payload.get("servers", [])
        if not isinstance(incoming, list) or len(incoming) > MAX_SERVERS_PER_REQUEST:
            self._send_json(400, {"error": "bad 'servers' list"})
            return
        raw_seq = payload.get("since_seq", None)
        since_seq = None if raw_seq is None else _clamp_seq(raw_seq)
        since = _clamp_ts(payload.get("since", 0) or 0)
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
                con.row_factory = sqlite3.Row
                if since_seq is not None:
                    cur = con.execute(
                        "SELECT * FROM servers WHERE seq > ?"
                        " ORDER BY seq ASC LIMIT ?",
                        (since_seq, MAX_SERVERS_PER_RESPONSE))
                else:
                    cur = con.execute(
                        "SELECT * FROM servers WHERE last_seen > ?"
                        " ORDER BY last_seen ASC LIMIT ?",
                        (since, MAX_SERVERS_PER_RESPONSE))
                deltas = [dict(r) for r in cur.fetchall()]
                total = con.execute("SELECT COUNT(*) FROM servers").fetchone()[0]
            finally:
                con.close()
        self._send_json(200, {"servers": deltas, "now": _utcnow(),
                              "merged": merged, "total": total,
                              "has_seq": True})


def main(argv=None):
    ap = argparse.ArgumentParser(description="Shared network DB for the MC scanner")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8777)
    ap.add_argument("--db", default="netdb.sqlite3")
    ap.add_argument("--token", default="",
                    help="Shared secret (else $DBSERVER_TOKEN, else token file).")
    ap.add_argument("--token-file", default=".dbserver_token",
                    help="Token file (mode 0600). A token.txt in the working "
                         "directory is used when this file is absent.")
    ap.add_argument("--tls-cert", default="", help="PEM chain for https://")
    ap.add_argument("--tls-key", default="", help="PEM private key for https://")
    args = ap.parse_args(argv)

    try:
        sys.stdout.reconfigure(line_buffering=True)
    except Exception:
        pass
    init_db(args.db)
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
    server.shared_token = token
    server.daemon_threads = True
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
          f"(db={server.db_path})")
    if scheme == "http":
        print("NOTE: plain HTTP -- clients auth with HMAC so the token itself "
              "is never sent in cleartext, but drop cert.pem + privkey.pem in "
              "this directory (or use --tls-cert/--tls-key / a reverse proxy) "
              "if your list is sensitive.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
