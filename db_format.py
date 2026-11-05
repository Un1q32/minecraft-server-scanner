"""Shared on-disk format helpers for the scanner and shared DB server.

Format 1 stored ``cracked`` as a display string ("Yes", "No",
"Yes (cached)", ...).  Format 2 stores it as a SQLite integer state
(1 = yes, 0 = no, NULL = unset/unknown) and also drops redundant/empty
payloads (host duplicated by ip_port, empty player lists as NULL).

Format 3 removes the dedicated ``first_seen`` and ``last_seen`` columns.
The source of truth is ``server_history`` (one row per sighting); the
read-only view ``servers`` adds back ``first_seen``/``last_seen`` as
MIN/MAX over that history so existing queries keep working.  The base table
is named ``server_state`` because SQLite cannot have a table and a view with
the same name.

Format 4 stores the sampled player roster as one compact blob on each
``server_history`` row instead of a ``player_history`` row per player per
sighting.  Rosters are often nearly identical and the server sample is
partial, so per-player rows dominated the database and duplicated the same
names over and over.  Names are separated by ``\\x1f`` (a control character
that filtered player names cannot contain).

SQLite's ``PRAGMA user_version`` marks the format; older databases have 0
and are migrated in place.
"""

from __future__ import annotations

import json
import sqlite3
import unicodedata

CURRENT_FORMAT = 4
BASE_FORMAT = 1
STATE_TABLE = "server_state"
SERVER_VIEW = "servers"

SERVER_STATE_SCHEMA = (
    "CREATE TABLE IF NOT EXISTS server_state ("
    " ip_port TEXT PRIMARY KEY,"
    " host TEXT DEFAULT '',"
    " port INTEGER DEFAULT 25565,"
    " motd TEXT DEFAULT '',"
    " players_online INTEGER DEFAULT 0,"
    " max_players INTEGER DEFAULT 0,"
    " version TEXT DEFAULT '',"
    " protocol INTEGER,"
    " cracked INTEGER DEFAULT NULL,"
    " whitelist TEXT DEFAULT '',"
    " times_seen INTEGER DEFAULT 1,"
    " last_source TEXT DEFAULT '',"
    " needs_sync INTEGER DEFAULT 1,"
    " players_now TEXT,"
    " players_ever TEXT"
    ")"
)

HISTORY_TABLES = (
    "CREATE TABLE IF NOT EXISTS server_history ("
    " ip_port TEXT NOT NULL,"
    " seen_at REAL NOT NULL,"
    " players_online INTEGER,"
    " max_players INTEGER,"
    " players TEXT,"
    " synced INTEGER DEFAULT 0,"
    " PRIMARY KEY (ip_port, seen_at)"
    ")",
)

HISTORY_INDEXES = (
    # Only unsynced rows need upload indexes.  After a sync these are
    # nearly empty instead of indexing the entire history.
    "CREATE INDEX IF NOT EXISTS idx_server_history_unsynced"
    " ON server_history(seen_at ASC) WHERE synced=0",
    # The User Log only needs sightings that actually sampled players.
    "CREATE INDEX IF NOT EXISTS idx_server_history_players_time"
    " ON server_history(seen_at DESC) WHERE players IS NOT NULL",
)

# Older format-3 builds created these full-table indexes.  They are either
# redundant with the primary key, replaced by a partial index, or no longer
# needed for graph queries.
OLD_HISTORY_INDEXES = (
    "idx_player_history_ip_time",
    "idx_player_history_name_time",
    "idx_server_history_synced",
    "idx_player_history_synced",
)
PLAYER_BLOB_SEP = "\x1f"
PLAYER_BLOB_MAX = 500


def init_history_schema(con: sqlite3.Connection):
    """Create the per-sighting tables used by the viewer graphs."""
    for statement in HISTORY_TABLES:
        con.execute(statement)
    # Format 3 originally shipped without the sync flag; format 4 adds the
    # roster blob.  Existing rows become unsynced so the next sync uploads
    # the local history once.  The upload indexes must be created after
    # these ALTERs.
    columns = {str(row[1]) for row in
               con.execute("PRAGMA table_info(server_history)")}
    if "synced" not in columns:
        con.execute("ALTER TABLE server_history"
                    " ADD COLUMN synced INTEGER DEFAULT 0")
    if "players" not in columns:
        con.execute("ALTER TABLE server_history ADD COLUMN players TEXT")
    # Drop the old, much larger indexes.  This is a no-op after the first
    # startup; the pages are reclaimed by vacuum_if_bloated().
    for name in OLD_HISTORY_INDEXES:
        con.execute(f"DROP INDEX IF EXISTS {name}")
    # A format-2 migration left old duplicate seq/version index names on
    # server_state.
    con.execute("DROP INDEX IF EXISTS idx_servers_seq")
    if object_type(con, STATE_TABLE) == "table":
        con.execute("DROP INDEX IF EXISTS idx_servers_version")
        con.execute("CREATE INDEX IF NOT EXISTS idx_server_state_version"
                    " ON server_state(version)")
    for statement in HISTORY_INDEXES:
        con.execute(statement)


def vacuum_if_bloated(con: sqlite3.Connection):
    """VACUUM once when index migrations free a significant part of the DB."""
    try:
        con.commit()
        page_count = int(con.execute("PRAGMA page_count").fetchone()[0] or 0)
        free = int(con.execute("PRAGMA freelist_count").fetchone()[0] or 0)
        if page_count and free > max(64, page_count // 10):
            con.execute("VACUUM")
    except Exception:
        pass


def object_type(con: sqlite3.Connection, name: str):
    """'table', 'view', or None for one schema object."""
    row = con.execute(
        "SELECT type FROM sqlite_master WHERE name=?", (name,)).fetchone()
    return str(row[0]) if row else None


def base_table(con: sqlite3.Connection) -> str:
    """Name of the writable servers table (v3 uses ``server_state``)."""
    if object_type(con, STATE_TABLE) == "table":
        return STATE_TABLE
    return "servers"


def ensure_view(con: sqlite3.Connection, recreate: bool = False):
    """Create the derived ``servers`` view, optionally replacing it so it
    picks up columns added to ``server_state`` after migration."""
    if object_type(con, STATE_TABLE) != "table":
        return
    existing = object_type(con, SERVER_VIEW)
    if existing == "view":
        if not recreate:
            return
        con.execute("DROP VIEW servers")
    elif existing == "table":
        # A format-2 table was not migrated; leave it alone.
        return
    con.execute(
        "CREATE VIEW servers AS SELECT s.*,"
        " (SELECT MIN(seen_at) FROM server_history h"
        "  WHERE h.ip_port=s.ip_port) AS first_seen,"
        " (SELECT MAX(seen_at) FROM server_history h"
        "  WHERE h.ip_port=s.ip_port) AS last_seen"
        " FROM server_state s"
    )


def _table_columns(con: sqlite3.Connection):
    return list(con.execute("PRAGMA table_info(servers)"))


def _column_names(con: sqlite3.Connection, table: str):
    return [str(row[1]) for row in con.execute(f"PRAGMA table_info({table})")]


def _to_float(value) -> float:
    try:
        return float(value or 0)
    except Exception:
        return 0.0


def _to_int(value, default=0) -> int:
    try:
        return int(value)
    except Exception:
        return default


ANONYMOUS_PLAYER_NAMES = {"anonymous player", "anonymousplayer"}


def is_anonymous_player_name(value) -> bool:
    """Synthetic placeholder some servers use instead of a real player."""
    return str(value or "").strip().lower() in ANONYMOUS_PLAYER_NAMES


def is_spoofed_player_name(value) -> bool:
    """True for color codes/emoji/control symbols used in fake ad names."""
    text = str(value or "")
    for ch in text:
        if ch == "\u00a7":
            return True
        cp = ord(ch)
        if cp >= 0x1F000:
            return True
        if 0x2600 <= cp <= 0x27BF or 0x2B00 <= cp <= 0x2BFF:
            return True
        if cp in (0x200D, 0x20E3, 0xFE0F):
            return True
        if unicodedata.category(ch) in ("Cc", "Cf", "Cs", "Co", "So"):
            return True
    return False


def _name_list(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        raw = value
    else:
        text = str(value).strip()
        if not text or text == "[]":
            return []
        try:
            parsed = json.loads(text)
        except Exception:
            return []
        if not isinstance(parsed, list):
            return []
        raw = parsed
    out = []
    seen = set()
    for item in raw:
        name = str(item or "").strip()
        if name and not is_spoofed_player_name(name) and name not in seen:
            seen.add(name)
            out.append(name)
    return out


def _blob_names(value) -> list[str]:
    """Decode a player roster blob (or legacy JSON/list) into names."""
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        raw = value
    else:
        text = str(value)
        if not text:
            return []
        if text.lstrip().startswith("["):
            try:
                parsed = json.loads(text)
            except Exception:
                return []
            raw = parsed if isinstance(parsed, list) else []
        else:
            raw = text.split(PLAYER_BLOB_SEP)
    out = []
    seen = set()
    for item in raw:
        name = str(item or "").strip()
        if (name and not is_spoofed_player_name(name)
                and not is_anonymous_player_name(name)
                and name not in seen):
            seen.add(name)
            out.append(name)
    return out


def encode_player_blob(names) -> str | None:
    """One compact roster -> stored blob (None when empty)."""
    values = _blob_names(names)
    if not values:
        return None
    values = sorted(values, key=str.lower)[:PLAYER_BLOB_MAX]
    return PLAYER_BLOB_SEP.join(values)


def decode_player_blob(value) -> list[str]:
    """Stored blob (or legacy JSON/list) -> sorted activity names."""
    values = _blob_names(value)
    return sorted(values, key=str.lower)


def merge_player_blobs(old, new) -> str | None:
    """Union two rosters, keeping established (old) names first."""
    merged = _blob_names(old)
    seen = set(merged)
    for name in _blob_names(new):
        if name not in seen:
            seen.add(name)
            merged.append(name)
    return encode_player_blob(merged)


def _insert_history(con, ip_port, seen_at, players_online, max_players,
                    names=(), synced=0, merge=False):
    if not ip_port or seen_at <= 0:
        return
    players = encode_player_blob(names)
    if merge and players is not None:
        row = con.execute(
            "SELECT players FROM server_history"
            " WHERE ip_port=? AND seen_at=?", (ip_port, seen_at)).fetchone()
        if row is not None:
            players = merge_player_blobs(row[0], players)
            con.execute(
                "UPDATE server_history SET players=?"
                " WHERE ip_port=? AND seen_at=?",
                (players, ip_port, seen_at))
            if players:
                con.execute(
                    "UPDATE server_history SET synced=0"
                    " WHERE ip_port=? AND seen_at=?", (ip_port, seen_at))
            return
    con.execute(
        "INSERT OR IGNORE INTO server_history"
        " (ip_port, seen_at, players_online, max_players, players, synced)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        (ip_port, seen_at, players_online, max_players, players, synced))


def name_list(value) -> list[str]:
    """Decode a players_now/players_ever JSON value into names."""
    return _name_list(value)


def insert_history(con, ip_port, seen_at, players_online=None,
                   max_players=None, names=(), synced=0, merge=False):
    """Insert one sighting (and its player samples) with duplicate safety."""
    _insert_history(con, ip_port, seen_at, players_online, max_players, names,
                    synced, merge=merge)


def insert_range(con, ip_port, first_seen, last_seen, players_online,
                 max_players, now_names=(), ever_names=(), synced=0):
    """Insert the two endpoints of an aggregated first/last-seen record.

    Used by sync and by the format migration: the current roster/count
    belongs to the last sighting, while the ever-seen names are attached to
    the first sighting so they are not lost.  When both endpoints are the
    same, there is one sighting with both player lists.
    """
    first_seen = _to_float(first_seen)
    last_seen = _to_float(last_seen)
    if first_seen <= 0 and last_seen <= 0:
        return
    if first_seen <= 0:
        first_seen = last_seen
    if last_seen <= 0:
        last_seen = first_seen
    if abs(last_seen - first_seen) < 1e-9:
        _insert_history(con, ip_port, first_seen, players_online,
                        max_players, list(ever_names) + list(now_names),
                        synced)
    else:
        _insert_history(con, ip_port, first_seen, None, None, ever_names,
                        synced)
        _insert_history(con, ip_port, last_seen, players_online,
                        max_players, now_names, synced)


def _populate_history_from_columns(con: sqlite3.Connection):
    """Seed history from a format-2 ``servers`` table."""
    names = set(_column_names(con, "servers"))
    if "first_seen" not in names and "last_seen" not in names:
        return
    extra = [name for name in
             ("players_online", "max_players", "players_now", "players_ever")
             if name in names]
    select = ["ip_port"]
    if "first_seen" in names:
        select.append("first_seen")
    else:
        select.append("NULL")
    if "last_seen" in names:
        select.append("last_seen")
    else:
        select.append("NULL")
    for name in extra:
        select.append(name)
    # Pad missing optional columns so unpacking below is simple.
    rows = con.execute(
        f"SELECT {', '.join(select)} FROM servers").fetchall()
    for row in rows:
        ip_port = str(row[0] or "")
        first_seen = _to_float(row[1])
        last_seen = _to_float(row[2])
        values = dict(zip(extra, row[3:]))
        online = _to_int(values.get("players_online"), 0)
        maximum = _to_int(values.get("max_players"), 0)
        now_names = _name_list(values.get("players_now"))
        ever_names = _name_list(values.get("players_ever"))
        if first_seen <= 0 and last_seen <= 0:
            continue
        if first_seen <= 0:
            first_seen = last_seen
        if last_seen <= 0:
            last_seen = first_seen
        if abs(last_seen - first_seen) < 1e-9:
            # Single known sighting: its current player data belongs here.
            _insert_history(con, ip_port, first_seen, online, maximum,
                            list(ever_names) + list(now_names))
        else:
            # Every-seen names go to the first sighting so they survive;
            # today's online count/roster belongs to the last sighting.
            _insert_history(con, ip_port, first_seen, None, None, ever_names)
            _insert_history(con, ip_port, last_seen, online, maximum,
                            now_names)


def detect_format(con: sqlite3.Connection) -> int:
    """4 for blob rosters, 3 for history-derived servers, 2/1 legacy.

    ``user_version`` is authoritative, but the schema is a useful fallback
    for databases created by an interrupted migration.
    """
    try:
        version = int(con.execute("PRAGMA user_version").fetchone()[0] or 0)
    except Exception:
        version = 0
    if version >= 4:
        return 4
    if object_type(con, "server_history") == "table":
        columns = {str(row[1]) for row in
                   con.execute("PRAGMA table_info(server_history)")}
        if ("players" in columns
                and object_type(con, "player_history") != "table"):
            return 4
    if object_type(con, SERVER_VIEW) == "view" and \
            object_type(con, STATE_TABLE) == "table":
        return 3
    if version >= 3:
        return 3
    if version >= 2:
        return 2
    for _cid, name, ctype, _notnull, _default, _pk in _table_columns(con):
        if str(name).lower() == "cracked":
            return 2 if "INT" in str(ctype or "").upper() else 1
    return 1


def cracked_state(value):
    """Any format-1 label or format-2 value -> 0, 1, or None (unset)."""
    if value is None:
        return None
    if isinstance(value, bool):
        return 1 if value else 0
    if isinstance(value, (int, float)):
        return 1 if value else 0
    text = str(value).strip().lower()
    if not text or text in ("unknown", "unset", "?", "null", "none"):
        return None
    if text in ("1", "true", "yes", "yes (cached)", "yes (heuristic)"):
        return 1
    if text.startswith("yes"):
        return 1
    if text in ("0", "false", "no"):
        return 0
    return None


def cracked_bool(value) -> int:
    """Any format-1 label or format-2 value -> 0/1 (None -> 0)."""
    return cracked_state(value) or 0


def cracked_text(value) -> str:
    """Format-2 state / format-1 label -> the legacy display label."""
    state = cracked_state(value)
    if state is None:
        return ""
    return "Yes" if state else "No"


def source_is_cracked_verdict(source) -> bool:
    """True when last_source marks an authoritative cracked/online verdict.

    ``cracked`` rows are written by the explicit cracked checker (or the
    whitelist probe).  Plain scan sources are heuristic and must never
    overwrite an existing verdict.
    """
    return str(source or "").strip().lower() == "cracked"


def _host_for(ip_port: str) -> str:
    return str(ip_port or "").rsplit(":", 1)[0]


def row_for_format(row: dict, target: int) -> dict:
    """Convert one row between formats without mutating the input."""
    out = dict(row)
    out["cracked"] = cracked_state(row.get("cracked"))
    if target >= 2:
        out["host"] = None
        for name in ("players_now", "players_ever"):
            if out.get(name) in (None, "", "[]"):
                out[name] = None
    else:
        out["cracked"] = cracked_text(out["cracked"])
        if not out.get("host"):
            out["host"] = _host_for(str(row.get("ip_port", "")))
        for name in ("players_now", "players_ever"):
            if not out.get(name):
                out[name] = "[]"
    return out


def _column_defs(columns) -> list[str]:
    defs = []
    for _cid, name, ctype, notnull, default, pk in columns:
        name = str(name)
        if name == "cracked":
            defs.append("cracked INTEGER DEFAULT NULL")
        elif name in ("players_now", "players_ever"):
            defs.append(f"{name} TEXT")
        else:
            ddl = f"{name} {ctype or 'TEXT'}"
            if notnull:
                ddl += " NOT NULL"
            if default is not None:
                ddl += f" DEFAULT {default}"
            if pk:
                ddl += " PRIMARY KEY"
            defs.append(ddl)
    return defs


def _select_expr(name: str) -> str:
    if name == "cracked":
        return (
            "CASE "
            "WHEN cracked IS NULL OR trim(CAST(cracked AS TEXT))='' THEN NULL "
            "WHEN lower(trim(CAST(cracked AS TEXT))) LIKE 'yes%' THEN 1 "
            "WHEN lower(trim(CAST(cracked AS TEXT))) IN ('no','false') THEN 0 "
            "WHEN trim(CAST(cracked AS TEXT)) IN ('0','1') "
            "  THEN CAST(trim(CAST(cracked AS TEXT)) AS INTEGER) "
            "WHEN typeof(cracked) IN ('integer','real') "
            "  THEN (CASE WHEN cracked <> 0 THEN 1 ELSE 0 END) "
            "ELSE NULL END"
        )
    if name in ("players_now", "players_ever"):
        return f"NULLIF(NULLIF({name},'[]'),'')"
    if name == "host":
        return ("CASE WHEN host IS NULL OR "
                "host=substr(ip_port,1,instr(ip_port,':')-1) "
                "THEN NULL ELSE host END")
    return name


def _migrate_1_to_2(con: sqlite3.Connection) -> bool:
    """Rebuild the format-1 servers table as format 2. Returns True if
    it changed anything."""
    columns = _table_columns(con)
    if not columns:
        return False
    names = [str(c[1]) for c in columns]
    if "cracked" not in names:
        return False
    defs = ", ".join(_column_defs(columns))
    exprs = ", ".join(_select_expr(name) for name in names)
    quoted = ", ".join(f'"{name}"' for name in names)
    try:
        con.execute("BEGIN IMMEDIATE")
        con.execute("DROP TABLE IF EXISTS servers_v2")
        con.execute(f"CREATE TABLE servers_v2 ({defs})")
        con.execute(
            f"INSERT INTO servers_v2 ({quoted}) SELECT {exprs} FROM servers")
        con.execute("DROP TABLE servers")
        con.execute("ALTER TABLE servers_v2 RENAME TO servers")
        if "last_seen" in names:
            con.execute("CREATE INDEX IF NOT EXISTS idx_servers_last_seen "
                        "ON servers(last_seen DESC)")
        if "version" in names:
            con.execute("CREATE INDEX IF NOT EXISTS idx_servers_version "
                        "ON servers(version)")
        if "seq" in names:
            con.execute("CREATE INDEX IF NOT EXISTS idx_servers_seq "
                        "ON servers(seq ASC)")
        con.execute("PRAGMA user_version=2")
        con.commit()
        try:
            con.execute("VACUUM")
        except Exception:
            pass
        return True
    except Exception:
        try:
            con.rollback()
        except Exception:
            pass
        raise


def _init_v3(con: sqlite3.Connection):
    con.execute(SERVER_STATE_SCHEMA)
    init_history_schema(con)
    ensure_view(con)
    con.execute("PRAGMA user_version=3")


def _migrate_2_to_3(con: sqlite3.Connection) -> bool:
    """Convert first/last-seen columns into history points. Returns True."""
    if object_type(con, "servers") != "table":
        if object_type(con, STATE_TABLE) != "table":
            _init_v3(con)
            return True
        init_history_schema(con)
        ensure_view(con)
        con.execute("PRAGMA user_version=3")
        return False
    changed = False
    try:
        con.execute("BEGIN IMMEDIATE")
        init_history_schema(con)
        _populate_history_from_columns(con)
        names = set(_column_names(con, "servers"))
        con.execute("DROP INDEX IF EXISTS idx_servers_last_seen")
        con.execute("ALTER TABLE servers RENAME TO server_state")
        if "first_seen" in names:
            con.execute("ALTER TABLE server_state DROP COLUMN first_seen")
        if "last_seen" in names:
            con.execute("ALTER TABLE server_state DROP COLUMN last_seen")
        ensure_view(con)
        con.execute("PRAGMA user_version=3")
        con.commit()
        changed = True
        try:
            con.execute("VACUUM")
        except Exception:
            pass
        return changed
    except Exception:
        try:
            con.rollback()
        except Exception:
            pass
        raise


def _migrate_3_to_4(con: sqlite3.Connection) -> bool:
    """Fold ``player_history`` into a roster blob on each sighting."""
    con.execute(
        "CREATE TABLE IF NOT EXISTS server_history ("
        " ip_port TEXT NOT NULL, seen_at REAL NOT NULL,"
        " players_online INTEGER, max_players INTEGER,"
        " players TEXT, synced INTEGER DEFAULT 0,"
        " PRIMARY KEY (ip_port, seen_at))")
    columns = {str(row[1]) for row in
               con.execute("PRAGMA table_info(server_history)")}
    if "players" not in columns:
        con.execute("ALTER TABLE server_history ADD COLUMN players TEXT")
    if "synced" not in columns:
        con.execute("ALTER TABLE server_history"
                    " ADD COLUMN synced INTEGER DEFAULT 0")
    if object_type(con, "player_history") != "table":
        con.execute("PRAGMA user_version=4")
        return False
    changed = False
    state = {"key": None, "names": []}

    def flush():
        nonlocal changed
        ip_port, seen_at = state["key"]
        blob = encode_player_blob(state["names"])
        state["names"] = []
        if blob is None:
            return
        row = con.execute(
            "SELECT players FROM server_history"
            " WHERE ip_port=? AND seen_at=?",
            (ip_port, seen_at)).fetchone()
        if row is None:
            con.execute(
                "INSERT OR IGNORE INTO server_history"
                " (ip_port, seen_at, players_online, max_players,"
                " players, synced) VALUES (?, ?, NULL, NULL, ?, 0)",
                (ip_port, seen_at, blob))
            changed = True
            return
        merged = merge_player_blobs(row[0], blob)
        if merged != row[0]:
            con.execute(
                "UPDATE server_history SET players=?, synced=0"
                " WHERE ip_port=? AND seen_at=?",
                (merged, ip_port, seen_at))
            changed = True

    try:
        con.execute("BEGIN IMMEDIATE")
        # Streamed, not grouped in memory: a Pi with a large history file
        # should not need hundreds of MB just to migrate.
        for ip_port, seen_at, name in con.execute(
                "SELECT ip_port, seen_at, player_name FROM player_history"
                " ORDER BY ip_port, seen_at"):
            key = (str(ip_port or ""), float(seen_at or 0))
            if not key[0] or key[1] <= 0:
                continue
            if key != state["key"]:
                if state["key"] is not None:
                    flush()
                state["key"] = key
            state["names"].append(name)
        if state["key"] is not None:
            flush()
        con.execute("DROP TABLE player_history")
        con.execute("PRAGMA user_version=4")
        con.commit()
        try:
            con.execute("VACUUM")
        except Exception:
            pass
        return True
    except Exception:
        try:
            con.rollback()
        except Exception:
            pass
        raise


def migrate(con: sqlite3.Connection) -> bool:
    """Upgrade the database to the current format in place."""
    changed = False
    if detect_format(con) < 2:
        changed = _migrate_1_to_2(con) or changed
    if detect_format(con) < 3:
        changed = _migrate_2_to_3(con) or changed
    if detect_format(con) < CURRENT_FORMAT:
        changed = _migrate_3_to_4(con) or changed
    try:
        version = int(con.execute("PRAGMA user_version").fetchone()[0] or 0)
    except Exception:
        version = 0
    if version < CURRENT_FORMAT:
        try:
            con.execute(f"PRAGMA user_version={CURRENT_FORMAT}")
            con.commit()
        except Exception:
            pass
    return changed


def _json_name_list(names):
    return json.dumps(names, ensure_ascii=False) if names else None


def clean_spoofed_player_data(con: sqlite3.Connection):
    """Drop ad/spoof names from activity and scrub stored player lists.

    "Anonymous Player" is kept in the players_now/players_ever lists but is
    not a real player, so it is removed from the roster history.
    """
    try:
        con.execute(
            "CREATE TABLE IF NOT EXISTS db_meta ("
            " key TEXT PRIMARY KEY, value TEXT)"
        )
        row = con.execute(
            "SELECT value FROM db_meta WHERE key='player_name_filter'"
        ).fetchone()
        if row and str(row[0]) == "3":
            return
        if object_type(con, "player_history") == "table":
            names = [r[0] for r in con.execute(
                "SELECT DISTINCT player_name FROM player_history")]
            bad = [name for name in names
                   if is_spoofed_player_name(name)
                   or is_anonymous_player_name(name)]
            if bad:
                con.executemany(
                    "DELETE FROM player_history WHERE player_name=?",
                    [(name,) for name in bad])
        if object_type(con, "server_history") == "table":
            cur = con.execute(
                "SELECT rowid, players FROM server_history"
                " WHERE players IS NOT NULL")
            updates = []
            while True:
                rows = cur.fetchmany(1000)
                if not rows:
                    break
                for rowid, blob in rows:
                    cleaned = encode_player_blob(_blob_names(blob))
                    if cleaned != blob:
                        updates.append((cleaned, rowid))
                if len(updates) >= 1000:
                    con.executemany(
                        "UPDATE server_history SET players=?"
                        " WHERE rowid=?", updates)
                    updates.clear()
            if updates:
                con.executemany(
                    "UPDATE server_history SET players=? WHERE rowid=?",
                    updates)
        if object_type(con, STATE_TABLE) == "table":
            cur = con.execute(
                "SELECT ip_port, players_now, players_ever FROM server_state")
            updates = []
            while True:
                rows = cur.fetchmany(1000)
                if not rows:
                    break
                for ip_port, now, ever in rows:
                    new_now = _json_name_list(_name_list(now))
                    new_ever = _json_name_list(_name_list(ever))
                    if new_now != now or new_ever != ever:
                        updates.append((new_now, new_ever, ip_port))
                if len(updates) >= 1000:
                    con.executemany(
                        "UPDATE server_state SET players_now=?,"
                        " players_ever=? WHERE ip_port=?", updates)
                    updates.clear()
            if updates:
                con.executemany(
                    "UPDATE server_state SET players_now=?,"
                    " players_ever=? WHERE ip_port=?", updates)
        con.execute(
            "INSERT OR REPLACE INTO db_meta (key, value)"
            " VALUES ('player_name_filter', '3')")
        con.commit()
    except Exception:
        pass


def ensure_format(con: sqlite3.Connection) -> int:
    migrate(con)
    fmt = detect_format(con)
    if fmt >= CURRENT_FORMAT:
        init_history_schema(con)
        ensure_view(con)
        con.execute(f"PRAGMA user_version={CURRENT_FORMAT}")
        con.commit()
        clean_spoofed_player_data(con)
    return detect_format(con)
