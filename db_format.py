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

Format 5 keeps the format-4 schema.  The marker enables the 4-day activity
retention policy and the shared server rejects sync uploads from older
formats, so every node must update its scanner/database before syncing
again.

SQLite's ``PRAGMA user_version`` marks the format; older databases have 0
and are migrated in place.
"""

from __future__ import annotations

import json
import sqlite3
import time
import unicodedata

CURRENT_FORMAT = 5
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


# Activity history retention and thinning.  Sighting rows power the
# charts; players_ever lives in server_state and is never touched here.
HISTORY_RETENTION_SECONDS = 4 * 86400
ACTIVITY_PLAYER_GAP_SECONDS = 5 * 60
ACTIVITY_EMPTY_GAP_SECONDS = 30 * 60


def prune_history(con: sqlite3.Connection, max_age_seconds=HISTORY_RETENTION_SECONDS,
                  now=None) -> int:
    """Delete sightings older than the retention window.

    The newest sighting per server is always kept, even when it is older
    than the window, so last-seen dates survive for dormant servers and the
    rescan tiers can still find them.  The seen-names roster
    (``players_ever``) is stored on server_state and is not affected.
    """
    cutoff = (time.time() if now is None else float(now)) - max_age_seconds
    cur = con.execute(
        "DELETE FROM server_history"
        " WHERE seen_at < ?"
        "   AND EXISTS (SELECT 1 FROM server_history newer"
        "               WHERE newer.ip_port = server_history.ip_port"
        "                 AND newer.seen_at > server_history.seen_at)",
        (cutoff,))
    return max(0, int(cur.rowcount or 0))


def prune_activity(con: sqlite3.Connection, max_age_seconds=HISTORY_RETENTION_SECONDS,
                   player_gap_seconds=ACTIVITY_PLAYER_GAP_SECONDS,
                   empty_gap_seconds=ACTIVITY_EMPTY_GAP_SECONDS,
                   now=None) -> dict:
    """Drop old sightings and thin the rest to the rescan resolution.

    A sighting with sampled players is kept at most once per
    ``player_gap_seconds``; an empty sighting once per
    ``empty_gap_seconds``.  The first and newest sighting of every server
    are always kept so first/last-seen and the latest activity survive.
    ``prune_history`` keeps the newest row even when it is older than the
    retention window.
    Returns counts for old rows removed and rows thinned.
    """
    now = time.time() if now is None else float(now)
    removed_old = prune_history(con, max_age_seconds, now)

    con.execute("DROP TABLE IF EXISTS temp.history_prune_ids")
    con.execute("CREATE TEMP TABLE history_prune_ids (rowid INTEGER PRIMARY KEY)")
    rows = con.execute(
        "SELECT rowid, ip_port, seen_at,"
        " CASE WHEN players IS NOT NULL AND length(players) > 0"
        "      THEN 1 ELSE 0 END"
        " FROM server_history ORDER BY ip_port ASC, seen_at ASC")
    pending = []
    current_ip = None
    last_kept = 0.0
    last_was_deleted = False
    batch = []

    def flush_pending():
        nonlocal pending, batch
        if pending:
            batch.extend(pending)
            pending = []

    def flush_batch():
        nonlocal batch
        if batch:
            con.executemany(
                "INSERT OR IGNORE INTO history_prune_ids(rowid) VALUES (?)",
                ((rowid,) for rowid in batch))
            batch = []

    for rowid, ip, seen_at, has_players in rows:
        if ip != current_ip:
            # Keep the newest point of the previous server even when it
            # falls inside the spacing window.
            if last_was_deleted and pending:
                pending.pop()
            flush_pending()
            flush_batch()
            current_ip = ip
            last_kept = float(seen_at or 0)
            last_was_deleted = False
            continue
        gap = float(seen_at or 0) - last_kept
        threshold = (player_gap_seconds if has_players
                     else empty_gap_seconds)
        if gap >= threshold:
            flush_pending()
            last_kept = float(seen_at or 0)
            last_was_deleted = False
        else:
            pending.append(rowid)
            last_was_deleted = True

    if last_was_deleted and pending:
        pending.pop()
    flush_pending()
    flush_batch()
    rows.close()

    con.execute(
        "DELETE FROM server_history WHERE rowid IN"
        " (SELECT rowid FROM history_prune_ids)")
    thinned = int(con.execute(
        "SELECT COUNT(*) FROM history_prune_ids").fetchone()[0] or 0)
    con.execute("DROP TABLE IF EXISTS temp.history_prune_ids")
    return {"removed_old": removed_old, "thinned": thinned}


def name_list(value) -> list[str]:
    """Decode a players_now/players_ever JSON value into names."""
    return _name_list(value)


DEDUPE_MIN_PORTS = 5
DEDUPE_PLAYER_CAP = 500


def _dedupe_chunks(values, size=500):
    values = list(values)
    for start in range(0, len(values), size):
        yield values[start:start + size]


def _dedupe_signature(motd, version, protocol):
    try:
        protocol = int(protocol)
    except Exception:
        protocol = -1
    return (str(motd or "").strip().lower(),
            str(version or "").strip().lower(), protocol)


def _dedupe_port(ip_port):
    try:
        return int(str(ip_port).rsplit(":", 1)[1])
    except Exception:
        return 0


def _dedupe_host(ip_port):
    return str(ip_port).rsplit(":", 1)[0]


def _dedupe_whitelist_rank(value):
    text = str(value or "").strip().lower()
    if text.startswith("not whitelisted"):
        return 3
    if text.startswith("whitelisted"):
        return 2
    if text.startswith("unknown"):
        return 1
    return 0


def _dedupe_names(value, out):
    for name in _name_list(value):
        out.add(name)


def deduplicate_ports(con, min_ports=DEDUPE_MIN_PORTS, mark_dirty=True):
    """Merge a host that answers identically on many ports into one row.

    This is the same rule the Minecraft viewer applies: same host + same
    MOTD/version/protocol, with at least ``min_ports`` rows.  The
    representative prefers port 25565, then the most-seen port.  Duplicate
    history is removed (after preserving the group's first/last endpoints on
    the representative) so VACUUM can reclaim the file space.

    The caller owns the transaction and must commit/rollback.  Returns a dict
    with groups/removed/inserted counts.
    """
    table = base_table(con)
    columns = {str(row[1]) for row in con.execute(f"PRAGMA table_info({table})")}
    required = {"ip_port", "motd", "version", "protocol", "players_online",
                "max_players", "times_seen", "players_now", "players_ever"}
    if not required.issubset(columns):
        return {"groups": 0, "removed_state": 0, "removed_history": 0,
                "inserted_history": 0}
    has_needs_sync = "needs_sync" in columns
    has_seq = "seq" in columns

    old_factory = con.row_factory
    con.row_factory = sqlite3.Row
    try:
        groups = {}
        for row in con.execute(f"SELECT * FROM {table}"):
            key = (_dedupe_host(row["ip_port"]),
                   _dedupe_signature(row["motd"], row["version"], row["protocol"]))
            groups.setdefault(key, []).append(row)
        work = [group for group in groups.values() if len(group) >= min_ports]
        if not work:
            return {"groups": 0, "removed_state": 0, "removed_history": 0,
                    "inserted_history": 0}

        history = {}
        all_ips = [row["ip_port"] for group in work for row in group]
        for chunk in _dedupe_chunks(all_ips):
            marks = ",".join("?" * len(chunk))
            for ip, first, last in con.execute(
                    f"SELECT ip_port, MIN(seen_at), MAX(seen_at)"
                    f" FROM server_history WHERE ip_port IN ({marks})"
                    f" GROUP BY ip_port", chunk):
                history[ip] = (float(first or 0), float(last or 0))

        removed_state = removed_history = inserted_history = 0
        synced = 0 if (has_needs_sync and mark_dirty) else 1
        for group in work:
            representative = group[0]
            best_port = _dedupe_port(representative["ip_port"]) == 25565
            for row in group[1:]:
                canonical = _dedupe_port(row["ip_port"]) == 25565
                if canonical != best_port:
                    if canonical:
                        representative = row
                        best_port = True
                    continue
                if int(row["times_seen"] or 0) > int(representative["times_seen"] or 0):
                    representative = row
                elif (int(row["times_seen"] or 0) == int(representative["times_seen"] or 0)
                      and int(row["players_online"] or 0) > int(representative["players_online"] or 0)):
                    representative = row

            ever_names = set()
            now_names = []
            online = maximum = times_seen = 0
            cracked = None
            whitelist = ""
            source = ""
            for row in group:
                _dedupe_names(row["players_ever"], ever_names)
                _dedupe_names(row["players_now"], ever_names)
                names_now = _name_list(row["players_now"])
                if names_now and not now_names:
                    now_names = names_now
                online = max(online, int(row["players_online"] or 0))
                maximum = max(maximum, int(row["max_players"] or 0))
                times_seen = max(times_seen, int(row["times_seen"] or 0))
                if cracked is None and row["cracked"] is not None:
                    cracked = row["cracked"]
                if _dedupe_whitelist_rank(row["whitelist"]) > _dedupe_whitelist_rank(whitelist):
                    whitelist = row["whitelist"] or ""
                if source_is_cracked_verdict(row["last_source"]):
                    source = row["last_source"] or ""
            if not source:
                source = representative["last_source"] or ""
            if not now_names:
                now_names = _name_list(representative["players_now"])
            if not whitelist:
                whitelist = representative["whitelist"] or ""
            if cracked is None:
                cracked = representative["cracked"]

            first = min((history[ip][0] for ip in
                         (row["ip_port"] for row in group)
                         if ip in history and history[ip][0] > 0), default=0.0)
            last = max((history[ip][1] for ip in
                        (row["ip_port"] for row in group)
                        if ip in history), default=0.0)
            if first > 0 and last >= first:
                insert_range(con, representative["ip_port"], first, last,
                             online, maximum, now_names,
                             sorted(ever_names, key=str.lower)[:DEDUPE_PLAYER_CAP],
                             synced=synced)
                inserted_history += 2 if abs(last - first) >= 1e-9 else 1

            duplicate_ips = [row["ip_port"] for row in group
                             if row["ip_port"] != representative["ip_port"]]
            for chunk in _dedupe_chunks(duplicate_ips):
                marks = ",".join("?" * len(chunk))
                cur = con.execute(
                    f"DELETE FROM server_history WHERE ip_port IN ({marks})", chunk)
                removed_history += max(0, cur.rowcount)

            ever_json = json.dumps(sorted(ever_names, key=str.lower)[:DEDUPE_PLAYER_CAP],
                                   ensure_ascii=False) if ever_names else None
            now_json = json.dumps(now_names[:DEDUPE_PLAYER_CAP],
                                  ensure_ascii=False) if now_names else None
            assignments = [
                "motd=?", "players_online=?", "max_players=?", "version=?",
                "protocol=?", "cracked=?", "whitelist=?", "times_seen=?",
                "last_source=?", "players_now=?", "players_ever=?",
            ]
            values = [representative["motd"], online, maximum,
                      representative["version"], representative["protocol"],
                      cracked, whitelist, times_seen, source, now_json, ever_json]
            if has_needs_sync:
                assignments.append("needs_sync=1" if mark_dirty else "needs_sync=0")
            if has_seq:
                assignments.append(
                    f"seq=(SELECT COALESCE(MAX(seq), 0) + 1 FROM {table})")
            con.execute(
                f"UPDATE {table} SET {', '.join(assignments)} WHERE ip_port=?",
                (*values, representative["ip_port"]))

            for chunk in _dedupe_chunks(duplicate_ips):
                marks = ",".join("?" * len(chunk))
                cur = con.execute(
                    f"DELETE FROM {table} WHERE ip_port IN ({marks})", chunk)
                removed_state += max(0, cur.rowcount)

        return {"groups": len(work), "removed_state": removed_state,
                "removed_history": removed_history,
                "inserted_history": inserted_history}
    finally:
        con.row_factory = old_factory


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
    if version >= CURRENT_FORMAT:
        return CURRENT_FORMAT
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


def _migrate_4_to_5(con: sqlite3.Connection) -> bool:
    """Format 5 applies the activity-retention policy.

    The schema is unchanged, but the conversion prunes sightings older than
    4 days and thins the rest to the rescan resolution, then vacuums so the
    one-time upgrade also reclaims the file space.
    """
    stats = prune_activity(con)
    con.execute("PRAGMA user_version=5")
    con.commit()
    try:
        con.execute("VACUUM")
    except Exception:
        pass
    return bool(stats.get("removed_old") or stats.get("thinned"))


def migrate(con: sqlite3.Connection) -> bool:
    """Upgrade the database to the current format in place."""
    changed = False
    if detect_format(con) < 2:
        changed = _migrate_1_to_2(con) or changed
    if detect_format(con) < 3:
        changed = _migrate_2_to_3(con) or changed
    if detect_format(con) < 4:
        changed = _migrate_3_to_4(con) or changed
    if detect_format(con) < CURRENT_FORMAT:
        changed = _migrate_4_to_5(con) or changed
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


UNVERIFIED_CRACKED_CLEANUP_KEY = "unverified_cracked_cleanup_v1"


def clear_unverified_cracked_once(con: sqlite3.Connection) -> int:
    """Clear heuristic (non-authoritative) cracked verdicts once per database.

    Status-sample heuristics used to write cracked=1 with last_source='scan'.
    Those were never authoritative and produced false positives.  Explicit
    cracked-checker rows (last_source='cracked') are left alone.
    """
    try:
        con.execute(
            "CREATE TABLE IF NOT EXISTS db_meta ("
            " key TEXT PRIMARY KEY, value TEXT)")
        if con.execute("SELECT 1 FROM db_meta WHERE key=? LIMIT 1",
                       (UNVERIFIED_CRACKED_CLEANUP_KEY,)).fetchone():
            return 0
        columns = {str(row[1]) for row in
                   con.execute("PRAGMA table_info(server_state)")}
        if "cracked" not in columns or "last_source" not in columns:
            return 0
        updates = ["cracked=NULL", "last_source='cracked'"]
        if "needs_sync" in columns:
            updates.append("needs_sync=1")
        if "seq" in columns:
            updates.append(
                "seq=(SELECT COALESCE(MAX(seq), 0) + 1 FROM server_state)")
        cur = con.execute(
            "UPDATE server_state SET " + ", ".join(updates)
            + " WHERE cracked=1 AND (last_source IS NULL"
            + " OR lower(trim(last_source)) != 'cracked')")
        con.execute(
            "INSERT OR REPLACE INTO db_meta (key, value) VALUES (?, '1')",
            (UNVERIFIED_CRACKED_CLEANUP_KEY,))
        con.commit()
        return max(0, int(cur.rowcount or 0))
    except Exception:
        try:
            con.rollback()
        except Exception:
            pass
        return 0


def ensure_format(con: sqlite3.Connection) -> int:
    migrate(con)
    fmt = detect_format(con)
    if fmt >= CURRENT_FORMAT:
        init_history_schema(con)
        ensure_view(con)
        con.execute(f"PRAGMA user_version={CURRENT_FORMAT}")
        con.commit()
        clean_spoofed_player_data(con)
        clear_unverified_cracked_once(con)
    return detect_format(con)
