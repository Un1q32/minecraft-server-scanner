"""Shared on-disk format helpers for the scanner and shared DB server.

Format 1 stored ``cracked`` as a display string ("Yes", "No",
"Yes (cached)", ...).  Format 2 stores it as a SQLite integer state
(1 = yes, 0 = no, NULL = unset/unknown) and also drops redundant/empty
payloads (host duplicated by ip_port, empty player lists as NULL).
SQLite's ``PRAGMA user_version`` marks the format; older databases have 0
and are migrated in place.
"""

from __future__ import annotations

import sqlite3

CURRENT_FORMAT = 2
BASE_FORMAT = 1


def _table_columns(con: sqlite3.Connection):
    return list(con.execute("PRAGMA table_info(servers)"))


def detect_format(con: sqlite3.Connection) -> int:
    """2 when the table is format 2; 1 for the legacy schema.

    ``user_version`` is authoritative, but the cracked column type is a
    useful fallback for databases created by an interrupted migration.
    """
    try:
        version = int(con.execute("PRAGMA user_version").fetchone()[0] or 0)
    except Exception:
        version = 0
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


def migrate(con: sqlite3.Connection) -> bool:
    """Upgrade servers to format 2 in place. Returns True if it changed."""
    if detect_format(con) >= 2:
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
        return False
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
        con.execute(f"PRAGMA user_version={CURRENT_FORMAT}")
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


def ensure_format(con: sqlite3.Connection) -> int:
    migrate(con)
    return detect_format(con)
