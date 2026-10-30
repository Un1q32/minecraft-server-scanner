//! Read-only access to `servers.db`.
//!
//! Qt's `ListView` only ever asks for the visible rows, so the loader keeps
//! just the columns needed to draw a line and formats it on demand. The
//! detail pane is a separate single-row lookup when the user selects a row.
//! That keeps opening a 100k+ row database cheap and memory flat.

use chrono::TimeZone;
use rusqlite::{Connection, OpenFlags};
use std::fmt::Write as _;
use std::time::Instant;

use crate::search;

pub struct Row {
    pub ip: String,
    pub motd: String,
    pub players: i64,
    pub max_players: i64,
    pub version: String,
    pub cracked: String,
    pub whitelist: String,
    pub names_now: String,
    pub names_ever: String,
    pub first_seen: f64,
    pub last_seen: f64,
    pub times_seen: i64,
}

pub struct Loaded {
    pub rows: Vec<Row>,
    pub total: i64,
    pub ms: u128,
}

// Column widths, in monospace characters, of the fixed-width row string.
const IP_W: usize = 21;
const MOTD_W: usize = 52;
const PLAYERS_W: usize = 9;
const VERSION_W: usize = 22;
const CRACKED_W: usize = 3;

fn open_read_only(path: &str) -> Result<Connection, String> {
    if !std::path::Path::new(path).is_file() {
        return Err(format!("no such database: {path}"));
    }
    let con = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .or_else(|_| Connection::open(path))
    .map_err(|e| format!("cannot open {path}: {e}"))?;
    con.busy_timeout(std::time::Duration::from_millis(3000))
        .map_err(|e| e.to_string())?;
    Ok(con)
}

fn has_column(con: &Connection, name: &str) -> bool {
    let Ok(mut stmt) = con.prepare("PRAGMA table_info(servers)") else {
        return false;
    };
    let Ok(rows) = stmt.query_map([], |r| r.get::<_, String>(1)) else {
        return false;
    };
    let mut found = false;
    for col in rows.flatten() {
        if col.eq_ignore_ascii_case(name) {
            found = true;
            break;
        }
    }
    found
}

fn col_or(con: &Connection, name: &str, fallback: &str) -> String {
    if has_column(con, name) {
        format!("COALESCE({name}, {fallback})")
    } else {
        fallback.to_string()
    }
}

/// Controls/bidi characters hidden from display. U+200C/U+200D are kept so
/// emoji ZWJ sequences and scripts using ZWNJ/ZWJ render normally.
fn is_hidden(ch: char) -> bool {
    matches!(ch,
        '\u{061c}' | '\u{180e}' | '\u{200b}' | '\u{200e}' | '\u{200f}'
        | '\u{202a}'..='\u{202e}' | '\u{2060}'..='\u{206f}' | '\u{feff}')
}

/// Remove terminal/UI control and bidi characters from server-controlled
/// database text. Newlines/tabs become spaces for single-line cells.
fn clean_display(value: &str) -> String {
    value
        .chars()
        .filter(|&ch| {
            matches!(ch, '\n' | '\r' | '\t') || (!ch.is_control() && !is_hidden(ch))
        })
        .map(|ch| match ch {
            '\n' | '\r' | '\t' => ' ',
            other => other,
        })
        .collect()
}

/// Like [`clean_display`], but keeps newlines for the multi-line detail pane.
/// Tabs are expanded because Qt's plain-text edit renders them inconsistently.
fn clean_multiline(value: &str) -> String {
    value
        .chars()
        .filter(|&ch| {
            matches!(ch, '\n' | '\t') || (!ch.is_control() && !is_hidden(ch))
        })
        .flat_map(|ch| match ch {
            '\t' => "    ".chars().collect::<Vec<_>>(),
            other => vec![other],
        })
        .collect()
}

/// Copy `value` into `out`, clipped/padded to `width` characters.
fn push_field(out: &mut String, value: &str, width: usize) {
    let clean = clean_display(value);
    let clipped = clean.chars().count() > width;
    // Leave room for an ellipsis so a cut field is visibly cut.
    let limit = if clipped { width.saturating_sub(1) } else { width };
    let mut used = 0;
    for ch in clean.chars().take(limit) {
        out.push(ch);
        used += 1;
    }
    if clipped {
        out.push('…');
        used += 1;
    }
    for _ in used..width {
        out.push(' ');
    }
}

pub fn cracked_short(cracked: &str) -> &'static str {
    match cracked.to_ascii_lowercase().as_str() {
        "" => "",
        "no" => "no",
        "yes" => "yes",
        "yes (cached)" => "yes*",
        "yes (heuristic)" => "yes?",
        _ => "yes",
    }
}

fn push_timestamp(out: &mut String, epoch: f64) {
    if epoch <= 0.0 {
        out.push('-');
        return;
    }
    match chrono::Local.timestamp_opt(epoch as i64, 0) {
        chrono::LocalResult::Single(dt) => {
            let _ = write!(out, "{}", dt.format("%Y-%m-%d %H:%M"));
        }
        _ => out.push('-'),
    }
}

/// Collapse a database string to a single table cell line.
pub fn one_line(value: &str) -> String {
    clean_display(value)
}

/// The fixed-width line used by `--selftest`; the GUI draws real columns.
pub fn display_line(row: &Row) -> String {
    let mut out = String::with_capacity(140);
    push_field(&mut out, &row.ip, IP_W);
    out.push(' ');
    push_field(&mut out, &row.motd, MOTD_W);
    out.push(' ');
    let players = format!("{}/{}", row.players, row.max_players);
    push_field(&mut out, &players, PLAYERS_W);
    out.push(' ');
    push_field(&mut out, &row.version, VERSION_W);
    out.push(' ');
    push_field(&mut out, cracked_short(&row.cracked), CRACKED_W);
    out.push(' ');
    push_timestamp(&mut out, row.last_seen);
    out
}

pub fn names_of(raw: &str) -> String {
    // Stored as a JSON array; fall back to the raw text if it isn't.
    match serde_json::from_str::<Vec<serde_json::Value>>(raw) {
        Ok(items) => {
            let names: Vec<String> = items
                .into_iter()
                .filter_map(|value| value.as_str().map(clean_display))
                .filter(|name| !name.trim().is_empty())
                .collect();
            if names.is_empty() {
                "-".to_string()
            } else {
                names.join(", ")
            }
        }
        Err(_) => {
            let text = clean_display(raw.trim());
            if text.is_empty() || text == "[]" {
                "-".to_string()
            } else {
                text.to_string()
            }
        }
    }
}

pub fn timestamp_text(epoch: f64) -> String {
    let mut out = String::new();
    push_timestamp(&mut out, epoch);
    out
}

/// Load every row matching `query` in the same order the Python GUI uses
/// (`last_seen DESC`). Sorting is done in memory with Python-compatible keys.
pub fn load(path: &str, query: &str) -> Result<Loaded, String> {
    if path.trim().is_empty() {
        return Err("no database selected".into());
    }
    let started = Instant::now();
    let con = open_read_only(path)?;

    let total: i64 = con
        .query_row("SELECT COUNT(*) FROM servers", [], |r| r.get(0))
        .unwrap_or(0);

    let (where_sql, params) = search::compile(query)?;
    let select = format!(
        "SELECT ip_port, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {} FROM servers {} \
         ORDER BY last_seen DESC",
        col_or(&con, "motd", "''"),
        col_or(&con, "players_online", "0"),
        col_or(&con, "max_players", "0"),
        col_or(&con, "version", "''"),
        col_or(&con, "cracked", "''"),
        col_or(&con, "whitelist", "''"),
        col_or(&con, "players_now", "'[]'"),
        col_or(&con, "players_ever", "'[]'"),
        col_or(&con, "first_seen", "0"),
        col_or(&con, "last_seen", "0"),
        col_or(&con, "times_seen", "0"),
        where_sql,
    );

    let mut stmt = con.prepare(&select).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    let mut rows = stmt
        .query(rusqlite::params_from_iter(params.iter()))
        .map_err(|e| e.to_string())?;
    while let Some(row) = rows.next().map_err(|e| e.to_string())? {
        let ip: String = row.get(0).map_err(|e| e.to_string())?;
        out.push(Row {
            ip,
            motd: row.get(1).unwrap_or_default(),
            players: row.get(2).unwrap_or(0),
            max_players: row.get(3).unwrap_or(0),
            version: row.get(4).unwrap_or_default(),
            cracked: row.get(5).unwrap_or_default(),
            whitelist: row.get(6).unwrap_or_default(),
            names_now: row.get(7).unwrap_or_default(),
            names_ever: row.get(8).unwrap_or_default(),
            first_seen: row.get(9).unwrap_or(0.0),
            last_seen: row.get(10).unwrap_or(0.0),
            times_seen: row.get(11).unwrap_or(0),
        });
    }

    Ok(Loaded {
        rows: out,
        total,
        ms: started.elapsed().as_millis(),
    })
}

/// Full record text for one selected row (a single primary-key lookup).
pub fn detail(path: &str, row: &Row) -> Result<String, String> {
    let con = open_read_only(path)?;
    let select = format!(
        "SELECT {}, {}, {}, {}, {}, {} FROM servers WHERE ip_port = ? LIMIT 1",
        col_or(&con, "whitelist", "''"),
        col_or(&con, "first_seen", "0"),
        col_or(&con, "times_seen", "0"),
        col_or(&con, "protocol", "0"),
        col_or(&con, "players_now", "'[]'"),
        col_or(&con, "players_ever", "'[]'"),
    );
    let mut stmt = con.prepare(&select).map_err(|e| e.to_string())?;
    let mut rows = stmt.query([&row.ip]).map_err(|e| e.to_string())?;
    let Some(found) = rows.next().map_err(|e| e.to_string())? else {
        return Ok(format!("{}\n\nrow no longer in the database (synced?)", row.ip));
    };

    let whitelist: String = found.get(0).unwrap_or_default();
    let first_seen: f64 = found.get(1).unwrap_or(0.0);
    let times_seen: i64 = found.get(2).unwrap_or(0);
    let protocol: i64 = found.get(3).unwrap_or(0);
    let names_now: String = found.get(4).unwrap_or_default();
    let names_ever: String = found.get(5).unwrap_or_default();

    let mut out = String::with_capacity(512);
    let _ = writeln!(out, "{}\n", clean_multiline(&row.ip));
    let motd = clean_multiline(&row.motd);
    let version = clean_multiline(&row.version);
    let whitelist = clean_multiline(&whitelist);
    let _ = writeln!(
        out,
        "MOTD:        {}",
        if motd.is_empty() { "-" } else { &motd }
    );
    let _ = writeln!(
        out,
        "Players:     {}/{} (seen {} time(s))",
        row.players, row.max_players, times_seen
    );
    let _ = writeln!(
        out,
        "Version:     {} (protocol {})",
        if version.is_empty() { "-" } else { &version },
        protocol
    );
    let cracked = clean_multiline(&row.cracked);
    let _ = writeln!(
        out,
        "Cracked:     {}",
        if cracked.is_empty() { "-" } else { &cracked }
    );
    let _ = writeln!(
        out,
        "Whitelist:   {}",
        if whitelist.is_empty() { "-" } else { &whitelist }
    );
    let _ = writeln!(out, "First seen:  {}", timestamp_text(first_seen));
    let _ = writeln!(out, "Last seen:   {}", timestamp_text(row.last_seen));
    let _ = writeln!(out);
    let _ = writeln!(out, "Online now:  {}", names_of(&names_now));
    let _ = writeln!(out, "Ever seen:   {}", names_of(&names_ever));
    Ok(out)
}

/// Whether the path looks like a scanner database.
pub fn looks_like_db(path: &str) -> bool {
    Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .and_then(|con| {
            con.query_row("SELECT COUNT(*) FROM servers", [], |r| r.get::<_, i64>(0))
        })
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_text_strips_controls_and_bidi() {
        let cleaned = one_line("a\x1b[31m\nb\u{202e}c\u{200b}d\x00e");
        assert_eq!(cleaned, "a[31m bcde");
    }

    #[test]
    fn detail_text_keeps_newlines_but_strips_controls() {
        let text = clean_multiline("line1\nline2\u{202e}\x1b[31m");
        assert_eq!(text, "line1\nline2[31m");
    }

    #[test]
    fn emoji_zwj_sequences_are_kept() {
        let emoji = "👨\u{200d}👩\u{200d}👧";
        assert_eq!(one_line(emoji), emoji);
    }

    #[test]
    fn names_are_cleaned() {
        let names = names_of(r#"["alice", "b\u0000ob", "\u001b[31mcarol"]"#);
        assert_eq!(names, "alice, bob, [31mcarol");
    }
}
