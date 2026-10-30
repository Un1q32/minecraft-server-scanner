//! Search expression compiler.
//!
//! The query language is deliberately small but expressive; every value is
//! bound as a SQL parameter and every identifier comes from a whitelist, so
//! nothing the user types can change the query shape.
//!
//!   anarchy                 substring across ip/motd/version/whitelist/names
//!   motd:"anarchy server"   contains (quotes keep spaces)
//!   ip:1.2.3.               prefix match
//!   version~1.21            contains
//!   cracked=yes             equality (yes/no map to Yes/No)
//!   players>=10             numeric compare
//!   seen<7d                 last seen less than 7 days ago
//!   first>30d               first seen more than 30 days ago
//!   names:Notch             player was seen on the server
//!   -motd:test              negation
//!   times>3 players:0       terms combine with AND

use rusqlite::types::Value;

const NOW: &str = "strftime('%s','now')";

/// Text columns searched by a bare (unqualified) term.
const BARE_COLUMNS: &[&str] = &[
    "ip_port", "motd", "version", "whitelist", "players_now", "players_ever",
];

fn text_column(field: &str) -> Option<&'static str> {
    Some(match field {
        "ip" | "ip_port" | "host" => "ip_port",
        "motd" | "description" => "motd",
        "version" => "version",
        "cracked" => "cracked",
        "whitelist" | "wl" => "whitelist",
        "source" => "last_source",
        _ => return None,
    })
}

fn numeric_column(field: &str) -> Option<&'static str> {
    Some(match field {
        "players" | "online" => "players_online",
        "max" | "max_players" => "max_players",
        "times" | "times_seen" => "times_seen",
        "protocol" => "protocol",
        "port" => "port",
        _ => return None,
    })
}

fn time_column(field: &str) -> Option<&'static str> {
    Some(match field {
        "seen" | "last_seen" | "last" => "last_seen",
        "first" | "first_seen" => "first_seen",
        _ => return None,
    })
}

/// Split into terms, honouring double quotes and backslash escapes.
fn tokenize(input: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut escape = false;
    for ch in input.chars() {
        if escape {
            cur.push(ch);
            escape = false;
            continue;
        }
        match ch {
            '\\' => escape = true,
            '"' => quoted = !quoted,
            c if c.is_whitespace() && !quoted => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if quoted {
        return Err("unbalanced quote".into());
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    Ok(out)
}

/// `30`, `45s`, `12m`, `6h`, `7d`, `3w` -> seconds
fn parse_duration(value: &str) -> Option<i64> {
    let v = value.trim();
    let (num, mult) = match v.chars().last()? {
        's' => (&v[..v.len() - 1], 1),
        'm' => (&v[..v.len() - 1], 60),
        'h' => (&v[..v.len() - 1], 3600),
        'd' => (&v[..v.len() - 1], 86400),
        'w' => (&v[..v.len() - 1], 7 * 86400),
        _ => (v, 0),
    };
    if mult == 0 {
        return None;
    }
    num.parse::<i64>().ok().map(|n| n * mult)
}

fn like_param(value: &str) -> String {
    // Escape LIKE wildcards so a search for "100%" is literal.
    let mut s = String::with_capacity(value.len() + 2);
    for ch in value.chars() {
        if matches!(ch, '%' | '_' | '\\') {
            s.push('\\');
        }
        s.push(ch);
    }
    format!("%{s}%")
}

fn prefix_param(value: &str) -> String {
    let mut s = String::with_capacity(value.len() + 1);
    for ch in value.chars() {
        if matches!(ch, '%' | '_' | '\\') {
            s.push('\\');
        }
        s.push(ch);
    }
    format!("{s}%")
}

/// Split a term into (field, operator, value). A term without a field has
/// field=None and operator="".
fn split_term(term: &str) -> (Option<String>, &'static str, String) {
    // Longest operators first so ">=" wins over ">".
    const OPS: &[&str] = &[">=", "<=", "!=", "!~", "~", "=", ">", "<", ":", "^"];
    let bytes = term.as_bytes();
    for (i, ch) in term.char_indices() {
        if !(ch.is_ascii_alphanumeric() || ch == '_') {
            let rest = &term[i..];
            for op in OPS {
                if let Some(tail) = rest.strip_prefix(op) {
                    let field = &term[..i];
                    if field.is_empty() {
                        break;
                    }
                    return (
                        Some(field.to_ascii_lowercase()),
                        op,
                        unquote(tail),
                    );
                }
            }
            // Unknown operator character: treat the whole term as bare.
            break;
        }
        let _ = bytes;
    }
    (None, "", unquote(term))
}

fn unquote(value: &str) -> String {
    let v = value.trim();
    if v.len() >= 2 && v.starts_with('"') && v.ends_with('"') {
        v[1..v.len() - 1].to_string()
    } else {
        v.to_string()
    }
}

/// `whitelist=yes` and friends map to the status prefixes stored in the
/// column ("Whitelisted: ...", "Not Whitelisted: ...", "Unknown: ..."),
/// which plain text matching cannot express.
fn whitelist_prefix(value: &str) -> Option<&'static str> {
    match value.trim().to_ascii_lowercase().as_str() {
        "yes" | "true" | "whitelisted" => Some("Whitelisted:%"),
        "no" | "false" | "not whitelisted" => Some("Not Whitelisted:%"),
        "unknown" => Some("Unknown:%"),
        _ => None,
    }
}

fn cmp_sql(op: &str, col: &str, value: &str, params: &mut Vec<Value>) -> Option<String> {
    let raw = value.trim();
    let number = match raw.parse::<i64>() {
        Ok(n) => n,
        Err(_) => return None,
    };
    let sql_op = match op {
        "=" | ":" | "~" => "=",
        "!=" | "!~" => "!=",
        ">" => ">",
        ">=" => ">=",
        "<" => "<",
        "<=" => "<=",
        _ => return None,
    };
    params.push(Value::Integer(number));
    Some(format!("({col} {sql_op} ?)"))
}

/// Age-based comparison for timestamps: `seen<7d` means "seen within the
/// last 7 days", i.e. `last_seen > now - 7d`.
fn age_sql(op: &str, col: &str, value: &str, params: &mut Vec<Value>) -> Option<String> {
    let raw = value.trim();
    let seconds = match parse_duration(raw) {
        Some(s) => s,
        // A plain number is an absolute epoch timestamp, not an age.
        None => {
            let ts = raw.parse::<i64>().ok()?;
            let sql_op = match op {
                "=" | ":" | "~" => "=",
                "!=" | "!~" => "!=",
                ">" => ">",
                ">=" => ">=",
                "<" => "<",
                "<=" => "<=",
                _ => return None,
            };
            params.push(Value::Integer(ts));
            return Some(format!("({col} {sql_op} ?)"));
        }
    };
    // col > now - age   <=>   age < seconds
    let sql_op = match op {
        "<" => ">",
        "<=" => ">=",
        ">" => "<",
        ">=" => "<=",
        "=" | ":" | "~" => "=",
        "!=" | "!~" => "!=",
        _ => return None,
    };
    params.push(Value::Integer(seconds));
    Some(format!("({col} {sql_op} {NOW} - ?)"))
}

/// A substring match against every text column a bare term searches.
fn bare_clause(value: &str, params: &mut Vec<Value>) -> String {
    let like = like_param(value);
    let mut parts = Vec::new();
    for col in BARE_COLUMNS {
        params.push(Value::Text(like.clone()));
        parts.push(format!("{col} LIKE ? ESCAPE '\\'"));
    }
    format!("({})", parts.join(" OR "))
}

/// Compile user input into a `WHERE ...` fragment (empty when there is no
/// filter) plus bound parameters.
pub fn compile(input: &str) -> Result<(String, Vec<Value>), String> {
    let mut clauses = Vec::new();
    let mut params = Vec::new();

    for term in tokenize(input)? {
        let negate = term.starts_with('-') && term.len() > 1;
        let body = if negate { &term[1..] } else { &term[..] };
        if body.is_empty() {
            continue;
        }
        let (field, op, value) = split_term(body);

        let clause = match field.as_deref() {
            None => bare_clause(&value, &mut params),
            Some(f) => {
                if let Some(col) = text_column(f) {
                    let negated = matches!(op, "!=" | "!~");
                    let status = if col == "whitelist"
                        && matches!(op, "=" | ":" | "!=" | "!~")
                    {
                        whitelist_prefix(&value)
                    } else {
                        None
                    };
                    let pat = if let Some(prefix) = status {
                        prefix.to_string()
                    } else if op == "^" || (col == "ip_port" && op == ":") {
                        prefix_param(&value)
                    } else {
                        like_param(&value)
                    };
                    params.push(Value::Text(pat));
                    format!("({col} {} ? ESCAPE '\\')",
                            if negated { "NOT LIKE" } else { "LIKE" })
                } else if let Some(col) = numeric_column(f) {
                    match cmp_sql(op, col, &value, &mut params) {
                        Some(c) => c,
                        None => return Err(format!("{f} needs a number (got {value:?})")),
                    }
                } else if let Some(col) = time_column(f) {
                    match age_sql(op, col, &value, &mut params) {
                        Some(c) => c,
                        None => return Err(format!("{f} needs a duration/epoch (got {value:?})")),
                    }
                } else if matches!(f, "names" | "player" | "players_sample") {
                    let like = like_param(&value);
                    params.push(Value::Text(like.clone()));
                    params.push(Value::Text(like));
                    "(players_now LIKE ? ESCAPE '\\' OR players_ever LIKE ? ESCAPE '\\')"
                        .to_string()
                } else if op == ":" {
                    // Not a field: search the literal text (URLs, "C:\\path", ...).
                    bare_clause(body, &mut params)
                } else {
                    return Err(format!(
                        "unknown field {f:?} (ip, motd, version, cracked, whitelist, \
                         source, players, max, seen, first, times, protocol, names)"
                    ));
                }
            }
        };
        clauses.push(if negate { format!("NOT {clause}") } else { clause });
    }

    if clauses.is_empty() {
        return Ok((String::new(), params));
    }
    Ok((format!("WHERE {}", clauses.join(" AND ")), params))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_term_searches_all_text_columns() {
        let (sql, params) = compile("anarchy").unwrap();
        assert!(sql.starts_with("WHERE ("));
        assert_eq!(params.len(), BARE_COLUMNS.len());
        assert!(sql.contains("motd LIKE"));
    }

    #[test]
    fn quoted_values_keep_spaces() {
        let (sql, params) = compile("motd:\"anarchy server\"").unwrap();
        assert!(sql.contains("motd LIKE"));
        match &params[0] {
            Value::Text(t) => assert_eq!(t, "%anarchy server%"),
            _ => panic!("expected text param"),
        }
    }

    #[test]
    fn numeric_and_time_operators() {
        let (sql, _) = compile("players>=10").unwrap();
        assert!(sql.contains("players_online >= ?"));
        let (sql, _) = compile("seen<7d").unwrap();
        assert!(sql.contains("last_seen >"));
        let (sql, _) = compile("first>30d").unwrap();
        assert!(sql.contains("first_seen <"));
    }

    #[test]
    fn negation_and_multiple_terms() {
        let (sql, _) = compile("-motd:test players:0").unwrap();
        assert!(sql.contains("NOT"));
        assert!(sql.contains(" AND "));
    }

    #[test]
    fn whitelist_status_values_use_the_stored_prefixes() {
        for (query, expected) in [
            ("whitelist=yes", "Whitelisted:%"),
            ("whitelist=no", "Not Whitelisted:%"),
            ("whitelist=unknown", "Unknown:%"),
            ("whitelist:whitelisted", "Whitelisted:%"),
        ] {
            let (sql, params) = compile(query).unwrap();
            assert!(sql.contains("whitelist"), "{query}: {sql}");
            match &params[0] {
                Value::Text(t) => assert_eq!(t, expected, "{query}"),
                _ => panic!("expected text param"),
            }
        }
        let (sql, _) = compile("whitelist!=yes").unwrap();
        assert!(sql.contains("NOT LIKE"), "{sql}");
        // Other values still use a normal substring match.
        let (_, params) = compile("whitelist:offline").unwrap();
        match &params[0] {
            Value::Text(t) => assert_eq!(t, "%offline%"),
            _ => panic!(),
        }
    }

    #[test]
    fn wildcards_are_escaped() {
        let (_, params) = compile("motd:100%").unwrap();
        match &params[0] {
            Value::Text(t) => assert_eq!(t, "%100\\%%"),
            _ => panic!(),
        }
    }

    #[test]
    fn rejects_bad_number_and_unbalanced_quote() {
        assert!(compile("players:many").is_err());
        assert!(compile("nope>=1").is_err());
        assert!(compile("motd:\"unclosed").is_err());
    }

    #[test]
    fn unknown_field_colon_falls_back_to_text() {
        // `http://...` must not be mistaken for a field named "http".
        let (sql, params) = compile("http://example").unwrap();
        assert!(sql.contains("motd LIKE"));
        match &params[0] {
            Value::Text(t) => assert_eq!(t, "%http://example%"),
            _ => panic!(),
        }
    }

    #[test]
    fn empty_query_has_no_where() {
        assert_eq!(compile("   ").unwrap().0, "");
    }

    #[test]
    fn ip_field_is_a_prefix_match() {
        let (sql, params) = compile("ip:1.2.3.").unwrap();
        assert!(sql.contains("ip_port LIKE"));
        match &params[0] {
            Value::Text(t) => assert_eq!(t, "1.2.3.%"),
            _ => panic!("expected text param"),
        }
    }

    #[test]
    fn text_equality_is_still_a_contains_match() {
        let (sql, params) = compile("cracked=yes").unwrap();
        assert!(sql.contains("cracked LIKE"));
        match &params[0] {
            Value::Text(t) => assert_eq!(t, "%yes%"),
            _ => panic!(),
        }
    }
}
