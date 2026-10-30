//! Sorting keys matching the Python GUI's `ResultTable`.
//!
//! The Python app sorts in memory with custom keys (version numbers are
//! compared numerically, IPs as octets, etc.), so the viewer does the same
//! instead of relying on SQLite's byte ordering.

use crate::db::Row;

#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum IpKey {
    V4(u32, u32, u32, u32, u32),
    Other(String, u32),
}

/// "a.b.c.d:port" -> (a,b,c,d,port); anything else sorts after IPv4, as in
/// the Python `_ip_key`.
fn ip_key(value: &str) -> IpKey {
    let (host, port) = if value.bytes().filter(|&b| b == b':').count() == 1 {
        match value.split_once(':') {
            Some((host, port)) => match port.parse::<u32>() {
                Ok(port) => (host, port),
                Err(_) => (value, 0),
            },
            None => (value, 0),
        }
    } else {
        (value, 0)
    };

    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() == 4
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_digit()))
    {
        let numbers: Result<Vec<u32>, _> =
            parts.iter().map(|part| part.parse::<u32>()).collect();
        return match numbers {
            Ok(numbers) => IpKey::V4(numbers[0], numbers[1], numbers[2], numbers[3], port),
            Err(_) => IpKey::V4(0, 0, 0, 0, port),
        };
    }
    IpKey::Other(host.to_string(), port)
}

/// "1.21.10" -> [1,21,10]; text around numbers is split into extra numbers
/// ("26.3-pre2" -> [26,3,2]) exactly like the Python `_version_key`.
fn version_key(value: &str) -> Vec<u64> {
    let mut out = Vec::new();
    for token in value.trim().split('.') {
        if !token.is_empty() && token.chars().all(|c| c.is_ascii_digit()) {
            if let Ok(number) = token.parse::<u64>() {
                out.push(number);
            }
        } else {
            let mut found = false;
            for part in token.split(|c: char| !c.is_ascii_digit()) {
                if !part.is_empty() {
                    if let Ok(number) = part.parse::<u64>() {
                        out.push(number);
                        found = true;
                    }
                }
            }
            if !found {
                out.push(0);
            }
        }
    }
    if out.is_empty() {
        out.push(0);
    }
    out
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum SortKey {
    Ip(IpKey),
    Text(String),
    Players(i64),
    Number(i64),
    Version(Vec<u64>),
    Time(i64),
}

/// Timestamps are displayed with minute precision, and the Python GUI
/// sorts that text. Comparing whole minutes reproduces it exactly (ties in
/// the same minute keep their previous order).
fn minute_key(epoch: f64) -> i64 {
    if epoch > 0.0 {
        (epoch / 60.0) as i64
    } else {
        0
    }
}

fn sort_key(row: &Row, column: &str) -> SortKey {
    match column {
        "ip_port" => SortKey::Ip(ip_key(&row.ip)),
        "motd" => SortKey::Text(row.motd.to_lowercase()),
        "players" => SortKey::Players(row.players),
        "version" => SortKey::Version(version_key(&row.version)),
        "cracked" => SortKey::Text(row.cracked.to_lowercase()),
        "whitelist" => SortKey::Text(row.whitelist.to_lowercase()),
        "online_names" => SortKey::Text(crate::db::names_of(&row.names_now).to_lowercase()),
        "seen_names" => SortKey::Text(crate::db::names_of(&row.names_ever).to_lowercase()),
        "first_seen" => SortKey::Time(minute_key(row.first_seen)),
        "times_seen" => SortKey::Number(row.times_seen),
        _ => SortKey::Time(minute_key(row.last_seen)),
    }
}

/// Sort rows by a whitelisted column, ascending or descending.
///
/// The sort is stable in both directions (equal keys keep their existing
/// order), matching Python's `list.sort(key=..., reverse=...)`.
pub fn sort_rows(rows: &mut Vec<Row>, column: &str, desc: bool) {
    let mut keyed: Vec<(SortKey, Row)> = std::mem::take(rows)
        .into_iter()
        .map(|row| (sort_key(&row, column), row))
        .collect();
    if desc {
        keyed.sort_by(|a, b| b.0.cmp(&a.0));
    } else {
        keyed.sort_by(|a, b| a.0.cmp(&b.0));
    }
    rows.extend(keyed.into_iter().map(|(_, row)| row));
}

/// Apply several sort keys in click order. Later keys are the primary sort;
/// earlier keys break ties, matching sequential stable header sorts in the
/// Python GUI (version then whitelist keeps version order inside each
/// whitelist group).
pub fn sort_rows_multi(rows: &mut Vec<Row>, keys: &[(String, bool)]) {
    for (column, desc) in keys {
        sort_rows(rows, column, *desc);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(ip: &str, version: &str, players: i64, cracked: &str, last_seen: f64) -> Row {
        Row {
            ip: ip.to_string(),
            motd: String::new(),
            players,
            max_players: 0,
            version: version.to_string(),
            cracked: cracked.to_string(),
            whitelist: String::new(),
            names_now: String::new(),
            names_ever: String::new(),
            first_seen: 0.0,
            last_seen,
            times_seen: 0,
        }
    }

    fn versions(order: &[&str]) -> Vec<String> {
        let mut rows: Vec<Row> = order
            .iter()
            .map(|version| row("1.2.3.4:25565", version, 0, "", 0.0))
            .collect();
        sort_rows(&mut rows, "version", false);
        rows.into_iter().map(|row| row.version).collect()
    }

    #[test]
    fn version_numbers_sort_numerically() {
        assert_eq!(
            versions(&["1.21.10", "1.21.1", "1.9", "Paper 26.3", ""]),
            vec!["", "1.9", "1.21.1", "1.21.10", "Paper 26.3"]
        );
        assert_eq!(
            versions(&["1.21.1-pre2", "1.21.1", "1.21.10"]),
            vec!["1.21.1", "1.21.1-pre2", "1.21.10"]
        );
    }

    #[test]
    fn ip_addresses_sort_as_octets() {
        let mut rows = vec![
            row("1.2.3.10:25565", "", 0, "", 0.0),
            row("10.0.0.1:25565", "", 0, "", 0.0),
            row("1.2.3.9:25565", "", 0, "", 0.0),
            row("hostname:25565", "", 0, "", 0.0),
        ];
        sort_rows(&mut rows, "ip_port", false);
        let ips: Vec<&str> = rows.iter().map(|row| row.ip.as_str()).collect();
        assert_eq!(
            ips,
            vec![
                "1.2.3.9:25565",
                "1.2.3.10:25565",
                "10.0.0.1:25565",
                "hostname:25565"
            ]
        );
    }

    #[test]
    fn descending_is_stable() {
        let mut rows = vec![
            row("1.2.3.1:25565", "", 5, "", 0.0),
            row("1.2.3.2:25565", "", 5, "", 0.0),
            row("1.2.3.3:25565", "", 9, "", 0.0),
        ];
        sort_rows(&mut rows, "players", true);
        let ips: Vec<&str> = rows.iter().map(|row| row.ip.as_str()).collect();
        assert_eq!(
            ips,
            vec!["1.2.3.3:25565", "1.2.3.1:25565", "1.2.3.2:25565"]
        );
    }

    #[test]
    fn later_keys_break_earlier_ties() {
        let mut first = row("1.0.0.1:25565", "1.20", 0, "", 0.0);
        first.whitelist = "A".to_string();
        let mut second = row("1.0.0.2:25565", "1.10", 0, "", 0.0);
        second.whitelist = "A".to_string();
        let mut third = row("1.0.0.3:25565", "1.30", 0, "", 0.0);
        third.whitelist = "B".to_string();

        let mut rows = vec![first, second, third];
        let keys = vec![
            ("version".to_string(), false),
            ("whitelist".to_string(), false),
        ];
        sort_rows_multi(&mut rows, &keys);

        let ips: Vec<&str> = rows.iter().map(|row| row.ip.as_str()).collect();
        assert_eq!(
            ips,
            vec![
                "1.0.0.2:25565", // A, 1.10
                "1.0.0.1:25565", // A, 1.20
                "1.0.0.3:25565"  // B, 1.30
            ]
        );
    }

    #[test]
    fn players_use_the_online_count() {
        let mut rows = vec![
            row("a:1", "", 2, "", 0.0),
            row("b:1", "", 10, "", 0.0),
            row("c:1", "", 1, "", 0.0),
        ];
        sort_rows(&mut rows, "players", false);
        let players: Vec<i64> = rows.iter().map(|row| row.players).collect();
        assert_eq!(players, vec![1, 2, 10]);
    }
}
