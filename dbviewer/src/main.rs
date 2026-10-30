//! Fast read-only viewer for the scanner's `servers.db`.
//!
//! The Python GUI loads every row into widgets; this keeps the rows in Rust
//! and exposes them through a QAbstractTableModel, so Qt's TableView only
//! touches the visible cells and a 100k+ row database stays responsive.

mod db;
mod job;
mod model;
mod search;
mod sort;

use cxx_qt_lib::{QGuiApplication, QQmlApplicationEngine, QUrl};
use std::time::Instant;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        println!(
            "dbviewer - fast read-only viewer for servers.db\n\n\
             usage: dbviewer [DATABASE] [options]\n\n\
             options:\n  \
             --db PATH            database file (default: servers.db)\n  \
             --query EXPR         initial search expression\n  \
             --sort COL[:asc|desc] initial sort column\n  \
             --selftest           headless load/search benchmark and exit\n  \
             -h, --help           show this help"
        );
        return;
    }
    if args.iter().any(|arg| arg == "--selftest") {
        selftest(&args);
        return;
    }

    let mut app = QGuiApplication::new();
    let mut engine = QQmlApplicationEngine::new();
    if let Some(engine) = engine.as_mut() {
        engine.load(&QUrl::from("qrc:/qt/qml/MC/DbViewer/qml/main.qml"));
    }
    if let Some(app) = app.as_mut() {
        app.exec();
    }
}

/// Headless check/benchmark: `dbviewer --selftest path/to/servers.db`.
fn selftest(args: &[String]) {
    let path = args
        .iter()
        .skip(1)
        .find(|arg| !arg.starts_with("--"))
        .cloned()
        .unwrap_or_else(|| "servers.db".to_string());

    println!("db: {path}");
    let started = Instant::now();
    match db::load(&path, "") {
        Ok(loaded) => {
            println!(
                "all rows: {} of {} loaded in {} ms",
                loaded.rows.len(),
                loaded.total,
                loaded.ms
            );
            if let Some(row) = loaded.rows.first() {
                println!("  first: {}", db::display_line(row));
            }
            if let Some(row) = loaded.rows.last() {
                println!("  last:  {}", db::display_line(row));
            }
            if let Some(row) = loaded.rows.first() {
                match db::detail(&path, row) {
                    Ok(text) => {
                        println!("  detail:");
                        for line in text.lines().take(12) {
                            println!("    {line}");
                        }
                    }
                    Err(error) => println!("  detail error: {error}"),
                }
            }
        }
        Err(error) => {
            eprintln!("error: {error}");
            std::process::exit(1);
        }
    }

    for query in [
        "anarchy",
        "motd:anarchy",
        "players>=10",
        "seen<7d",
        "cracked=yes",
        "whitelist=yes",
        "whitelist=no",
        "-motd:test players:0",
        "names:Notch",
        "version~1.21",
    ] {
        match db::load(&path, query) {
            Ok(loaded) => {
                let sample = loaded
                    .rows
                    .first()
                    .map(|row| row.ip.as_str())
                    .unwrap_or("-");
                println!(
                    "query {query:?}: {} rows in {} ms (first {sample})",
                    loaded.rows.len(),
                    loaded.ms
                );
            }
            Err(error) => println!("query {query:?}: error: {error}"),
        }
    }

    for (column, desc) in [
        ("ip_port", false),
        ("motd", false),
        ("players", true),
        ("version", false),
        ("cracked", false),
        ("whitelist", false),
        ("online_names", false),
        ("seen_names", false),
        ("first_seen", false),
        ("last_seen", true),
        ("times_seen", true),
    ] {
        match db::load(&path, "") {
            Ok(mut loaded) => {
                let started = Instant::now();
                sort::sort_rows(&mut loaded.rows, column, desc);
                println!(
                    "sort {column:12} desc={desc:5}: {} rows in {} ms",
                    loaded.rows.len(),
                    started.elapsed().as_millis()
                );
            }
            Err(error) => println!("sort {column}: error: {error}"),
        }
    }

    println!("total wall time: {} ms", started.elapsed().as_millis());
}
