//! Qt bridge: a `QAbstractTableModel` over the server rows, plus the
//! invokables the QML front-end drives (open / search / sort / jobs).

#[cxx_qt::bridge]
pub mod qobject {
    unsafe extern "C++Qt" {
        include!(<QtCore/QAbstractTableModel>);
        /// Base class for the row model.
        #[qobject]
        type QAbstractTableModel;
    }

    unsafe extern "C++" {
        include!("cxx-qt-lib/qhash.h");
        /// QHash<i32, QByteArray> used for role names.
        type QHash_i32_QByteArray = cxx_qt_lib::QHash<cxx_qt_lib::QHashPair_i32_QByteArray>;

        include!("cxx-qt-lib/qstring.h");
        /// QString from cxx_qt_lib.
        type QString = cxx_qt_lib::QString;

        include!("cxx-qt-lib/qvariant.h");
        /// QVariant from cxx_qt_lib.
        type QVariant = cxx_qt_lib::QVariant;

        include!("cxx-qt-lib/qmodelindex.h");
        /// QModelIndex from cxx_qt_lib.
        type QModelIndex = cxx_qt_lib::QModelIndex;
    }

    extern "RustQt" {
        #[qobject]
        #[qml_element]
        #[base = QAbstractTableModel]
        #[qproperty(QString, db_path)]
        #[qproperty(i32, total)]
        #[qproperty(i32, shown)]
        #[qproperty(i32, load_ms)]
        #[qproperty(QString, status)]
        #[qproperty(bool, busy)]
        #[qproperty(bool, job_failed)]
        #[qproperty(bool, job_finished)]
        #[qproperty(QString, job_log)]
        #[qproperty(QString, sort_column)]
        #[qproperty(bool, sort_desc)]
        type ViewerModel = super::ViewerModelRust;

        /// DB path from the command line (or `servers.db` in the cwd).
        #[qinvokable]
        #[cxx_name = "defaultPath"]
        fn default_path(self: &ViewerModel) -> QString;

        /// Initial query from `--query` (empty when not given).
        #[qinvokable]
        #[cxx_name = "defaultQuery"]
        fn default_query(self: &ViewerModel) -> QString;

        /// Initial sort column from `--sort`.
        #[qinvokable]
        #[cxx_name = "defaultSort"]
        fn default_sort(self: &ViewerModel) -> QString;

        /// Initial sort direction (`--sort col:desc`).
        #[qinvokable]
        #[cxx_name = "defaultDesc"]
        fn default_desc(self: &ViewerModel) -> bool;

        /// Open a database; returns an error message (empty on success).
        #[qinvokable]
        #[cxx_name = "open"]
        fn open_file(self: Pin<&mut ViewerModel>, path: QString) -> QString;

        /// Re-run the query and sorting against the open database.
        #[qinvokable]
        fn apply(self: Pin<&mut ViewerModel>, query: QString) -> QString;

        /// Add/toggle a column in the sort stack (last click is primary).
        #[qinvokable]
        #[cxx_name = "toggleSort"]
        fn toggle_sort(self: Pin<&mut ViewerModel>, column: QString);

        /// Replace the sort stack with one column (used for `--sort`).
        #[qinvokable]
        #[cxx_name = "setSort"]
        fn set_sort(self: Pin<&mut ViewerModel>, column: QString, desc: bool);

        /// Detail text for one row (fetched on demand by the UI).
        #[qinvokable]
        fn detail(self: &ViewerModel, row: i32) -> QString;

        /// Set the status line (copy feedback, selection hints, ...).
        #[qinvokable]
        fn note(self: Pin<&mut ViewerModel>, message: QString);

        /// IP:PORT for a row (used to build the recheck selection).
        #[qinvokable]
        #[cxx_name = "ipAt"]
        fn ip_at(self: &ViewerModel, row: i32) -> QString;

        /// Start `mcscan.py --sync`; returns an error message (empty on success).
        #[qinvokable]
        #[cxx_name = "startSync"]
        fn start_sync(self: Pin<&mut ViewerModel>) -> QString;

        /// Recheck whitelist status for a comma-separated list of ip:port.
        #[qinvokable]
        #[cxx_name = "startRecheck"]
        fn start_recheck(self: Pin<&mut ViewerModel>, ips: QString) -> QString;

        /// Re-ping a comma-separated list of ip:port and update the local DB.
        #[qinvokable]
        #[cxx_name = "startRescan"]
        fn start_rescan(self: Pin<&mut ViewerModel>, ips: QString) -> QString;

        /// Poll the running job. Returns true while it is still running.
        #[qinvokable]
        #[cxx_name = "pollJob"]
        fn poll_job(self: Pin<&mut ViewerModel>) -> bool;

        #[qinvokable]
        #[cxx_override]
        #[cxx_name = "rowCount"]
        fn row_count(self: &ViewerModel, parent: &QModelIndex) -> i32;

        #[qinvokable]
        #[cxx_override]
        #[cxx_name = "columnCount"]
        fn column_count(self: &ViewerModel, parent: &QModelIndex) -> i32;

        #[qinvokable]
        #[cxx_override]
        #[cxx_name = "data"]
        fn data(self: &ViewerModel, index: &QModelIndex, role: i32) -> QVariant;

        #[qinvokable]
        #[cxx_override]
        #[cxx_name = "roleNames"]
        fn role_names(self: &ViewerModel) -> QHash_i32_QByteArray;
    }

    extern "RustQt" {
        /// # Safety
        ///
        /// Inherited from QAbstractItemModel; pair it with `end_reset_model`.
        #[inherit]
        #[cxx_name = "beginResetModel"]
        unsafe fn begin_reset_model(self: Pin<&mut ViewerModel>);

        /// # Safety
        ///
        /// Must follow a matching `begin_reset_model` call.
        #[inherit]
        #[cxx_name = "endResetModel"]
        unsafe fn end_reset_model(self: Pin<&mut ViewerModel>);
    }
}

use core::pin::Pin;
use cxx_qt::CxxQtType;
use cxx_qt_lib::{QByteArray, QHash, QHashPair_i32_QByteArray, QModelIndex, QString, QVariant};
use std::time::Instant;

use crate::job::JobHandle;

/// Column order, matching the Python Servers tab.
pub const COLUMNS: [&str; 11] = [
    "ip_port",
    "motd",
    "players",
    "version",
    "cracked",
    "whitelist",
    "online_names",
    "seen_names",
    "first_seen",
    "last_seen",
    "times_seen",
];

#[derive(Default)]
pub struct ViewerModelRust {
    // Mirrors the `#[qproperty]` list; CXX-Qt generates accessors for these.
    db_path: QString,
    total: i32,
    shown: i32,
    load_ms: i32,
    status: QString,
    busy: bool,
    job_failed: bool,
    job_finished: bool,
    job_log: QString,
    sort_column: QString,
    sort_desc: bool,

    // Plain state, not exposed as Qt properties.
    query: String,
    /// Click order: earlier keys break ties for later (primary) keys.
    sort_keys: Vec<(String, bool)>,
    rows: Vec<crate::db::Row>,
    job: Option<JobHandle>,
}

fn qs(value: &str) -> QString {
    QString::from(value)
}

impl qobject::ViewerModel {
    pub fn default_path(&self) -> QString {
        qs(&launch().db)
    }

    pub fn default_query(&self) -> QString {
        qs(&launch().query)
    }

    pub fn default_sort(&self) -> QString {
        qs(&launch().sort)
    }

    pub fn default_desc(&self) -> bool {
        launch().desc
    }

    pub fn open_file(mut self: Pin<&mut Self>, path: QString) -> QString {
        let path = path.to_string();
        if path.trim().is_empty() {
            return qs("no database selected");
        }
        if !crate::db::looks_like_db(&path) {
            let message = format!("not a scanner database: {path}");
            self.as_mut().set_status(qs(&message));
            return qs(&message);
        }

        {
            let mut rust = self.as_mut().rust_mut();
            rust.query.clear();
        }
        // Use the generated setter: writing the field directly would not emit
        // dbPathChanged, leaving QML bindings (Sync/Recheck enabled state) stale.
        self.as_mut().set_db_path(qs(&path));
        self.as_mut().set_job_log(QString::default());
        self.as_mut().reload()
    }

    pub fn apply(mut self: Pin<&mut Self>, query: QString) -> QString {
        {
            let mut rust = self.as_mut().rust_mut();
            rust.query = query.to_string();
        }
        self.as_mut().reload()
    }

    pub fn toggle_sort(mut self: Pin<&mut Self>, column: QString) {
        let column = column.to_string();
        if column.is_empty() {
            return;
        }
        let started = Instant::now();
        let (count, label);
        unsafe {
            self.as_mut().begin_reset_model();
        }
        {
            let mut rust = self.as_mut().rust_mut();
            let desc = match rust.sort_keys.iter().position(|(key, _)| key == &column) {
                Some(index) => {
                    let (_, previous) = rust.sort_keys.remove(index);
                    !previous
                }
                None => false,
            };
            rust.sort_keys.push((column, desc));
            let keys = rust.sort_keys.clone();
            crate::sort::sort_rows_multi(&mut rust.rows, &keys);
            count = rust.rows.len();
            label = sort_stack_label(&rust.sort_keys);
        }
        unsafe {
            self.as_mut().end_reset_model();
        }
        self.as_mut().sync_sort_props();

        let millis = started.elapsed().as_millis().min(i32::MAX as u128) as i32;
        self.as_mut().set_load_ms(millis);
        self.as_mut().set_status(qs(&format!(
            "{count} rows sorted by {label} in {millis} ms"
        )));
    }

    pub fn set_sort(mut self: Pin<&mut Self>, column: QString, desc: bool) {
        let column = column.to_string();
        let started = Instant::now();
        let (count, label);
        unsafe {
            self.as_mut().begin_reset_model();
        }
        {
            let mut rust = self.as_mut().rust_mut();
            rust.sort_keys = if column.is_empty() {
                Vec::new()
            } else {
                vec![(column, desc)]
            };
            let keys = rust.sort_keys.clone();
            crate::sort::sort_rows_multi(&mut rust.rows, &keys);
            count = rust.rows.len();
            label = sort_stack_label(&rust.sort_keys);
        }
        unsafe {
            self.as_mut().end_reset_model();
        }
        self.as_mut().sync_sort_props();

        if !label.is_empty() {
            let millis = started.elapsed().as_millis().min(i32::MAX as u128) as i32;
            self.as_mut().set_load_ms(millis);
            self.as_mut().set_status(qs(&format!(
                "{count} rows sorted by {label} in {millis} ms"
            )));
        }
    }

    /// Mirror the primary (last-clicked) key into the QML header bindings.
    fn sync_sort_props(mut self: Pin<&mut Self>) {
        let primary = self.rust().sort_keys.last().cloned();
        let (column, desc) = primary.unwrap_or_default();
        self.as_mut().set_sort_column(qs(&column));
        self.as_mut().set_sort_desc(desc);
    }

    pub fn detail(&self, row: i32) -> QString {
        if row < 0 {
            return QString::default();
        }
        let rust = self.rust();
        let Some(entry) = rust.rows.get(row as usize) else {
            return QString::default();
        };
        let path = rust.db_path.to_string();
        match crate::db::detail(&path, entry) {
            Ok(text) => qs(&text),
            Err(error) => qs(&format!("could not load row: {error}")),
        }
    }

    pub fn note(mut self: Pin<&mut Self>, message: QString) {
        self.as_mut().set_status(message);
    }

    pub fn ip_at(&self, row: i32) -> QString {
        self.rust()
            .rows
            .get(row as usize)
            .map(|entry| qs(&entry.ip))
            .unwrap_or_default()
    }

    pub fn start_sync(mut self: Pin<&mut Self>) -> QString {
        self.as_mut()
            .start_job(vec!["--sync".to_string()], "syncing shared DB...")
    }

    pub fn start_recheck(mut self: Pin<&mut Self>, ips: QString) -> QString {
        let ips: Vec<String> = ips
            .to_string()
            .split(',')
            .map(str::trim)
            .filter(|ip| !ip.is_empty())
            .map(str::to_string)
            .collect();
        if ips.is_empty() {
            let message = "select one or more server rows first";
            self.as_mut().set_status(qs(message));
            return qs(message);
        }
        let count = ips.len();
        let mut args = vec!["--recheck-whitelist".to_string()];
        args.extend(ips);
        self.as_mut().start_job(
            args,
            &format!("rechecking whitelist for {count} server(s)..."),
        )
    }

    pub fn start_rescan(mut self: Pin<&mut Self>, ips: QString) -> QString {
        let ips: Vec<String> = ips
            .to_string()
            .split(',')
            .map(str::trim)
            .filter(|ip| !ip.is_empty())
            .map(str::to_string)
            .collect();
        if ips.is_empty() {
            let message = "select one or more server rows first";
            self.as_mut().set_status(qs(message));
            return qs(message);
        }
        let count = ips.len();
        let mut args = vec!["--rescan".to_string()];
        args.extend(ips);
        self.as_mut().start_job(
            args,
            &format!("rescanning {count} server(s)..."),
        )
    }

    fn start_job(mut self: Pin<&mut Self>, args: Vec<String>, label: &str) -> QString {
        if self.rust().job.is_some() {
            return qs("a background task is already running");
        }
        let db_path = self.rust().db_path.to_string();
        if db_path.is_empty() {
            return qs("open a database first");
        }

        let target = match crate::job::find(&db_path) {
            Ok(target) => target,
            Err(error) => {
                self.as_mut().set_status(qs(&error));
                self.as_mut().set_job_log(qs(&error));
                return qs(&error);
            }
        };

        let header = command_line(&target, &args);
        match JobHandle::start(&target, &args) {
            Ok(handle) => {
                {
                    let mut rust = self.as_mut().rust_mut();
                    rust.job = Some(handle);
                }
                self.as_mut().set_busy(true);
                self.as_mut().set_job_failed(false);
                self.as_mut().set_job_finished(false);
                self.as_mut()
                    .set_job_log(qs(&format!("{header}\n(starting...)\n")));
                self.as_mut().set_status(qs(label));
                QString::default()
            }
            Err(error) => {
                self.as_mut().set_status(qs(&error));
                self.as_mut().set_job_log(qs(&error));
                qs(&error)
            }
        }
    }

    pub fn poll_job(mut self: Pin<&mut Self>) -> bool {
        enum State {
            Idle,
            Running(String),
            Done(String, Option<i32>),
        }

        let state = match self.as_mut().rust_mut().job.as_mut() {
            None => State::Idle,
            Some(handle) => {
                let (running, log, exit) = handle.poll();
                if running {
                    State::Running(log)
                } else {
                    State::Done(log, exit)
                }
            }
        };

        match state {
            State::Idle => {
                self.as_mut().set_busy(false);
                false
            }
            State::Running(log) => {
                self.as_mut().set_job_log(qs(&log));
                true
            }
            State::Done(log, exit) => {
                {
                    let mut rust = self.as_mut().rust_mut();
                    rust.job = None;
                }
                self.as_mut().set_job_log(qs(&log));
                self.as_mut().set_busy(false);
                self.as_mut().set_job_failed(!matches!(exit, Some(0)));
                // Reload (and sort) first so QML's completion handler sees
                // the refreshed rows; it then re-applies the active sort.
                let _ = self.as_mut().reload();
                self.as_mut().set_job_finished(true);
                false
            }
        }
    }

    /// Fetch rows for the current query and sort them in memory.
    fn reload(mut self: Pin<&mut Self>) -> QString {
        let (path, query, sort_keys) = {
            let rust = self.rust();
            (
                rust.db_path.to_string(),
                rust.query.clone(),
                rust.sort_keys.clone(),
            )
        };
        if path.is_empty() {
            return qs("no database selected");
        }

        let started = Instant::now();
        match crate::db::load(&path, &query) {
            Ok(loaded) => {
                let total = loaded.total.min(i32::MAX as i64) as i32;
                let mut rows = loaded.rows;
                crate::sort::sort_rows_multi(&mut rows, &sort_keys);
                let shown = rows.len() as i32;
                let millis = started.elapsed().as_millis().min(i32::MAX as u128) as i32;

                unsafe {
                    self.as_mut().begin_reset_model();
                }
                {
                    let mut rust = self.as_mut().rust_mut();
                    rust.rows = rows;
                }
                unsafe {
                    self.as_mut().end_reset_model();
                }

                self.as_mut().set_total(total);
                self.as_mut().set_shown(shown);
                self.as_mut().set_load_ms(millis);
                let sort_note = if sort_keys.is_empty() {
                    String::new()
                } else {
                    format!(", sorted by {}", sort_stack_label(&sort_keys))
                };
                self.as_mut().set_status(qs(&format!(
                    "{shown} of {total} rows{sort_note} in {millis} ms"
                )));
                QString::default()
            }
            Err(error) => {
                self.as_mut().set_status(qs(&error));
                qs(&error)
            }
        }
    }

    pub fn row_count(&self, _parent: &QModelIndex) -> i32 {
        self.rust().rows.len() as i32
    }

    pub fn column_count(&self, _parent: &QModelIndex) -> i32 {
        COLUMNS.len() as i32
    }

    pub fn data(&self, index: &QModelIndex, role: i32) -> QVariant {
        if role != 0 {
            // Qt::DisplayRole
            return QVariant::default();
        }
        let Some(row) = self.rust().rows.get(index.row() as usize) else {
            return QVariant::default();
        };
        let text = match index.column() {
            0 => row.ip.clone(),
            1 => crate::db::one_line(&row.motd),
            2 => format!("{}/{}", row.players, row.max_players),
            3 => crate::db::one_line(&row.version),
            4 => crate::db::one_line(&row.cracked),
            5 => crate::db::one_line(&row.whitelist),
            6 => crate::db::names_of(&row.names_now),
            7 => crate::db::names_of(&row.names_ever),
            8 => crate::db::timestamp_text(row.first_seen),
            9 => crate::db::timestamp_text(row.last_seen),
            10 => row.times_seen.to_string(),
            _ => return QVariant::default(),
        };
        QVariant::from(&qs(&text))
    }

    pub fn role_names(&self) -> QHash<QHashPair_i32_QByteArray> {
        let mut roles = QHash::<QHashPair_i32_QByteArray>::default();
        roles.insert(0, QByteArray::from("display"));
        roles
    }
}

fn sort_label(column: &str) -> &str {
    match column {
        "ip_port" => "ip",
        "last_seen" => "last seen",
        "first_seen" => "first seen",
        "times_seen" => "times seen",
        "online_names" => "online names",
        "seen_names" => "seen names",
        other => other,
    }
}

fn sort_stack_label(keys: &[(String, bool)]) -> String {
    keys.iter()
        .rev()
        .map(|(column, desc)| {
            format!(
                "{}{}",
                sort_label(column),
                if *desc { " ↓" } else { " ↑" }
            )
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn command_line(target: &crate::job::Target, args: &[String]) -> String {
    let mut line = format!("$ {} {}", target.python, target.script.display());
    for arg in args {
        line.push(' ');
        line.push_str(arg);
    }
    line
}

struct Launch {
    db: String,
    query: String,
    sort: String,
    desc: bool,
}

/// Parse the command line once:
///   dbviewer [--db PATH | PATH] [--query EXPR] [--sort COL[:asc|desc]]
fn launch() -> &'static Launch {
    static LAUNCH: std::sync::OnceLock<Launch> = std::sync::OnceLock::new();
    LAUNCH.get_or_init(|| {
        let mut launch = Launch {
            db: "servers.db".to_string(),
            query: String::new(),
            sort: String::new(),
            desc: false,
        };
        let mut args = std::env::args().skip(1);
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--db" => {
                    if let Some(value) = args.next() {
                        launch.db = value;
                    }
                }
                "--query" => {
                    if let Some(value) = args.next() {
                        launch.query = value;
                    }
                }
                "--sort" => {
                    if let Some(value) = args.next() {
                        let (column, desc) = match value.rsplit_once(':') {
                            Some((column, direction)) => {
                                (column.to_string(), direction.eq_ignore_ascii_case("desc"))
                            }
                            None => (value, false),
                        };
                        launch.sort = column;
                        launch.desc = desc;
                    }
                }
                other if !other.starts_with('-') => launch.db = other.to_string(),
                _ => {}
            }
        }

        // Accept the short names people use from the CLI, but keep the
        // canonical key so the header knows which column is sorted.
        launch.sort = match launch.sort.as_str() {
            "ip" | "host" => "ip_port",
            "seen" | "last" => "last_seen",
            "first" => "first_seen",
            "times" => "times_seen",
            "online" => "players",
            "wl" => "whitelist",
            _ => launch.sort.as_str(),
        }
        .to_string();

        let candidate = std::path::Path::new(&launch.db);
        if candidate.is_dir() {
            launch.db = candidate
                .join("servers.db")
                .to_string_lossy()
                .into_owned();
        }
        launch
    })
}
