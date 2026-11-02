//! Background `mcscan.py` job runner (sync and whitelist rechecks).
//!
//! The viewer runs the same commands the CLI uses, in the directory that
//! holds `netdb.json` and `servers.db`. Output is captured on a background
//! thread so the UI stays responsive and can show progress.

use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;

/// Keep the log bounded so a chatty/failing sync cannot grow memory forever.
const MAX_LOG_BYTES: usize = 48 * 1024;

pub struct Target {
    pub script: PathBuf,
    pub cwd: PathBuf,
    pub python: String,
}

pub struct JobHandle {
    child: Child,
    log: Arc<Mutex<String>>,
    readers: Vec<thread::JoinHandle<()>>,
}

impl JobHandle {
    /// Spawn `<python> mcscan.py <args...>` in the database's directory.
    pub fn start(target: &Target, args: &[String]) -> Result<Self, String> {
        let mut cmd = Command::new(&target.python);
        cmd.env("PYTHONIOENCODING", "utf-8:backslashreplace")
            .env("PYTHONUTF8", "1")
            .arg("-u")
            .arg(&target.script)
            .args(args)
            .current_dir(&target.cwd)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        // Avoid flashing a console window on Windows.
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }

        let mut child = cmd
            .spawn()
            .map_err(|e| format!("could not run {}: {e}", target.python))?;

        let mut header = format!("$ {} -u {}", target.python, target.script.display());
        for arg in args {
            header.push(' ');
            header.push_str(arg);
        }
        header.push('\n');
        let log = Arc::new(Mutex::new(header));
        let mut readers = Vec::new();
        if let Some(out) = child.stdout.take() {
            readers.push(spawn_reader(out, Arc::clone(&log)));
        }
        if let Some(err) = child.stderr.take() {
            readers.push(spawn_reader(err, Arc::clone(&log)));
        }

        Ok(Self {
            child,
            log,
            readers,
        })
    }

    /// `(still_running, log_so_far, exit_code)`. Joins the pipe readers once
    /// the child has exited so the final log is complete. `exit_code` is
    /// `None` while running and when the child was killed by a signal.
    pub fn poll(&mut self) -> (bool, String, Option<i32>) {
        let status = self.child.try_wait();
        let running = matches!(status, Ok(None));
        let mut code = None;
        if !running {
            for reader in self.readers.drain(..) {
                let _ = reader.join();
            }
            if let Ok(Some(status)) = status {
                code = status.code();
                let note = match code {
                    Some(code) => format!("\n[exit code {code}]\n"),
                    None => "\n[terminated by signal]\n".to_string(),
                };
                if let Ok(mut log) = self.log.lock() {
                    log.push_str(&note);
                }
            }
        }
        let text = self
            .log
            .lock()
            .map(|log| log.clone())
            .unwrap_or_default();
        (running, text, code)
    }
}

fn spawn_reader<R: Read + Send + 'static>(
    pipe: R,
    log: Arc<Mutex<String>>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut reader = BufReader::new(pipe);
        let mut bytes = Vec::new();
        loop {
            bytes.clear();
            match reader.read_until(b'\n', &mut bytes) {
                Ok(0) => break,
                Ok(_) => {},
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
            // A malformed byte must not close the pipe and crash Python on
            // its next print. Python is UTF-8, but raw server/tool bytes can
            // still reach stdout.buffer.
            let line = String::from_utf8_lossy(&bytes);
            let Ok(mut text) = log.lock() else { break };
            text.push_str(line.trim_end_matches(&['\r', '\n'][..]));
            text.push('\n');
            if text.len() > MAX_LOG_BYTES {
                // Trim whole lines from the front, on a char boundary.
                let cut = text.len() - MAX_LOG_BYTES / 2;
                let cut = (0..=cut)
                    .rev()
                    .find(|&i| text.is_char_boundary(i))
                    .unwrap_or(0);
                let cut = text[..cut]
                    .rfind('\n')
                    .map(|i| i + 1)
                    .unwrap_or(cut);
                text.drain(..cut);
            }
        }
    })
}

#[cfg(test)]
mod output_tests {
    use super::*;
    use std::io::Cursor;

    fn captured(bytes: Vec<u8>) -> String {
        let log = Arc::new(Mutex::new(String::new()));
        spawn_reader(Cursor::new(bytes), Arc::clone(&log)).join().unwrap();
        let result = log.lock().unwrap().clone();
        result
    }

    #[test]
    fn invalid_utf8_does_not_truncate_following_output() {
        let text = captured(b"before\r\nlegacy:\x96\r\nafter\n".to_vec());
        assert_eq!(text, "before\nlegacy:\u{fffd}\nafter\n");
    }

    #[test]
    fn multilingual_output_and_last_unterminated_line_are_preserved() {
        let text = captured("caf\u{e9} \u{2014} \u{a7}a \u{4e2d}\u{6587} \u{1f3ae}\r\nlast".as_bytes().to_vec());
        assert_eq!(text, "caf\u{e9} \u{2014} \u{a7}a \u{4e2d}\u{6587} \u{1f3ae}\nlast\n");
    }

    #[test]
    fn large_multilingual_logs_keep_the_final_result() {
        let mut bytes = "caf\u{e9} \u{1f3ae} output line\n".repeat(10000).into_bytes();
        bytes.extend_from_slice(b"FINAL RESULT\n");
        let text = captured(bytes);
        assert!(text.len() <= MAX_LOG_BYTES);
        assert!(text.ends_with("FINAL RESULT\n"));
    }

    #[test]
    #[ignore = "requires Python; set DBVIEWER_TEST_PYTHON"]
    fn python_twenty_target_job_survives_unicode_and_malformed_bytes() {
        let python = std::env::var("DBVIEWER_TEST_PYTHON")
            .expect("set DBVIEWER_TEST_PYTHON to a Python executable");
        let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let directory = std::env::temp_dir().join(format!("dbviewer-output-{}-{nonce}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        let script = directory.join("output_fixture.py");
        std::fs::write(&script, r#"import sys
assert sys.stdout.encoding.lower().replace('-', '') == 'utf8'
assert len(sys.argv[2:]) == 20
for i in range(20):
    print(f'{i}: caf\u00e9 \u2014 \u00a7a \u4e2d\u6587 \U0001f3ae', flush=True)
sys.stdout.buffer.write(b'legacy:\x96\n')
sys.stdout.buffer.flush()
print('AFTER MALFORMED BYTES', flush=True)
"#).unwrap();
        let target = Target { script: script.clone(), cwd: directory.clone(), python };
        let mut args = vec!["--rescan".to_string()];
        args.extend((1..=20).map(|i| format!("192.0.2.{i}:25565")));
        let mut job = JobHandle::start(&target, &args).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let (log, code) = loop {
            let (running, log, code) = job.poll();
            if !running { break (log, code); }
            assert!(std::time::Instant::now() < deadline, "fixture did not exit");
            std::thread::sleep(std::time::Duration::from_millis(20));
        };
        assert_eq!(code, Some(0), "{log}");
        assert!(log.contains("caf\u{e9} \u{2014} \u{a7}a \u{4e2d}\u{6587} \u{1f3ae}"), "{log}");
        assert!(log.contains("AFTER MALFORMED BYTES"), "{log}");
        std::fs::remove_file(script).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }
}

/// Locate `mcscan.py` for the given DB path and the Python interpreter to use.
pub fn find(db_path: &str) -> Result<Target, String> {
    let db = Path::new(db_path);
    let cwd = match db.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => std::env::current_dir().map_err(|e| e.to_string())?,
    };

    let mut candidates = vec![cwd.join("mcscan.py")];
    if let Some(parent) = cwd.parent() {
        candidates.push(parent.join("mcscan.py"));
    }
    if let Ok(executable) = std::env::current_exe() {
        if let Some(directory) = executable.parent() {
            candidates.push(directory.join("mcscan.py"));
        }
    }
    candidates.push(PathBuf::from("mcscan.py"));

    for script in candidates {
        if script.is_file() {
            return Ok(Target {
                script,
                cwd,
                python: python_exe(),
            });
        }
    }

    Err(format!(
        "could not find mcscan.py next to {}",
        db.display()
    ))
}

fn python_exe() -> String {
    std::env::var("DBVIEWER_PYTHON")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| {
            let executable = std::env::current_exe().ok()?;
            let path = std::fs::read_to_string(executable.with_file_name("python-path.txt")).ok()?;
            let path = path.trim().to_string();
            (!path.is_empty()).then_some(path)
        })
        .unwrap_or_else(|| {
            if cfg!(windows) {
                "python".to_string()
            } else {
                "python3".to_string()
            }
        })
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn runs_script_in_db_directory_and_captures_both_streams() {
        let dir = std::env::temp_dir().join(format!("dbviewer-sync-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let script = dir.join("mcscan.py");
        let mut file = std::fs::File::create(&script).unwrap();
        writeln!(file, "#!/bin/sh").unwrap();
        writeln!(file, "echo cwd=$(pwd)").unwrap();
        writeln!(file, "echo args=$*").unwrap();
        writeln!(file, "echo 'sync complete: uploaded=1'").unwrap();
        writeln!(file, "echo 'warning: on stderr' >&2").unwrap();
        drop(file);

        let target = Target {
            script: script.clone(),
            cwd: dir.clone(),
            python: "/bin/sh".to_string(),
        };

        let args = vec!["--sync".to_string()];
        let mut handle = JobHandle::start(&target, &args).expect("spawn");
        let mut log = String::new();
        let mut running = true;
        for _ in 0..200 {
            let (still, text, _exit) = handle.poll();
            running = still;
            log = text;
            if !running {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }

        assert!(!running, "sync did not finish: {log}");
        assert!(log.contains("args=--sync"), "args missing: {log}");
        assert!(log.contains("sync complete"), "missing stdout: {log}");
        assert!(log.contains("warning: on stderr"), "missing stderr: {log}");
        let canonical = std::fs::canonicalize(&dir).unwrap();
        assert!(
            log.contains(&format!("cwd={}", canonical.display())),
            "wrong cwd: {log}"
        );

        // The script is found next to the database, not in the cwd.
        let db = dir.join("servers.db");
        std::fs::write(&db, b"").unwrap();
        let found = find(db.to_str().unwrap()).expect("find mcscan.py");
        assert_eq!(found.script, script);
        assert_eq!(found.cwd, dir);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
