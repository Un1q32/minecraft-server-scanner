#!/usr/bin/env python3
"""mcscan: headless CLI for the Minecraft server scanner.

Shares all scanning/DB/sync code with the GUI (scanner.py), which imports
fine without Qt. Target syntax is identical to the GUI's Network Scan box:
IPs, CIDRs, start-end ranges, ASNs, hostnames, comma/space/newline
separated -- e.g. "1.0.0.0/8, AS13335, mc.example.com".

  mcscan.py --sync                  sync shared DB (creds from netdb.json)
  mcscan.py --download-db           replace local DB with the latest shared DB
  mcscan.py --vacuum-db             compact the local servers.db
  mcscan.py --dedupe                merge same-host duplicate ports + compact
  mcscan.py --init-db URL TOKEN     save shared-DB creds to netdb.json
  mcscan.py --recheck-whitelist IP:PORT ...
                                    probe whitelist status for those servers
  mcscan.py --set-whitelist IP:PORT LABEL
                                    store a whitelist verdict observed directly
  mcscan.py --rescan IP:PORT ...    re-ping those servers, update local DB
  mcscan.py --scan 1.0.0.0/8 ...    scan, print hits live, then sync
  mcscan.py --export out.csv        dump the full local DB to CSV
  mcscan.py --prune-activity        drop >4-day sightings, thin dense points,
                                    then VACUUM to reclaim space
  mcscan.py --continuous            self-tuning forever scan (matscan-style;
                                    auto-shards against the shared DB)
  mcscan.py --high-res              rescan-focused continuous mode: rescan
                                    every round with 5/30-minute due spacing

Discovery only (status ping + player sample) unless --recheck-whitelist
is used, which runs the same login probes as the GUI's Check Whitelist
button. Needs no display; masscan still needs raw-socket privileges (run as
root, or passwordless sudo for the automatic retry).
"""

import argparse
import csv
import os
import sys
import threading
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import scanner
import db_format

DB_COLUMNS = (
    "ip_port", "host", "port", "motd", "players_online", "max_players",
    "version", "protocol", "cracked", "whitelist", "first_seen",
    "last_seen", "times_seen", "last_source", "needs_sync",
    "players_now", "players_ever",
)


def _parse_ports(text):
    try:
        ports = scanner.parse_ports(text or "25565")
    except Exception:
        ports = [25565]
    return ports or [25565]


def _sync_creds():
    try:
        cfg = scanner.netdb_load_config()
    except Exception:
        return "", ""
    return (cfg.get("url", "") or "").strip(), \
        (cfg.get("token", "") or "").strip()


def cmd_init_db(url, token):
    """Write shared-DB creds to netdb.json (preserving sync progress)."""
    url = (url or "").strip().rstrip("/")
    token = (token or "").strip()
    if not url or not token:
        print("error: both URL and token are required: "
              "--init-db URL TOKEN")
        return 2
    try:
        cfg = scanner.netdb_load_config()
    except Exception:
        cfg = {}
    try:
        last_sync = float((cfg or {}).get("last_sync", 0) or 0)
    except Exception:
        last_sync = 0.0
    try:
        last_seq = int((cfg or {}).get("last_seq", 0) or 0)
    except Exception:
        last_seq = 0
    scanner.netdb_save_config(url, token, last_sync, last_seq)
    # netdb_save_config swallows IO errors, so verify the write.
    saved_url, saved_token = _sync_creds()
    if saved_url != url or saved_token != token:
        print("error: could not write netdb.json "
              "(check directory permissions).")
        return 1
    print(f"saved shared-DB URL and token to {scanner.NETDB_CONFIG_FILE}")
    return 0

def cmd_download_db(include_notes=True):
    """Download the shared DB (direct file when available) and install it."""
    url, token = _sync_creds()
    if not url or not token:
        print("error: netdb.json has no URL/token yet -- run "
              "'mcscan.py --init-db URL TOKEN' first.")
        return 2
    # Migrate/seed the local history before replacing the file so the
    # direct-download merge can carry it into the new database.
    try:
        scanner.init_server_db()
    except Exception:
        pass
    print(f"downloading shared DB at {url} ...", flush=True)

    def _size(value):
        value = max(0, int(value or 0))
        if value >= 1024 * 1024:
            return f"{value / (1024 * 1024):.1f} MB"
        if value >= 1024:
            return f"{value / 1024:.0f} KB"
        return f"{value} B"

    def progress(done, total):
        if total:
            pct = min(100, done * 100 // total)
            print(f"\r  {pct}% ({_size(done)}/{_size(total)})",
                  end="", flush=True)
        else:
            print(f"\r  {_size(done)}", end="", flush=True)

    try:
        try:
            count, max_seq, now = scanner.netdb_download_file(
                url, token, progress=progress)
            print()
        except scanner.NetdbDirectDownloadUnsupported:
            print("\nserver has no direct DB download; using row sync ...",
                  flush=True)
            rows, max_seq, now = scanner.netdb_download_all(url, token)
            count = scanner.netdb_replace_all(rows)
    except Exception as exc:
        print(f"\nerror: download failed: {exc}", flush=True)
        return 1
    scanner.netdb_save_config(url, token, now, max_seq)

    notes_count = 0
    notes_seq = None
    if not include_notes:
        print(f"download complete: {count} server(s), last_seq={max_seq}",
              flush=True)
        return 0
    try:
        print("downloading notes DB ...", flush=True)
        try:
            notes_count, notes_seq, _notes_now = scanner.netdb_notes_download_file(
                url, token, progress=progress)
            print()
        except scanner.NetdbDirectDownloadUnsupported:
            notes, notes_seq, _notes_now = scanner.notes_download_all(url, token)
            notes_count = scanner.notes_replace_all(notes)
    except scanner.NetdbEndpointUnsupported:
        print("notes sync not supported by this server; skipped.")
    except Exception as exc:
        print(f"\nwarning: notes download failed: {exc}", flush=True)
    if notes_seq is not None:
        scanner.netdb_save_config(last_notes_seq=notes_seq)
    shown_notes_seq = (notes_seq if notes_seq is not None
                       else scanner.netdb_load_config().get("last_notes_seq", 0))
    print(f"download complete: {count} server(s), {notes_count} note(s), "
          f"last_seq={max_seq}, notes_seq={shown_notes_seq}", flush=True)
    return 0


def cmd_vacuum_db():
    """Compact the local servers.db (useful after index migrations)."""
    scanner.init_server_db()
    path = os.path.abspath(scanner.SERVERS_DB_FILE)
    try:
        before = os.path.getsize(path)
    except OSError:
        before = 0
    print(f"vacuuming {path} ({before / (1024 * 1024):.1f} MB)...",
          flush=True)
    con = scanner._server_db_connect()
    try:
        con.execute("VACUUM")
    finally:
        con.close()
    try:
        after = os.path.getsize(path)
    except OSError:
        after = 0
    print(f"database compacted: {before / (1024 * 1024):.1f} MB -> "
          f"{after / (1024 * 1024):.1f} MB", flush=True)
    return 0


def cmd_dedupe():
    """Merge duplicate same-host ports and compact the local DB."""
    try:
        stats = scanner.deduplicate_local_db(vacuum=True)
    except Exception as exc:
        print(f"error: dedupe failed: {exc}", flush=True)
        return 1
    before = stats.get("before_bytes", 0)
    after = stats.get("after_bytes", 0)
    saved = max(0, before - after)
    print(
        "dedupe complete: "
        f"{stats.get('groups', 0)} groups, "
        f"{stats.get('removed_state', 0)} server rows, "
        f"{stats.get('removed_history', 0)} history rows removed; "
        f"{before / (1024 * 1024):.1f} MB -> {after / (1024 * 1024):.1f} MB "
        f"({saved / (1024 * 1024):.1f} MB saved)",
        flush=True)
    return 0


def cmd_sync():
    """Sync the shared DB using netdb.json. Returns exit code."""
    url, token = _sync_creds()
    if not url or not token:
        print("error: netdb.json has no URL/token yet -- run "
              "'mcscan.py --init-db URL TOKEN' first.")
        return 2
    if not scanner.netdb_local_db_ready():
        print("local DB missing or empty; downloading it first ...",
              flush=True)
        rc = cmd_download_db(include_notes=False)
        if rc:
            return rc
    print(f"syncing shared DB at {url} ...")
    try:
        summary = scanner.netdb_sync_once(url, token)
    except Exception as exc:
        print(f"sync failed: {exc}")
        return 1
    print("sync complete: "
          f"uploaded={summary.get('uploaded', 0)} "
          f"merged_on_server={summary.get('merged_on_server', 0)} "
          f"downloaded={summary.get('downloaded', 0)} "
          f"inserted={summary.get('inserted', 0)} "
          f"updated={summary.get('updated', 0)} "
          f"total_remote={summary.get('total_remote', 0)} "
          f"history_uploaded={summary.get('history_uploaded', 0)} "
          f"history_downloaded={summary.get('history_downloaded', 0)} "
          f"notes_uploaded={summary.get('notes_uploaded', 0)} "
          f"notes_downloaded={summary.get('notes_downloaded', 0)} "
          f"notes_inserted={summary.get('notes_inserted', 0)} "
          f"notes_updated={summary.get('notes_updated', 0)}")
    if summary.get("history_unsupported"):
        print("history sync not supported by this server; local history kept.")
    if summary.get("notes_unsupported"):
        print("notes sync not supported by this server; skipped.")
    if summary.get("notes_error"):
        print(f"warning: notes sync failed: {summary['notes_error']}")
    try:
        removed = scanner.prune_old_history()
        if removed:
            print(f"pruned {removed} old sighting(s) beyond the 4-day window")
    except Exception as exc:
        print(f"warning: could not prune old history: {exc}")
    return 0


def cmd_prune_activity():
    """Prune and thin activity history, then compact servers.db."""
    path = os.path.abspath(scanner.SERVERS_DB_FILE)
    before = os.path.getsize(path) if os.path.isfile(path) else 0
    try:
        con = scanner._server_db_connect()
    except Exception as exc:
        print(f"error: could not open {path}: {exc}")
        return 1
    try:
        try:
            stats = db_format.prune_activity(con)
            con.commit()
            remaining = int(con.execute(
                "SELECT COUNT(*) FROM server_history").fetchone()[0] or 0)
            con.execute("VACUUM")
        except Exception as exc:
            try:
                con.rollback()
            except Exception:
                pass
            print(f"error: activity prune failed: {exc}")
            return 1
    finally:
        con.close()
    after = os.path.getsize(path) if os.path.isfile(path) else 0
    print("activity prune: "
          f"removed_old={stats.get('removed_old', 0)} "
          f"thinned={stats.get('thinned', 0)} "
          f"remaining={remaining} "
          f"size={before / 1048576:.1f}MB -> {after / 1048576:.1f}MB")
    return 0


def cmd_set_whitelist(ip, label):
    """Store a whitelist verdict that a real client join already produced."""
    ip = scanner.strict_ip_port(ip)
    if not ip:
        print(f"error: {ip!r} is not a valid ip:port", flush=True)
        return 2
    label = (label or "").strip()
    if not label:
        print("error: whitelist label is empty", flush=True)
        return 2
    scanner.update_server_whitelist(ip, label)
    print(f"whitelist set: {ip}: {label}", flush=True)
    return 0


def cmd_recheck_whitelist(ips):
    """Probe whitelist status for the given servers and update servers.db.

    Mirrors the GUI's "Check Whitelist": stored Minecraft accounts rotate
    for online-mode servers, offline-mode servers answer without one.
    """
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except Exception:
        pass

    entries = []
    seen = set()
    for raw in ips or []:
        ip = scanner.strict_ip_port(raw)
        if not ip:
            print(f"skip {raw!r}: not a valid ip:port", flush=True)
            continue
        if ip in seen:
            continue
        seen.add(ip)
        version = ""
        protocol = None
        try:
            con = scanner._server_db_connect()
            try:
                row = con.execute(
                    "SELECT version, protocol FROM servers WHERE ip_port=?",
                    (ip,)).fetchone()
            finally:
                con.close()
            if row:
                version = str(row[0] or "")
                protocol = row[1]
        except Exception as exc:
            print(f"warning: could not read {ip}: {exc}", flush=True)
        if protocol in (None, ""):
            protocol = scanner._stored_protocol(ip)
        entries.append({"ip": ip, "version": version, "protocol": protocol})

    if not entries:
        print("error: no valid servers to check", flush=True)
        return 2

    print(f"whitelist recheck: {len(entries)} server(s)", flush=True)
    done = threading.Event()

    def on_update(entry, result, message):
        label = scanner.whitelist_result_label(result, message)
        scanner.update_server_whitelist(entry.get("ip"), label)
        print(f"  {entry.get('ip')}: {label}", flush=True)

    def progress(completed, total):
        print(f"  progress: {completed}/{total}", flush=True)
        if completed >= total:
            done.set()

    try:
        scanner.run_whitelist_verifier_async(
            entries, None, on_update, progress_cb=progress)
    except Exception as exc:
        print(f"error: whitelist recheck failed: {exc}", flush=True)
        return 1

    timeout = max(120, 20 * len(entries))
    if not done.wait(timeout):
        print("error: whitelist recheck timed out", flush=True)
        return 1
    print(f"whitelist recheck complete: {len(entries)} server(s)", flush=True)
    return 0


def cmd_rescan(ips):
    """Re-ping selected servers and update the local DB (no masscan/sync).

    Mirrors the GUI's "Rescan Selected": status ping only, so it also
    refreshes MOTD/version/player counts and player samples.
    """
    targets = []
    seen = set()
    for raw in ips or []:
        ip = scanner.strict_ip_port(raw)
        if not ip:
            print(f"skip {raw!r}: not a valid ip:port", flush=True)
            continue
        if ip in seen:
            continue
        seen.add(ip)
        targets.append(ip)
    if not targets:
        print("error: no valid servers to rescan", flush=True)
        return 2

    print(f"rescanning {len(targets)} server(s)...", flush=True)

    def on_result(result, line):
        print(line, flush=True)

    def on_progress(done, total):
        if done >= total:
            print(f"  progress: {done}/{total}", flush=True)

    try:
        results, _ = scanner.scan_servers_gui(
            targets, on_result=on_result, on_progress=on_progress)
    except scanner.ScanStopped:
        print("rescan stopped.", flush=True)
        return 130
    except Exception as exc:
        print(f"error: rescan failed: {exc}", flush=True)
        return 1

    print(f"rescan complete. Responded: {len(results)}/{len(targets)}.",
          flush=True)
    try:
        scanner.prune_old_history()
    except Exception:
        pass
    return 0


def _csv_cell(value):
    """Neutralize spreadsheet formula injection from server-controlled text."""
    if value is None:
        return ""
    text = str(value)
    if text[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + text
    return text


def cmd_export(path):
    """Dump the full local DB to CSV. Returns exit code."""
    try:
        entries = scanner.query_server_db()
    except Exception as exc:
        print(f"error: could not read local DB: {exc}")
        return 1
    try:
        with open(path, "w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(list(DB_COLUMNS))
            for e in entries:
                row = []
                for col in DB_COLUMNS:
                    try:
                        val = e.get(col, "")
                    except Exception:
                        val = ""
                    row.append(_csv_cell(val))
                writer.writerow(row)
    except Exception as exc:
        print(f"error: could not write {path}: {exc}")
        return 1
    print(f"exported {len(entries)} server(s) to {path}")
    return 0


def _print_hit(result):
    try:
        line = scanner.format_result_line(
            result.get("ip", ""), result.get("motd", ""),
            result.get("players", 0), result.get("max_players", 0),
            result.get("version", "N/A"))
    except Exception:
        try:
            line = str(result.get("ip", ""))
        except Exception:
            line = "<unprintable hit>"
    print(line, flush=True)
    return line


def _want_sudo_retry():
    """True when a failed privileged masscan is worth one sudo attempt.

    Only passwordless/cached sudo: a CLI must never prompt for (or accept
    via argv, which leaks to ps) a sudo password. Otherwise run as root.
    """
    try:
        return scanner.sudo_noninteractive_ok()
    except Exception:
        return False


def run_python_backend(target_text, ports, stop_event, max_hosts):
    """Pure-Python handshake sweep. Returns list of result dicts."""
    try:
        targets = scanner.expand_scan_targets(target_text, ports,
                                              max_hosts=max_hosts)
    except Exception as exc:
        print(f"target error: {exc}")
        return []
    if not targets:
        print("No valid targets to scan.")
        return []

    print(f"python: handshaking {len(targets)} target(s)...")
    last_status = [0.0]

    def on_result(r, line):
        _print_hit(r)

    def on_progress(done, total):
        now = time.time()
        if done >= total or now - last_status[0] >= 5:
            last_status[0] = now
            print(f"progress: {done}/{total}", flush=True)

    try:
        results, _ = scanner.scan_servers_gui(
            targets, on_result=on_result, on_progress=on_progress,
            stop_event=stop_event)
    except scanner.ScanStopped:
        print("stopped.")
        return []
    return results or []


def run_masscan_backend(target_text, ports, rate, wait, stop_event,
                        allow_sudo_retry=True):
    """masscan SYN discovery + handshake pool. Returns list of results.

    Raises FileNotFoundError (no binary) or PermissionError (no
    raw-socket privileges and no passwordless sudo).
    """
    ranges, direct = scanner.build_masscan_inputs(target_text, ports)
    if not ranges and not direct:
        print("No valid targets to scan.")
        return []
    try:
        total_hosts = (sum(scanner._masscan_count_hosts(spec, cap=None)
                           for spec in ranges) + len(direct))
    except Exception:
        total_hosts = len(direct)

    results = []
    lock = threading.Lock()
    pool = scanner.ThreadPoolExecutor(max_workers=scanner.STATUS_WORKERS)
    probed = {"n": 0}
    last_status = [0.0]

    def status():
        now = time.time()
        if now - last_status[0] >= 5:
            last_status[0] = now
            with lock:
                print(f"masscan: open={len(results)} "
                      f"handshaked={probed['n']}/{total_hosts}", flush=True)

    def handshake(ip_port):
        if scanner.shutdown_requested():
            return
        try:
            r = scanner.ping_server(ip_port)
        except Exception:
            r = None
        with lock:
            probed["n"] += 1
        if r:
            with lock:
                results.append(r)
            _print_hit(r)
        status()

    pool_done = False

    def finish_pool(wait):
        nonlocal pool_done
        if pool_done:
            return
        pool_done = True
        try:
            if wait:
                pool.shutdown(wait=True)
            else:
                pool.shutdown(wait=False, cancel_futures=True)
        except Exception:
            pass

    try:
        with lock:
            for d in direct:
                pool.submit(handshake, d)
        if not ranges:
            print(f"masscan: {len(direct)} direct target(s), "
                  "handshaking (no SYN sweep)...")
            finish_pool(not scanner.shutdown_requested())
            return results

        def on_open(ip_port):
            pool.submit(handshake, ip_port)

        def on_scan_progress(pct, rate_now):
            try:
                print(f"masscan: {pct}% @ {rate_now}pps | "
                      f"open={len(results)}", flush=True)
            except Exception:
                pass

        print(f"masscan: discovering open ports on ~{total_hosts:,} "
              f"host(s) (live)...")
        try:
            scanner.run_masscan_streaming(
                ranges, ports, rate=rate, wait=wait, on_open=on_open,
                on_scan_progress=on_scan_progress, stop_event=stop_event)
        except PermissionError:
            if allow_sudo_retry and _want_sudo_retry():
                print("masscan: retrying with sudo...")
                scanner.run_masscan_streaming(
                    ranges, ports, rate=rate, wait=wait, on_open=on_open,
                    on_scan_progress=on_scan_progress,
                    use_sudo=True, sudo_password=None,
                    stop_event=stop_event)
            else:
                raise
        finish_pool(not scanner.shutdown_requested())
    except scanner.ScanStopped:
        finish_pool(False)
        print("stopped.")
    except BaseException:
        # Ctrl+C / SIGTERM: never wait for queued handshakes.
        finish_pool(False)
        raise
    return results


def run_minescan_backend(target_text, ports, stop_event):
    """minescan (webscan) async sweep. Returns list of result dicts."""
    try:
        runs, warnings = scanner.build_minescan_inputs(
            target_text, ports, scanner.MINESCAN_MAX_HOSTS)
    except Exception as exc:
        print(f"target error: {exc}")
        return []
    for w in (warnings or [])[:5]:
        print(f"minescan: {w}")
    if not runs:
        print("No valid targets to scan.")
        return []
    try:
        timeout = scanner.minescan_default_timeout(
            runs, scanner.MASSCAN_DEFAULT_RATE)
    except Exception:
        timeout = 600
    results = []
    lock = threading.Lock()
    for ri, run in enumerate(runs):
        tag = f"run {ri + 1}/{len(runs)}: " if len(runs) > 1 else ""
        print(f"minescan {tag}{len(run['targets'])} target(s) on "
              f"port(s) {','.join(str(p) for p in run['ports'])}...")

        def on_hit(hit, _lock=lock):
            try:
                scanner.record_server_result(hit, source="minescan")
            except Exception:
                pass
            try:
                scanner.USER_LOG_MANAGER.update_from_result(hit)
            except Exception:
                pass
            with _lock:
                results.append(hit)
            _print_hit(hit)

        def on_stats(stats):
            try:
                print(scanner.format_minescan_status(
                    stats, len(results),
                    sum(int(r.get("estimate", 0) or 0) for r in runs)),
                    flush=True)
            except Exception:
                pass

        try:
            scanner.run_minescan_streaming(
                run["targets"], run["ports"], rate=scanner.MASSCAN_DEFAULT_RATE,
                timeout=timeout, stop_event=stop_event,
                on_hit=on_hit, on_stats=on_stats)
        except scanner.ScanStopped:
            print("stopped.")
            break
        except Exception as exc:
            print(f"minescan {tag}failed ({exc}), continuing")
    return results


# Set by the SIGINT/SIGTERM handler; scans poll it and bail out fast.
_CLI_STOP = threading.Event()
_SIGNAL_STATE = {"count": 0}


def install_signal_handlers():
    """Ctrl+C: ask scans to stop; a second one force-quits.

    Without a handler, Ctrl+C raises KeyboardInterrupt in whatever frame
    happens to be running, and unwinding leaves queued handshakes behind
    that the interpreter's atexit hook then joins (the "hang"). A handler
    plus cooperative cancellation makes the first Ctrl+C orderly and fast.
    """
    import signal

    def handler(signum, frame):
        _SIGNAL_STATE["count"] += 1
        _CLI_STOP.set()
        try:
            scanner.request_shutdown()
        except Exception:
            pass
        if _SIGNAL_STATE["count"] >= 2:
            try:
                sys.stdout.flush()
                sys.stderr.flush()
            except Exception:
                pass
            os._exit(130)
        try:
            print("\ninterrupted: stopping after the current probes "
                  "(Ctrl+C again to force quit)...", flush=True)
        except Exception:
            pass

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, handler)
        except Exception:
            pass


def cmd_scan(args):
    """Run a backend sweep, print hits live, sync at the end."""
    target_text = "\n".join(args.targets)
    ports = _parse_ports(args.ports)
    stop_event = _CLI_STOP
    results = []
    tried = []

    def want(name):
        return args.backend in ("auto", name)

    try:
        # masscan first (Auto order mirrors the GUI): SYN discovery, then
        # handshake only on open ports.
        if want("masscan"):
            try:
                if not scanner.is_masscan_available():
                    raise FileNotFoundError("masscan binary not found")
                tried.append("masscan")
                results = run_masscan_backend(
                    target_text, ports, args.rate, args.wait, stop_event)
            except FileNotFoundError as exc:
                if args.backend == "masscan":
                    print(f"error: {exc}")
                    return 1
                print("masscan not found; trying minescan instead...")
            except PermissionError as exc:
                if args.backend == "masscan":
                    print(f"error: masscan needs privileges: {exc}")
                    print("run as root (or passwordless sudo), or use "
                          "--backend python.")
                    return 1
                print("masscan needs privileges; trying minescan instead...")
        # minescan (unprivileged async webscan).
        if not results and want("minescan"):
            try:
                tried.append("minescan")
                results = run_minescan_backend(target_text, ports,
                                               stop_event)
            except FileNotFoundError as exc:
                if args.backend == "minescan":
                    print(f"error: {exc}")
                    return 1
                print(f"minescan not available ({exc}); "
                      "falling back to Python...")
                results = []
        # pure Python handshake sweep.
        if not results and want("python"):
            tried.append("python")
            results = run_python_backend(target_text, ports, stop_event,
                                         args.max_hosts)
    except KeyboardInterrupt:
        print("\ninterrupted; stopping...")
        try:
            stop_event.set()
            scanner.request_shutdown()
        except Exception:
            pass
        return 130
    if stop_event.is_set():
        print(f"scan stopped ({'+'.join(tried) or 'nothing ran'}). "
              f"Responded: {len(results)} before the interrupt.")
        print("skipping the shared-DB sync; run --sync when convenient.")
        return 130
    print(f"scan complete ({'+'.join(tried) or 'nothing ran'}). "
          f"Responded: {len(results)}.")

    url, token = _sync_creds()
    if url and token:
        print("syncing shared DB...")
        try:
            summary = scanner.netdb_sync_once(url, token)
            print("sync complete: "
                  f"uploaded={summary.get('uploaded', 0)} "
                  f"downloaded={summary.get('downloaded', 0)} "
                  f"inserted={summary.get('inserted', 0)} "
                  f"updated={summary.get('updated', 0)} "
                  f"history_uploaded={summary.get('history_uploaded', 0)} "
                  f"history_downloaded={summary.get('history_downloaded', 0)}")
        except Exception as exc:
            print(f"sync failed (results are kept locally): {exc}")
    else:
        print("sync skipped (no URL/token in netdb.json).")
    try:
        scanner.prune_old_history()
    except Exception:
        pass
    return 0


def cmd_continuous(args):
    """Run the self-tuning forever loop. Returns exit code."""
    try:
        import continuous
    except Exception as exc:
        print(f"error: could not load continuous mode: {exc}")
        return 1
    strategies = None
    if getattr(args, "strategies", None):
        strategies = [s.strip() for s in args.strategies.split(",")
                      if s.strip()]
    shard = None
    if getattr(args, "shard", None):
        try:
            index_s, total_s = str(args.shard).split("/", 1)
            index, total = int(index_s), int(total_s)
        except Exception:
            print(f"error: --shard must look like 1/3, got {args.shard!r}")
            return 2
        if not (1 <= index <= total <= 1_000_000):
            print(f"error: --shard must satisfy 1 <= I <= N, got {args.shard!r}")
            return 2
        shard = (index, total)
    high_res = bool(getattr(args, "high_res", False))
    rescan_every = getattr(args, "rescan_every", None)
    if high_res and rescan_every is None:
        rescan_every = 1
    return continuous.run_continuous(
        rate=args.rate,
        wait=args.wait,
        scan_duration=getattr(args, "scan_duration", 300),
        sync_every=getattr(args, "sync_every", 300),
        state_path=getattr(args, "state_file", "strategies.json"),
        backend=args.backend,
        strategies=strategies,
        do_rescan=not getattr(args, "no_rescan", False),
        rescan_every=rescan_every,
        high_res=high_res,
        stop_event=_CLI_STOP,
        max_rounds=getattr(args, "rounds", None),
        shard=shard,
        seed=getattr(args, "scan_seed", None),
        base_ports=_parse_ports(getattr(args, "ports", "25565")),
        # High-res mode is rescan-only, so registering for a discovery
        # shard would reserve scan space it never uses.
        auto_shard=(not getattr(args, "no_auto_shard", False)
                    and shard is None and not high_res),
        node_id=getattr(args, "node_id", None),
    )


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="mcscan",
        description="Headless Minecraft server scanner (shares the "
                    "GUI's code; Qt never required).")
    parser.add_argument(
        "--init-db", nargs=2, metavar=("URL", "TOKEN"), default=None,
        help="save shared-DB URL and token to netdb.json")
    parser.add_argument(
        "--sync", action="store_true",
        help="sync the shared DB using creds in netdb.json")
    parser.add_argument(
        "--download-db", action="store_true",
        help="replace the local servers.db and notes.db with the full latest "
             "shared DBs and update netdb.json's seq watermarks")
    parser.add_argument(
        "--vacuum-db", action="store_true",
        help="compact the local servers.db (can take a while on SD cards; "
             "run it when not scanning/syncing)")
    parser.add_argument(
        "--dedupe", action="store_true",
        help="merge same-host duplicate ports (same MOTD/version/protocol) "
             "and compact servers.db")

    parser.add_argument(
        "--prune-activity", "--prune-history", dest="prune_activity",
        action="store_true",
        help="delete sightings older than 4 days and thin remaining points "
             "closer than 5 minutes (with players) or 30 minutes (empty), "
             "then VACUUM to reclaim space; players_ever is kept")
    parser.add_argument(
        "--scan", nargs="+", metavar="TARGET", dest="targets",
        help="scan targets (same syntax as the GUI box): IPs, CIDRs, "
             "ranges (a-b), ASNs, hostnames")
    parser.add_argument(
        "--recheck-whitelist", nargs="+", metavar="IP:PORT", default=None,
        help="probe whitelist status for these servers and update the DB "
             "(same probes as the GUI's Check Whitelist)")
    parser.add_argument(
        "--set-whitelist", nargs=2, metavar=("IP:PORT", "LABEL"), default=None,
        help="store a whitelist verdict observed from a real client join")
    parser.add_argument(
        "--rescan", nargs="+", metavar="IP:PORT", default=None,
        help="re-ping these servers and update the local DB (status ping "
             "only; no masscan and no shared-DB sync)")
    parser.add_argument(
        "--export", metavar="FILE",
        help="write the full local DB to FILE as CSV")
    parser.add_argument(
        "--continuous", action="store_true",
        help="run forever, picking scan strategies by their yield history "
             "(matscan-style) and rescanning due servers")
    parser.add_argument(
        "--high-res", "--hi-res", dest="high_res", action="store_true",
        help="run the continuous loop in rescan-focused high-resolution "
             "mode: rescan every round (like --rescan-every 1), revisit "
             "players every 5 minutes and recent servers every 30 minutes. "
             "Does not register for automatic sharding")
    parser.add_argument(
        "--scan-duration", type=int, default=300, metavar="SECS",
        help="time box per scan round in --continuous (default: 300)")
    parser.add_argument(
        "--sync-every", type=int, default=300, metavar="SECS",
        help="shared-DB sync cadence in --continuous (default: 300)")
    parser.add_argument(
        "--state-file", default="strategies.json", metavar="FILE",
        help="strategy score file for --continuous "
             "(default: strategies.json)")
    parser.add_argument(
        "--strategies", metavar="LIST", default=None,
        help="comma-separated strategies for --continuous: "
             "slash0,slash16a,slash16b,slash24a,slash24b,slash24c,"
             "slash32a,slash32b,slash32c")
    parser.add_argument(
        "--no-rescan", action="store_true",
        help="--continuous: skip rescan rounds entirely")
    parser.add_argument(
        "--rescan-every", type=int, default=None, metavar="N",
        help="--continuous: run one rescan round every N rounds "
             "(default: 2, alternating normal/rescan; 1 rescans every "
             "round)")
    parser.add_argument(
        "--shard", metavar="I/N", default=None,
        help="--continuous: manual slice of the scan space (e.g. 1/3); "
             "overrides automatic sharding. By default continuous nodes "
             "register with the shared DB and are assigned shards "
             "automatically")
    parser.add_argument(
        "--no-auto-shard", action="store_true",
        help="--continuous: do not register with the shared DB for "
             "automatic sharding (use --shard for a fixed slice)")
    parser.add_argument(
        "--node-id", metavar="ID", default=None,
        help="--continuous: stable id for automatic sharding; default is "
             "stored in continuous_node_id next to --state-file")
    parser.add_argument(
        "--scan-seed", type=int, default=None, metavar="N",
        help="--continuous sharding: masscan shuffle seed; all machines "
             "must use the same value (default: a fixed constant)")
    parser.add_argument(
        "--rounds", type=int, default=None, metavar="N",
        help="--continuous: stop after N rounds (testing)")
    parser.add_argument(
        "--backend", default="auto",
        choices=("auto", "masscan", "minescan", "python"),
        help="discovery backend (default: auto, masscan first)")
    parser.add_argument(
        "--ports", default="25565",
        help='ports to scan, e.g. "25565" or "25565,25566" (default: 25565); '
             'in --continuous this sets the broad-strategy ports '
             '(slash0/slash16*/slash24a)')
    parser.add_argument(
        "--rate", type=int, default=scanner.MASSCAN_DEFAULT_RATE,
        help="masscan packets/sec (default: %(default)s)")
    parser.add_argument(
        "--wait", type=int, default=scanner.MASSCAN_DEFAULT_WAIT,
        help="masscan post-scan wait seconds (default: %(default)s)")
    parser.add_argument(
        "--max-hosts", type=int, default=scanner.NETWORK_SCAN_MAX_HOSTS,
        help="Python-backend host cap (default: %(default)s)")
    args = parser.parse_args(argv)

    if not args.sync and args.targets is None and not args.export \
            and args.init_db is None and not args.continuous \
            and not args.high_res \
            and args.recheck_whitelist is None and args.set_whitelist is None \
            and args.rescan is None \
            and not args.download_db and not args.vacuum_db \
            and not args.dedupe and not args.prune_activity:
        parser.print_help()
        return 2
    install_signal_handlers()
    try:
        scanner.init_server_db()
    except Exception as exc:
        print(f"warning: DB init failed: {exc}")
    try:
        scanner.init_notes_db()
    except Exception as exc:
        print(f"warning: notes DB init failed: {exc}")
    rc = 0
    try:
        if args.init_db is not None:
            rc = cmd_init_db(*args.init_db) or rc
        if args.download_db:
            rc = cmd_download_db() or rc
        if args.vacuum_db:
            rc = cmd_vacuum_db() or rc
        if args.dedupe:
            rc = cmd_dedupe() or rc
        if args.prune_activity:
            rc = cmd_prune_activity() or rc
        if args.sync:
            rc = cmd_sync() or rc
        if args.recheck_whitelist is not None:
            rc = cmd_recheck_whitelist(args.recheck_whitelist) or rc
        if args.set_whitelist is not None:
            rc = cmd_set_whitelist(*args.set_whitelist) or rc
        if args.rescan is not None:
            rc = cmd_rescan(args.rescan) or rc
        if args.continuous or args.high_res:
            rc = cmd_continuous(args) or rc
        if args.targets is not None:
            rc = cmd_scan(args) or rc
        if args.export:
            # --export runs even if a scan failed (rc preserved).
            rc = cmd_export(args.export) or rc
    finally:
        if _CLI_STOP.is_set():
            # Interrupted: don't let the interpreter's atexit hook join
            # worker threads (that is the classic "Ctrl+C hangs" path).
            try:
                sys.stdout.flush()
                sys.stderr.flush()
            except Exception:
                pass
            os._exit(rc or 130)
    return rc


if __name__ == "__main__":
    sys.exit(main())
