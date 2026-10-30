#!/usr/bin/env python3
"""mcscan: headless CLI for the Minecraft server scanner.

Shares all scanning/DB/sync code with the GUI (scanner.py), which imports
fine without Qt. Target syntax is identical to the GUI's Network Scan box:
IPs, CIDRs, start-end ranges, ASNs, hostnames, comma/space/newline
separated -- e.g. "1.0.0.0/8, AS13335, mc.example.com".

  mcscan.py --sync                  sync shared DB (creds from netdb.json)
  mcscan.py --init-db URL TOKEN     save shared-DB creds to netdb.json
  mcscan.py --recheck-whitelist IP:PORT ...
                                    probe whitelist status for those servers
  mcscan.py --scan 1.0.0.0/8 ...    scan, print hits live, then sync
  mcscan.py --export out.csv        dump the full local DB to CSV
  mcscan.py --continuous            self-tuning forever scan (matscan-style)

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


def cmd_sync():
    """Sync the shared DB using netdb.json. Returns exit code."""
    url, token = _sync_creds()
    if not url or not token:
        print("error: netdb.json has no URL/token yet -- run "
              "'mcscan.py --init-db URL TOKEN' first.")
        return 2
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
          f"total_remote={summary.get('total_remote', 0)}")
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
                    row.append("" if val is None else val)
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
    pool = scanner.ThreadPoolExecutor(max_workers=scanner.MAX_WORKERS)
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
                  f"updated={summary.get('updated', 0)}")
        except Exception as exc:
            print(f"sync failed (results are kept locally): {exc}")
    else:
        print("sync skipped (no URL/token in netdb.json).")
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
    return continuous.run_continuous(
        rate=args.rate,
        wait=args.wait,
        scan_duration=getattr(args, "scan_duration", 300),
        sync_every=getattr(args, "sync_every", 300),
        state_path=getattr(args, "state_file", "strategies.json"),
        backend=args.backend,
        strategies=strategies,
        do_rescan=not getattr(args, "no_rescan", False),
        stop_event=_CLI_STOP,
        max_rounds=getattr(args, "rounds", None),
        shard=shard,
        seed=getattr(args, "scan_seed", None),
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
        "--scan", nargs="+", metavar="TARGET", dest="targets",
        help="scan targets (same syntax as the GUI box): IPs, CIDRs, "
             "ranges (a-b), ASNs, hostnames")
    parser.add_argument(
        "--recheck-whitelist", nargs="+", metavar="IP:PORT", default=None,
        help="probe whitelist status for these servers and update the DB "
             "(same probes as the GUI's Check Whitelist)")
    parser.add_argument(
        "--export", metavar="FILE",
        help="write the full local DB to FILE as CSV")
    parser.add_argument(
        "--continuous", action="store_true",
        help="run forever, picking scan strategies by their yield history "
             "(matscan-style) and rescanning due servers")
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
        help="--continuous: skip the rescan half of the loop")
    parser.add_argument(
        "--shard", metavar="I/N", default=None,
        help="--continuous: this machine's slice of the scan space, e.g. "
             "1/3 on the first of three machines; use a different I on "
             "each machine (they share the default seed so slices are "
             "disjoint)")
    parser.add_argument(
        "--scan-seed", type=int, default=None, metavar="N",
        help="--continuous --shard: masscan shuffle seed; all machines "
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
        help='ports to scan, e.g. "25565" or "25565,25566" (default: 25565)')
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
            and args.recheck_whitelist is None:
        parser.print_help()
        return 2
    install_signal_handlers()
    try:
        scanner.init_server_db()
    except Exception as exc:
        print(f"warning: DB init failed: {exc}")
    rc = 0
    try:
        if args.init_db is not None:
            rc = cmd_init_db(*args.init_db) or rc
        if args.sync:
            rc = cmd_sync() or rc
        if args.recheck_whitelist is not None:
            rc = cmd_recheck_whitelist(args.recheck_whitelist) or rc
        if args.continuous:
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
