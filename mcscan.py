#!/usr/bin/env python3
"""mcscan: headless CLI for the Minecraft server scanner.

Shares all scanning/DB/sync code with the GUI (scanner.py), which imports
fine without Qt. Target syntax is identical to the GUI's Network Scan box:
IPs, CIDRs, start-end ranges, ASNs, hostnames, comma/space/newline
separated -- e.g. "1.0.0.0/8, AS13335, mc.example.com".

  mcscan.py --sync                  sync shared DB (creds from netdb.json)
  mcscan.py --init-db URL TOKEN     save shared-DB creds to netdb.json
  mcscan.py --scan 1.0.0.0/8 ...    scan, print hits live, then sync
  mcscan.py --export out.csv        dump the full local DB to CSV

Discovery only (status ping + player sample); whitelist/cracked login
probes stay in the GUI. Needs no display; masscan still needs raw-socket
privileges (run as root, or passwordless sudo for the automatic retry).
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

    try:
        with lock:
            for d in direct:
                pool.submit(handshake, d)
        if not ranges:
            print(f"masscan: {len(direct)} direct target(s), "
                  "handshaking (no SYN sweep)...")
            pool.shutdown(wait=True)
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
        pool.shutdown(wait=True)
    except scanner.ScanStopped:
        try:
            pool.shutdown(wait=False, cancel_futures=True)
        except Exception:
            pass
        print("stopped.")
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


def cmd_scan(args):
    """Run a backend sweep, print hits live, sync at the end."""
    target_text = "\n".join(args.targets)
    ports = _parse_ports(args.ports)
    stop_event = threading.Event()
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
        except Exception:
            pass
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
        "--export", metavar="FILE",
        help="write the full local DB to FILE as CSV")
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
            and args.init_db is None:
        parser.print_help()
        return 2
    try:
        scanner.init_server_db()
    except Exception as exc:
        print(f"warning: DB init failed: {exc}")
    rc = 0
    if args.init_db is not None:
        rc = cmd_init_db(*args.init_db) or rc
    if args.sync:
        rc = cmd_sync() or rc
    if args.targets is not None:
        rc = cmd_scan(args) or rc
    if args.export:
        # --export runs even if a scan failed (rc preserved).
        rc = cmd_export(args.export) or rc
    return rc


if __name__ == "__main__":
    sys.exit(main())
