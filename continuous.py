"""Continuous, self-tuning scanning mode (matscan-inspired).

Runs two round categories forever:

* **normal** -- a scan strategy picked by weight:
    slash0    the whole IPv4 space on the configured ports (default 25565;
              time-boxed, random order)
    slash16a  /16 blocks around servers seen in the last 30 days
    slash16b  /16 blocks with >= 32 known IPs (busy subnets, last 365 days)
    slash20a  /20 blocks around servers seen in the last 365 days
    slash24a  /24 blocks around servers seen in the last 365 days
    slash24b  ... same /24s on ports 25566-25568
    slash24c  ... same /24s on ports 25560-25564 + 25569-25570
    slash32a  known IPs (last 30 days) on all ports 1024-65535
    slash32b  known IPs (last 365 days) on all ports 1024-65535
    slash32c  IPs hosting >= 8 servers on all ports 1024-65535
* **rescan** -- servers whose last successful ping is due, by age tier
  (2h-1d, 1-7d, 7-30d, 30-365d, >365d), plus a fast tier for servers
  that have players online right now.  Rescans are cheap enough that they
  no longer need to take every other round; by default one rescan runs
  every ``DEFAULT_RESCAN_EVERY`` rounds (``--rescan-every``).

After each normal round the strategy is scored like matscan:
``(new + 5*new_on_25565 + 0.1*revived) * 3600 / (seconds + 30)`` --
new servers per hour, with default-port finds weighted 5x because they
last longer. Scores persist to ``strategies.json``; 90% of rounds take
the best strategy, 10% explore a random one. An empty/unknown DB makes
everything tie, which bootstraps with ``slash0``.

Every scan is time-boxed (``--scan-duration``), so ``slash0`` is a
random-order sweep of a slice of the internet, not a full 4-billion-host
sweep. The shared DB is synced on a cadence (``--sync-every``) so peers
see new finds promptly.

When shared-DB credentials exist, continuous nodes also auto-shard: each
heartbeats ``/api/continuous`` every 10 seconds, and the DB server returns
its 1-based index plus the current node count. Nodes are ordered by
registration time, so adding one appends a shard without disturbing the
others. A node expires after 30 seconds without a heartbeat, and a clean
stop sends an explicit leave. The latest index is applied at the next
round boundary. ``--shard I/N`` opts out and uses a fixed manual slice.

Discovery only: status pings, no logins. masscan is strongly recommended
(the /32 strategies scan 63k ports per host); without it the module falls
back to the Python handshake pool and skips rounds that are too large.
"""

import concurrent.futures
import json
import os
import random
import re
import secrets
import socket
import sys
import threading
import time

import scanner

# --- tunables -------------------------------------------------------------
SLEEP_SECS = 10                 # quiet gap between rounds (attribution)
DEFAULT_SCAN_DURATION = 300     # per-round time box (matscan: 5 min)
DEFAULT_SYNC_EVERY = 300        # shared-DB sync cadence
DEFAULT_RESCAN_EVERY = 4        # normal rounds between rescan rounds
RESCAN_PY_MAX = 100             # tiny port groups: ping directly, no masscan
DEEP_PORT_LO = 1024
DEEP_PORT_HI = 65535
REVIVED_AFTER = 7 * 86400       # unseen this long -> a find is a "revival"
DENSE_SUBNET_IPS = 32           # slash16b: only /16s with this many IPs
DENSE_IP_SERVERS = 8            # slash32c: only IPs with this many servers
DEFAULT_FOUND = 1_000_000       # matscan's "never scored yet" seed
PY_MAX_PROBES = 250_000         # refuse bigger rounds on the Python backend
RANDOM_EXPLORE = 0.10
STATUS_INTERVAL = 0.3           # live status redraw (seconds)
STATUS_LOG_INTERVAL = 15.0      # redraw cadence when output is piped
SHARD_HEARTBEAT = 10.0          # auto-shard heartbeat interval (seconds)
SHARD_TIMEOUT = 8.0             # per-heartbeat HTTP timeout (seconds)
NODE_ID_FILE = "continuous_node_id"

STRATEGY_NAMES = (
    "slash0", "slash16a", "slash16b", "slash20a",
    "slash24a", "slash24b", "slash24c",
    "slash32a", "slash32b", "slash32c",
)

# Rescan tiers: only servers whose last_seen falls in
# (now - max_age, now - every) are due. require_players is matscan's
# "rescan2" idea: servers with people on them are rechecked often.
# Rescans ping the exact ip:port that was stored, never a padded /20.
# Padding a 155k-server rescan into /20s turned it into >500M probes, so a
# 300s round only reached a few hundred servers and reported almost no
# hits.  masscan already paces SYNs globally (--rate), so exact endpoints
# are not a "tight burst".  Neighborhood discovery stays in the normal
# slash16/slash24 strategies, where it belongs.
#
# rescan-players goes first: those servers are online right now and are
# the most valuable to refresh.
RESCAN_TIERS = (
    {"name": "rescan-players", "every": 600, "max_age": 2 * 3600,
     "limit": 10_000, "sort": "oldest", "require_players": True},
    {"name": "rescan-1d", "every": 2 * 3600, "max_age": 86400,
     "limit": 250_000, "sort": "oldest"},
    {"name": "rescan-7d", "every": 86400, "max_age": 7 * 86400,
     "limit": 250_000, "sort": "oldest"},
    {"name": "rescan-30d", "every": 7 * 86400, "max_age": 30 * 86400,
     "limit": 250_000, "sort": "random"},
    {"name": "rescan-365d", "every": 30 * 86400, "max_age": 365 * 86400,
     "limit": 500_000, "sort": "random"},
    {"name": "rescan-old", "every": 365 * 86400, "max_age": 3650 * 86400,
     "limit": 500_000, "sort": "random"},
)


# --- helpers --------------------------------------------------------------
def _port_of(ip_port):
    try:
        return int(str(ip_port).rsplit(":", 1)[1])
    except Exception:
        return 25565


def _host_of(ip_port):
    """'1.2.3.4:25565' -> '1.2.3.4' (scanner.get_ip_only keeps the port)."""
    try:
        text = str(ip_port).split(" |", 1)[0].strip()
        if text.count(":") == 1:
            return text.rsplit(":", 1)[0]
        return text
    except Exception:
        return ""


def _now():
    return time.time()


def _known_rows():
    """Fresh rows for strategy/rescan selection. Never raises."""
    try:
        return scanner.query_server_db() or []
    except Exception as exc:
        print(f"warning: could not read local DB ({exc}); treating as empty")
        return []


def _dead_ports():
    """Ports in the deep range, as a plain list for the backends."""
    return list(range(DEEP_PORT_LO, DEEP_PORT_HI + 1))


def _group_by(rows, prefix_len):
    """{prefix_bytes: set(IPv4Address)} for rows' hosts, /8../32."""
    import ipaddress
    out = {}
    for row in rows:
        try:
            ip = ipaddress.IPv4Address(_host_of(row.get("ip_port", "")))
        except Exception:
            continue
        out.setdefault(ip.packed[:prefix_len // 8], set()).add(ip)
    return out


def _active(rows, max_age):
    cutoff = _now() - max_age
    out = []
    for row in rows:
        try:
            if float(row.get("last_seen") or 0) >= cutoff:
                out.append(row)
        except Exception:
            continue
    return out


def _prefixes_to_cidrs(groups, prefix_len):
    """{(a,b): ips} -> ['a.b.0.0/16', ...] (sorted for stable logs)."""
    out = []
    for key in groups:
        parts = list(key) + [0] * (4 - len(key))
        out.append(".".join(str(p) for p in parts) + f"/{prefix_len}")
    return sorted(out)


# --- scan strategies ------------------------------------------------------
def _base_ports(ports):
    """Configured ports for the broad strategies; default is 25565."""
    return list(ports) if ports else [25565]


def strat_slash0(_rows, base_ports=None):
    """Whole IPv4 space on the configured ports (default 25565)."""
    return (["0.0.0.0/0"], _base_ports(base_ports))


def strat_slash16a(rows, base_ports=None):
    active = _active(rows, 30 * 86400)
    groups = _group_by(active, 16)
    return (_prefixes_to_cidrs(groups, 16), _base_ports(base_ports))


def strat_slash16b(rows, base_ports=None):
    active = _active(rows, 365 * 86400)
    groups = {k: v for k, v in _group_by(active, 16).items()
              if len(v) >= DENSE_SUBNET_IPS}
    return (_prefixes_to_cidrs(groups, 16), _base_ports(base_ports))


def strat_slash20a(rows, base_ports=None):
    active = _active(rows, 365 * 86400)
    groups = _group_by(active, 20)
    return (_prefixes_to_cidrs(groups, 20), _base_ports(base_ports))


def strat_slash24a(rows, base_ports=None):
    active = _active(rows, 365 * 86400)
    groups = _group_by(active, 24)
    return (_prefixes_to_cidrs(groups, 24), _base_ports(base_ports))


def strat_slash24b(rows, _base_ports=None):
    active = _active(rows, 365 * 86400)
    groups = _group_by(active, 24)
    return (_prefixes_to_cidrs(groups, 24), [25566, 25567, 25568])


def strat_slash24c(rows, _base_ports=None):
    active = _active(rows, 365 * 86400)
    groups = _group_by(active, 24)
    ports = list(range(25560, 25565)) + [25569, 25570]
    return (_prefixes_to_cidrs(groups, 24), ports)


def _known_ips(rows, max_age):
    import ipaddress
    seen = set()
    for row in _active(rows, max_age):
        try:
            seen.add(ipaddress.IPv4Address(_host_of(row.get("ip_port", ""))))
        except Exception:
            continue
    return [str(ip) for ip in sorted(seen)]


def strat_slash32a(rows, _base_ports=None):
    return (_known_ips(rows, 30 * 86400), _dead_ports())


def strat_slash32b(rows, _base_ports=None):
    return (_known_ips(rows, 365 * 86400), _dead_ports())


def strat_slash32c(rows, _base_ports=None):
    import ipaddress
    counts = {}
    for row in _active(rows, 30 * 86400):
        try:
            ip = ipaddress.IPv4Address(_host_of(row.get("ip_port", "")))
        except Exception:
            continue
        counts[ip] = counts.get(ip, 0) + 1
    ips = [str(ip) for ip, n in sorted(counts.items())
           if n >= DENSE_IP_SERVERS]
    return (ips, _dead_ports())


STRATEGIES = {
    "slash0": strat_slash0,
    "slash16a": strat_slash16a,
    "slash16b": strat_slash16b,
    "slash20a": strat_slash20a,
    "slash24a": strat_slash24a,
    "slash24b": strat_slash24b,
    "slash24c": strat_slash24c,
    "slash32a": strat_slash32a,
    "slash32b": strat_slash32b,
    "slash32c": strat_slash32c,
}


# --- rescan tiers ---------------------------------------------------------
def rescan_targets(rows, tier):
    """Due servers for one tier -> [(ip, port), ...].

    Servers keep their own exact address and port.  The caller groups them
    by port before sweeping, so one masscan run checks each due endpoint.
    """
    now = _now()
    every = tier["every"]
    max_age = tier["max_age"]
    picked = []
    for row in rows:
        try:
            last = float(row.get("last_seen") or 0)
        except Exception:
            continue
        if not last:
            continue
        ago = now - last
        if ago <= every or ago > max_age:
            continue
        if tier.get("require_players"):
            try:
                if int(row.get("players_online") or 0) < 1:
                    continue
            except Exception:
                continue
        picked.append(row)

    picked.sort(key=lambda r: float(r.get("last_seen") or 0))
    if tier.get("sort") == "random":
        random.shuffle(picked)
    limit = tier.get("limit")
    if limit:
        picked = picked[:int(limit)]

    targets = []
    for row in picked:
        ip_port = str(row.get("ip_port", ""))
        ip = _host_of(ip_port)
        if ip:
            targets.append((ip, _port_of(ip_port)))
    return targets


# --- live round status ----------------------------------------------------
class LiveStatus:
    """One-line status pinned under the round output.

    On a terminal the line is rewritten in place (cursor up, clear, draw)
    so the screen doesn't scroll while a round runs. When stdout is piped
    it degrades to a plain summary line every few seconds, which keeps
    redirected logs readable. ``note()`` prints a message without losing
    the bar.
    """

    def __init__(self, stream=None):
        self.stream = stream or sys.stdout
        try:
            self.tty = bool(self.stream.isatty())
        except Exception:
            self.tty = False
        self.active = False
        self.label = ""
        self.stats = {"new": 0, "updated": 0, "revived": 0, "total": 0}
        self.started = 0.0
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = None
        self._drawn = False
        self._last_log = 0.0

    # -- rendering --
    def _line(self):
        s = self.stats
        elapsed = max(0.0, time.time() - self.started)
        return (f"[{self.label}] new {s['new']} | updated {s['updated']}"
                f" | {s['total']} hit(s) | {int(elapsed) // 60:02d}:"
                f"{int(elapsed) % 60:02d}")

    def _draw_locked(self):
        line = self._line()
        if self._drawn:
            self.stream.write("\x1b[1A\r\x1b[2K")
        self.stream.write(line + "\n")
        self.stream.flush()
        self._drawn = True

    def _erase_locked(self):
        if self._drawn:
            self.stream.write("\x1b[1A\r\x1b[2K")
            self.stream.flush()
            self._drawn = False

    # -- lifecycle --
    def start(self, label):
        with self._lock:
            self.label = label
            self.stats = {"new": 0, "updated": 0, "revived": 0, "total": 0}
            self.started = time.time()
            self.active = True
            self._last_log = time.time()
            if self.tty:
                self._draw_locked()
        # On a terminal the ticker keeps the elapsed clock moving even when
        # hits are sparse (hit() still redraws immediately).  When output is
        # piped it degrades to a periodic summary line.
        self._thread = threading.Thread(target=self._ticker, daemon=True)
        self._thread.start()

    def _ticker(self):
        interval = 1.0 if self.tty else STATUS_INTERVAL
        while not self._stop.wait(interval):
            with self._lock:
                if not self.active:
                    return
                if self.tty:
                    self._draw_locked()
                    continue
                now = time.time()
                if now - self._last_log >= STATUS_LOG_INTERVAL:
                    self._last_log = now
                    self.stream.write(self._line() + "\n")
                    self.stream.flush()

    def note(self, message):
        """Print a message without losing the bar."""
        with self._lock:
            if self.tty and self.active and self._drawn:
                self._erase_locked()
                self.stream.write(str(message) + "\n")
                self._draw_locked()
            else:
                self.stream.write(str(message) + "\n")
                self.stream.flush()

    def hit(self, kind):
        """kind: 'new' | 'updated' | 'revived' -- revived counts as updated."""
        with self._lock:
            if not self.active:
                return
            if kind == "new":
                self.stats["new"] += 1
            else:
                self.stats["updated"] += 1
            self.stats["total"] += 1
            if self.tty:
                self._draw_locked()

    def stop(self):
        with self._lock:
            self.active = False
            self._erase_locked()
        self._stop.set()
        if self._thread is not None:
            try:
                self._thread.join(timeout=1.0)
            except Exception:
                pass
            self._thread = None


# --- strategy picker (persisted scores) -----------------------------------
class StrategyPicker:
    def __init__(self, path, enabled=None):
        self.path = path
        self.enabled = [n for n in (enabled or STRATEGY_NAMES)
                        if n in STRATEGIES]
        if not self.enabled:
            self.enabled = list(STRATEGY_NAMES)
        self.scores = {}
        self._load()

    def _load(self):
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                for name, score in data.items():
                    if name in STRATEGIES:
                        try:
                            self.scores[name] = int(score)
                        except Exception:
                            continue
        except Exception:
            pass
        for name in self.enabled:
            self.scores.setdefault(name, DEFAULT_FOUND)

    def _save(self):
        try:
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump({k: self.scores[k] for k in sorted(self.scores)},
                          f, indent=2)
            os.replace(tmp, self.path)
        except Exception as exc:
            print(f"warning: could not write {self.path}: {exc}")

    def pick(self):
        untried = all(self.scores.get(n, DEFAULT_FOUND) in (0, DEFAULT_FOUND)
                      for n in self.enabled)
        # Bootstrap: everything ties, and slash0 finds the first servers.
        if untried and "slash0" in self.enabled:
            return "slash0"
        if random.random() < RANDOM_EXPLORE:
            return random.choice(self.enabled)
        # Best score wins, but break ties randomly: several machines with
        # the same history would otherwise pick the same strategy forever.
        best = max(self.scores.get(n, 0) for n in self.enabled)
        top = [n for n in self.enabled if self.scores.get(n, 0) == best]
        return random.choice(top)

    def update(self, name, score):
        self.scores[name] = int(score)
        self._save()


# --- running a round ------------------------------------------------------
def _carve(ranges):
    """Apply exclude.conf (and its bogon handling) to explicit specs."""
    out = []
    for spec in ranges or []:
        try:
            out.extend(scanner.subtract_excludes_from_spec(spec))
        except Exception:
            out.append(spec)
    return list(dict.fromkeys(s for s in out if s))


def _estimate_probes(ranges, ports):
    try:
        hosts = sum(scanner._masscan_count_hosts(r, cap=None)
                    for r in ranges)
    except Exception:
        hosts = 0
    return hosts * max(1, len(ports))


def _sudo_retryable():
    try:
        return scanner.sudo_noninteractive_ok()
    except Exception:
        return False


def run_round(ranges, ports, *, rate, wait, scan_duration, stop_event,
              backend="auto", on_hit=None, allow_sudo=True, log=None,
              shard=None, seed=None):
    """Run one time-boxed sweep. Returns result dicts.

    Uses masscan when available (explicit ranges/ports), else the Python
    handshake pool for rounds small enough to finish. ``log`` routes
    messages through the live status bar when one is active.
    """
    _log = log or print
    ranges = _carve(ranges)
    if not ranges:
        return []
    est = _estimate_probes(ranges, ports)
    use_masscan = (backend in ("auto", "masscan")
                   and scanner.is_masscan_available())
    if not use_masscan:
        if backend == "masscan":
            raise FileNotFoundError("masscan binary not found")
        if est > PY_MAX_PROBES:
            _log(f"  skipping: ~{est:,} probes is too much for the Python "
                 f"backend (install masscan or use --backend masscan)")
            return []

    results = []
    lock = threading.Lock()

    def emit(result):
        if not result:
            return
        with lock:
            results.append(result)
        if on_hit:
            try:
                on_hit(result)
            except Exception:
                pass

    if use_masscan:
        _log(f"  masscan: ~{est:,} probe(s) across {len(ranges):,} "
             f"target spec(s)")
        pool = scanner.ThreadPoolExecutor(max_workers=scanner.STATUS_WORKERS)
        sweep_deadline = time.monotonic() + max(1, scan_duration)
        futures = set()
        futures_lock = threading.Lock()

        def handshake(ip_port):
            if scanner.shutdown_requested():
                return
            try:
                emit(scanner.ping_server(ip_port))
            except Exception:
                pass

        def on_open(ip_port):
            if (scanner.shutdown_requested() or stop_event.is_set()
                    or time.monotonic() > sweep_deadline):
                # Do not let a burst of late masscan hits grow a handshake
                # queue that outlives the round's time box.
                return
            future = pool.submit(handshake, ip_port)
            with futures_lock:
                futures.add(future)

        def sweep(use_sudo):
            scanner.run_masscan_streaming(
                ranges, ports, rate=rate, wait=wait, on_open=on_open,
                timeout=scan_duration, use_sudo=use_sudo,
                stop_event=stop_event, shard=shard, seed=seed)

        try:
            try:
                sweep(False)
            except PermissionError:
                if allow_sudo and _sudo_retryable():
                    _log("  masscan needs root; retrying with passwordless "
                         "sudo...")
                    sweep(True)
                else:
                    raise
        except scanner.ScanStopped:
            pass
        except TimeoutError:
            # Time box hit with nothing found: normal for slash0.
            pass
        finally:
            # Drain handshakes only until the round deadline.  A slash24a
            # sweep can produce a hit backlog many times larger than the
            # worker pool, and waiting for all of it is what made those
            # rounds last 20 minutes.  Work already running is allowed to
            # finish (bounded by the ping socket timeout); queued work is
            # cancelled instead of extending the round.
            stopped = scanner.shutdown_requested() or stop_event.is_set()
            remaining = 0 if stopped else sweep_deadline - time.monotonic()
            if remaining > 0:
                with futures_lock:
                    snapshot = list(futures)
                try:
                    concurrent.futures.wait(snapshot, timeout=remaining)
                except Exception:
                    pass
            with futures_lock:
                snapshot = list(futures)
            for future in snapshot:
                try:
                    future.cancel()
                except Exception:
                    pass
            try:
                pool.shutdown(wait=True, cancel_futures=True)
            except Exception:
                pass
        return results

    # Python backend: expand and handshake.
    host_cap = max(1, est // max(1, len(ports)) + 1)
    try:
        targets = scanner.expand_scan_targets(
            " ".join(ranges), ports,
            max_hosts=min(host_cap, PY_MAX_PROBES))
    except Exception as exc:
        _log(f"  target expansion failed: {exc}")
        return []
    if not targets:
        return []
    if shard:
        try:
            index, total = int(shard[0]) - 1, int(shard[1])
            if 0 <= index < total:
                targets = targets[index::total]
        except Exception:
            pass
    if not targets:
        return []

    def on_result(result, _line):
        emit(result)

    deadline = time.monotonic() + max(1, scan_duration)

    class _RoundDeadline:
        """Stop the Python pool at the round's time box too.

        masscan rounds are killed after scan_duration, but the Python
        backend used to run until every target finished, so a large rescan
        could keep the whole loop busy for many minutes.
        """

        def is_set(self):
            return (stop_event.is_set()
                    or scanner.shutdown_requested()
                    or time.monotonic() >= deadline)

    try:
        scanner.scan_servers_gui(targets, on_result=on_result,
                                 stop_event=_RoundDeadline())
    except scanner.ScanStopped:
        pass
    return results


def _classify_one(before, result, now=None):
    """Classify one result: 'new' | 'updated' | 'revived' | None.

    'revived' is an updated server that had been unseen for a week.
    """
    try:
        ip_port = result.get("ip", "")
    except Exception:
        return None
    if not ip_port:
        return None
    now = now or _now()
    seen = before.get(ip_port)
    if seen is None:
        return "new"
    if seen > 0 and now - seen > REVIVED_AFTER:
        return "revived"
    return "updated"


def _classify(before, results):
    """(new, new_on_25565, revived) versus the pre-round snapshot."""
    new = new_def = revived = 0
    for result in results:
        kind = _classify_one(before, result)
        if kind == "new":
            new += 1
            try:
                if _port_of(result.get("ip", "")) == 25565:
                    new_def += 1
            except Exception:
                pass
        elif kind == "revived":
            revived += 1
    return new, new_def, revived


def _sync_now(url, token):
    """One shared-DB sync; returns True on success. Never raises."""
    if not url or not token:
        return False
    try:
        # A continuous node only needs to publish its findings.  Pulling the
        # shared per-sighting/player history or other people's notes back
        # would add a large download to every sync for no benefit here.
        # Both cursors are left untouched, so a later full --sync can fetch
        # everything that was skipped.
        summary = scanner.netdb_sync_once(
            url, token, history_download=False, notes_download=False)
    except Exception as exc:
        print(f"  sync failed: {exc}")
        return False
    print(f"  synced: uploaded={summary.get('uploaded', 0)} "
          f"downloaded={summary.get('downloaded', 0)} "
          f"inserted={summary.get('inserted', 0)} "
          f"updated={summary.get('updated', 0)} "
          f"history_uploaded={summary.get('history_uploaded', 0)} "
          f"player_events_uploaded={summary.get('player_events_uploaded', 0)}")
    return True


def _valid_node_id(node):
    return bool(node) and len(node) <= 128 and re.fullmatch(
        r"[A-Za-z0-9._:-]+", node) is not None


def _node_id_path(state_path):
    return os.path.join(os.path.dirname(os.path.abspath(state_path)),
                        NODE_ID_FILE)


def load_node_id(state_path, provided=None):
    """Stable per-machine id for auto-sharding; persisted with mode 0600."""
    if provided:
        node = str(provided).strip()
        if not _valid_node_id(node):
            raise ValueError(
                "node id must be 1-128 characters of A-Z, a-z, 0-9, . _ : -")
        return node

    path = _node_id_path(state_path)
    try:
        with open(path, "r", encoding="utf-8") as f:
            node = f.read().strip()
        if _valid_node_id(node):
            return node
    except Exception:
        pass

    host = re.sub(r"[^A-Za-z0-9._-]+", "-", socket.gethostname()).strip("-")
    node = f"{host[:48] or 'scanner'}-{secrets.token_hex(8)}"
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        try:
            with open(path, "r", encoding="utf-8") as f:
                existing = f.read().strip()
            if _valid_node_id(existing):
                return existing
        except Exception:
            pass
        # Corrupt/empty id file: replace it with this generated id.
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(node + "\n")
            os.chmod(path, 0o600)
        except Exception:
            pass
        return node
    except Exception as exc:
        print(f"warning: could not save node id to {path}: {exc}")
        return node
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(node + "\n")
    except Exception:
        pass
    return node


class ShardManager:
    """Heartbeat the shared DB and keep this node's auto-shard current.

    The DB server assigns 1-based indices for all currently registered
    continuous nodes. The heartbeat runs in its own thread so a long scan
    round does not let this node expire. A clean stop sends a leave request,
    so other nodes can take over this slice immediately instead of waiting
    for the TTL.
    """

    def __init__(self, url, token, node_id, stop_event, *,
                 interval=SHARD_HEARTBEAT):
        self.url = url
        self.token = token
        self.node_id = node_id
        self.interval = max(2.0, float(interval))
        self.stop_event = stop_event
        self._shard = None
        self._reported_total = None
        self._last_error = None
        self._messages = []
        self._lock = threading.Lock()
        self._local_stop = threading.Event()
        self._ready = threading.Event()
        self._thread = None

    def start(self):
        # Do the first heartbeat in the worker thread and wait only briefly.
        # A stuck DNS/socket lookup must not hang scanner startup.
        self._thread = threading.Thread(
            target=self._run, name="mcscan-shard-heartbeat", daemon=True)
        self._thread.start()
        self._ready.wait(timeout=5.0)

    def refresh(self, leave=False):
        # One retry for a transient timeout. The status bar log is deferred to
        # the end of the round, so a slow DB server does not spam the console.
        attempts = 1 if leave else 2
        data = None
        for attempt in range(attempts):
            try:
                data = scanner.netdb_continuous_heartbeat(
                    self.url, self.token, self.node_id,
                    timeout=2 if leave else SHARD_TIMEOUT, leave=leave)
                break
            except Exception as exc:
                text = str(exc)
                transient = ("timed out" in text.lower()
                             or "timeout" in text.lower())
                if attempt + 1 < attempts and transient:
                    time.sleep(0.5)
                    continue
                if not leave and text != self._last_error:
                    if transient:
                        text = "timed out; will retry next heartbeat"
                    with self._lock:
                        self._messages.append(
                            f"auto-shard heartbeat failed: {text}")
                    self._last_error = text
                return
        if leave or data is None:
            return
        try:
            index = int(data.get("index") or 0)
            total = int(data.get("total") or 0)
        except Exception:
            index = total = 0
        if not (1 <= index <= total):
            text = "invalid shard response from DB server"
            if text != self._last_error:
                with self._lock:
                    self._messages.append(f"auto-shard heartbeat failed: {text}")
            self._last_error = text
            return
        self._last_error = None
        with self._lock:
            self._shard = (index, total)

    def _run(self):
        self.refresh()
        self._ready.set()
        while not self._local_stop.wait(self.interval):
            if self.stop_event.is_set():
                break
            self.refresh()

    def shard(self):
        with self._lock:
            return self._shard

    def drain_messages(self):
        """Round-start output: errors plus one line if the peer count changed.

        Heartbeats may see a peer expire and re-register within a long round.
        Only the final total is reported, and only when it differs from the
        last reported total, so transient membership flaps do not produce a
        misleading 0-peer line after every round. Printing at the start of
        the next round makes the first peer count visible immediately when a
        node starts instead of after its first (possibly long) scan.
        """
        with self._lock:
            messages = list(self._messages)
            self._messages = []
            if self._shard is not None:
                index, total = self._shard
                if self._reported_total != total:
                    self._reported_total = total
                    messages.append(
                        f"auto-shard: {index}/{total} "
                        f"({max(0, total - 1)} peer(s))")
            return messages

    def stop(self):
        # Never let a stuck network call hold up shutdown. Stop the heartbeat
        # thread, then send the leave request from a short-lived daemon thread
        # (best effort; the server's TTL is the fallback).
        self._local_stop.set()
        if self._thread:
            self._thread.join(timeout=1.0)
            if self._thread.is_alive():
                # Stuck in DNS/socket: let the server TTL expire this node
                # rather than blocking exit or racing a late heartbeat.
                return
        threading.Thread(
            target=self.refresh, kwargs={"leave": True}, daemon=True
        ).start()


def run_continuous(*, rate, wait, scan_duration=DEFAULT_SCAN_DURATION,
                   sync_every=DEFAULT_SYNC_EVERY, state_path="strategies.json",
                   backend="auto", strategies=None, do_rescan=True,
                   rescan_every=DEFAULT_RESCAN_EVERY,
                   stop_event=None, max_rounds=None, shard=None, seed=None,
                   base_ports=None, auto_shard=False, node_id=None):
    """The forever loop. Returns a process exit code."""
    base_ports = _base_ports(base_ports)
    try:
        rescan_every = max(1, int(rescan_every))
    except Exception:
        rescan_every = DEFAULT_RESCAN_EVERY
    if backend == "minescan":
        print("error: continuous mode supports --backend auto, masscan or "
              "python (minescan is for one-off --scan).")
        return 1
    stop_event = stop_event or threading.Event()
    url, token = "", ""
    try:
        cfg = scanner.netdb_load_config()
        url = (cfg.get("url", "") or "").strip()
        token = (cfg.get("token", "") or "").strip()
    except Exception:
        pass

    shard_state = {"value": shard}
    shard_manager = None
    if auto_shard and shard is None:
        if url and token:
            try:
                shard_node = load_node_id(state_path, node_id)
            except Exception as exc:
                print(f"error: {exc}")
                return 2
            shard_manager = ShardManager(
                url, token, shard_node, stop_event)
        else:
            print("auto-shard: no shared-DB URL/token; sharding disabled")

    picker = StrategyPicker(state_path, strategies)
    shard_note = (f" shard={shard[0]}/{shard[1]}"
                  f" seed={seed if seed is not None else scanner.DEFAULT_SHARD_SEED}"
                  if shard else (" shard=auto" if shard_manager else ""))
    ports_note = ("" if base_ports == [25565]
                  else f" ports={','.join(str(p) for p in base_ports)}")
    rescan_note = (f"every {rescan_every} round(s)" if do_rescan else "off")
    print(f"continuous mode: strategies={','.join(picker.enabled)} "
          f"rescan={rescan_note} scan_duration={scan_duration}s "
          f"rate={rate}pps wait={wait}s backend={backend}"
          f"{ports_note}{shard_note}")
    print(f"shared-DB sync every {sync_every}s "
          f"({'enabled' if url and token else 'skipped: no netdb.json'})")
    if shard_manager:
        shard_manager.start()
        shard_state["value"] = shard_manager.shard()

    rounds = 0
    last_sync = 0.0
    # Auto degrades to Python after a privilege/binary failure so a daemon
    # never dies just because it isn't running as root.
    state = {"backend": backend}

    def do_round(ranges, ports, duration=None, on_hit=None, log=None,
                 backend=None):
        """run_round with daemon-grade error handling.

        Returns (results, fatal). A fatal error (masscan explicitly
        requested but missing/unprivileged) stops continuous mode;
        everything else is logged and the loop keeps going. In auto mode a
        masscan failure retries the round with the Python backend.  A
        per-round ``backend`` override is used for tiny rescan groups,
        where one masscan process costs more than the handshakes.
        """
        _log = log or print
        if shard_manager:
            shard_state["value"] = shard_manager.shard()
        for attempt in range(2):
            current = backend or state["backend"]
            try:
                return (run_round(
                    ranges, ports, rate=rate, wait=wait,
                    scan_duration=duration or scan_duration,
                    stop_event=stop_event, backend=current,
                    on_hit=on_hit, log=_log, shard=shard_state["value"],
                    seed=seed), False)
            except (PermissionError, FileNotFoundError) as exc:
                if current == "masscan":
                    _log(f"  error: masscan unavailable: {exc}")
                    _log("  run as root (or with passwordless sudo), "
                         "or use --backend python")
                    return ([], True)
                if attempt == 0:
                    _log(f"  masscan unavailable ({exc}); "
                         "using the Python backend from here on")
                    state["backend"] = "python"
                    continue
                _log(f"  round failed: {exc}")
                return ([], False)
            except Exception as exc:
                _log(f"  round failed: {exc}")
                return ([], False)
        return ([], False)

    try:
        while not stop_event.is_set():
            if shard_manager:
                shard_state["value"] = shard_manager.shard()
            rounds += 1
            body = ("rescan" if do_rescan
                    and rounds % rescan_every == 0 else "normal")
            print(f"\n=== round {rounds} ({body}) {time.strftime('%H:%M:%S')} ===")
            if shard_manager:
                for message in shard_manager.drain_messages():
                    print(f"  {message}", flush=True)
            before_rows = _known_rows()
            before = {}
            for row in before_rows:
                try:
                    before[row.get("ip_port", "")] = float(
                        row.get("last_seen") or 0)
                except Exception:
                    continue
            started = time.time()
            results = []
            name = None
            status = LiveStatus()
            counts = {"new": 0, "updated": 0, "revived": 0, "total": 0}
            count_lock = threading.Lock()

            def on_hit(result, _before=before):
                kind = _classify_one(_before, result)
                if kind is None:
                    return
                with count_lock:
                    counts[kind] += 1
                    counts["total"] += 1
                status.hit(kind)

            if body == "normal":
                name = picker.pick()
                label = f"round {rounds} {name}"
                print(f"strategy: {name}")
                try:
                    ranges, ports = STRATEGIES[name](before_rows, base_ports)
                except Exception as exc:
                    print(f"  strategy failed: {exc}")
                    ranges, ports = [], []
                if ranges:
                    carved_n = len(_carve(ranges))
                    dropped = len(ranges) - carved_n
                    note = (f", {dropped} removed by exclude.conf"
                            if dropped else "")
                    print(f"  {carved_n} target spec(s){note}, "
                          f"{len(ports)} port(s)")
                status.start(label)
                try:
                    results, fatal = do_round(ranges, ports, on_hit=on_hit,
                                              log=status.note)
                finally:
                    status.stop()
                if fatal:
                    _sync_now(url, token)
                    return 1
            else:
                targets = []
                seen_targets = set()
                for tier in RESCAN_TIERS:
                    try:
                        picked = rescan_targets(before_rows, tier)
                    except Exception as exc:
                        print(f"  {tier['name']} failed: {exc}")
                        continue
                    added = 0
                    for spec, port in picked:
                        key = (spec, port)
                        if key in seen_targets:
                            continue
                        seen_targets.add(key)
                        targets.append(key)
                        added += 1
                    if added:
                        print(f"  {tier['name']}: {added} due")
                if targets:
                    shard_total = 1
                    try:
                        if shard_state.get("value"):
                            shard_total = max(1, int(shard_state["value"][1]))
                    except Exception:
                        shard_total = 1
                    est_secs = (len(targets) / max(1, rate)
                                / shard_total)
                    print(f"  {len(targets)} unique due endpoint(s), "
                          f"~{est_secs:.0f}s at {rate}pps"
                          + (f" over {shard_total} shards"
                             if shard_total > 1 else ""))
                    if est_secs > scan_duration:
                        print(f"  note: this exceeds the {scan_duration}s "
                              f"round budget; raise --rate or "
                              f"--scan-duration, or rescans will be cut off")
                    # Keep per-target ports: group by port for the sweep.
                    by_port = {}
                    for spec, port in targets:
                        by_port.setdefault(port, []).append(spec)
                    status.start(f"round {rounds} rescan")
                    # This is one round, not one round per port.  Without a
                    # shared deadline a node with 40 known ports ran 40 x
                    # (scan_duration/2) = 6000s at the default settings.
                    rescan_deadline = (time.monotonic()
                                       + max(30, scan_duration))
                    processed_ports = 0
                    try:
                        # Largest groups first: port 25565 usually holds most
                        # of the servers, so it should get the shared budget
                        # before the long tail of tiny ports.
                        for port, specs in sorted(
                                by_port.items(), key=lambda kv: -len(kv[1])):
                            if stop_event.is_set():
                                break
                            remaining = rescan_deadline - time.monotonic()
                            if remaining <= 1:
                                break
                            # Use at most half the configured round for one
                            # port, but never go past the shared deadline.
                            duration = min(
                                max(30, scan_duration // 2), remaining)
                            direct = len(specs) <= RESCAN_PY_MAX
                            status.note(
                                f"  port {port}: {len(specs)} endpoint(s)"
                                + (" via python" if direct else ""))
                            group_started = time.monotonic()
                            batch, fatal = do_round(
                                specs, [port], duration=duration,
                                on_hit=on_hit, log=status.note,
                                backend="python" if direct else None)
                            status.note(
                                f"  port {port}: {len(batch)} result(s) in "
                                f"{time.monotonic() - group_started:.0f}s")
                            results.extend(batch)
                            processed_ports += 1
                            if fatal:
                                _sync_now(url, token)
                                return 1
                        skipped_ports = len(by_port) - processed_ports
                        if skipped_ports > 0 and not stop_event.is_set():
                            status.note(
                                f"  rescan time budget exhausted; skipped "
                                f"{skipped_ports} port group(s)")
                    finally:
                        status.stop()
                else:
                    print("  nothing due")

            elapsed = max(0.0, time.time() - started)
            new, new_def, revived = _classify(before, results)
            with count_lock:
                live_total = counts["total"]
                live_updated = counts["updated"]
            print(f"  {live_total} responded, {new} new "
                  f"({new_def} on 25565), {live_updated} updated, "
                  f"{revived} revived, {elapsed:.0f}s")
            if name:
                score = round((new + 5 * new_def + 0.1 * revived)
                              * 3600.0 / (elapsed + 30.0))
                print(f"  score for {name}: {score}")
                picker.update(name, score)

            now = _now()
            if (sync_every and not stop_event.is_set()
                    and (now - last_sync >= sync_every or last_sync == 0.0)):
                _sync_now(url, token)
                last_sync = now

            if max_rounds and rounds >= max_rounds:
                break
            if stop_event.is_set():
                break
            if SLEEP_SECS:
                print(f"  sleeping {SLEEP_SECS}s")
                # Wait in slices so Ctrl-C stays responsive.
                for _ in range(SLEEP_SECS * 10):
                    if stop_event.is_set():
                        break
                    time.sleep(0.1)
    except KeyboardInterrupt:
        print("\ninterrupted.")
        stop_event.set()
        try:
            scanner.request_shutdown()
        except Exception:
            pass
        print("skipping the final sync (run --sync when convenient); "
              "findings are already in the local DB.")
        return 130
    finally:
        if shard_manager:
            shard_manager.stop()
    if stop_event.is_set():
        # Ctrl+C / SIGTERM: a sync can take many seconds per request, so
        # don't make the user wait for it. Unsent rows stay dirty.
        print("\ncontinuous mode stopped. Skipping the final sync "
              "(run --sync when convenient); findings are already stored "
              "locally.")
        return 130
    print("\ncontinuous mode stopping; final sync...")
    _sync_now(url, token)
    return 0
