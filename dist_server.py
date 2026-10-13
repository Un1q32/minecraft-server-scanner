"""Distributed scan coordinator + shared result database (single service).

One TCP port, optionally TLS-wrapped, token-authenticated. Clients
(register from any network) are tracked with heartbeats; scan jobs created
by any client are split into chunks and leased to idle worker clients, so a
scan runs concurrently across many machines/networks. Found servers stream
back to the job owner live and are also upserted into a shared SQLite
database (WAL mode) that every client can push to and pull from.

Why this instead of a standalone DB (Postgres/MySQL)?
  * Single port-forward, no reverse proxy / domain / CA setup.
  * TLS with TOFU certificate pinning: encryption + server identity with
    zero CA infrastructure. Token auth on top, optional IP allowlist.
  * SQLite+WAL with batched single-writer upserts is far faster than this
    workload needs (thousands of results/sec) with zero DB administration.

Run:
    python dist_server.py --port 8443 --token <secret>   # first run prints
    python dist_server.py --no-tls --port 8484           # trusted-LAN testing

Files (created next to the server working directory):
    dist_server.db    shared result database (SQLite)
    dist_server.crt / dist_server.key   auto-generated self-signed TLS cert
    dist_token.txt    generated token (mode 0600) when --token is omitted
"""

import argparse
import ipaddress
import json
import os
import queue
import secrets
import socket
import sqlite3
import sys
import threading
import time
import uuid

from dist_common import (
    DEFAULT_CHUNK_SIZE,
    DEFAULT_PORT,
    DEFAULT_SPEC_HOSTS,
    MAX_CHUNKS_PER_JOB,
    MAX_SPEC_TARGETS,
    MAX_TARGETS_PER_JOB,
    NDJsonConnection,
    SPEC_UPLOAD_BATCH,
    UPLOAD_BATCH,
    cert_fingerprint,
    denormalize_result_from_wire,
    enumerate_spec_targets,
    generate_self_signed_cert,
    make_server_context,
    new_token,
    normalize_result_for_wire,
    piece_target_count,
    range_host_count,
    spec_excludes,
    spec_host_count,
    split_spec,
    split_targets,
)

PROTOCOL_VERSION = 1
LEASE_SECONDS = 300
HEARTBEAT_TIMEOUT = 90
SCHEDULER_TICK = 1.0
# MAX_TARGETS_PER_JOB comes from dist_common (shared with the client).
JOB_RESULT_BUFFER_CAP = 5000
DB_BATCH_SIZE = 500
LOADING_TIMEOUT = 900  # drop abandoned streamed uploads (begin without commit)


# ==================== database ====================

SCHEMA = """
CREATE TABLE IF NOT EXISTS servers (
    ip TEXT PRIMARY KEY,
    motd TEXT DEFAULT '',
    version TEXT DEFAULT '',
    players INTEGER DEFAULT 0,
    max_players INTEGER DEFAULT 0,
    cracked INTEGER DEFAULT 0,
    first_seen REAL DEFAULT 0,
    last_seen REAL DEFAULT 0,
    source TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_servers_last_seen ON servers(last_seen);
CREATE INDEX IF NOT EXISTS idx_servers_players ON servers(players);
"""


class Database:
    """Single-writer SQLite store (WAL). Writers enqueue batches; one thread
    applies them inside transactions for speed."""

    def __init__(self, path):
        self.path = path
        self._queue = queue.Queue()
        self._stop = threading.Event()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        try:
            self._conn.execute("PRAGMA journal_mode=WAL;")
            self._conn.execute("PRAGMA synchronous=NORMAL;")
        except Exception:
            pass
        self._conn.executescript(SCHEMA)
        self._conn.commit()
        self._thread = threading.Thread(target=self._writer, daemon=True)
        self._thread.start()

    def _writer(self):
        while not self._stop.is_set():
            try:
                batch = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue
            if batch is None:
                break
            if not batch:
                continue
            try:
                now_rows = []
                for row in batch:
                    seen = float(row.get("seen", time.time()) or time.time())
                    now_rows.append((
                        row.get("ip", ""),
                        row.get("motd", "") or "",
                        row.get("version", "") or "",
                        int(row.get("players", 0) or 0),
                        int(row.get("max_players", 0) or 0),
                        1 if row.get("cracked") else 0,
                        seen,
                        seen,
                        row.get("source", "") or "",
                    ))
                now_rows = [r for r in now_rows if r[0]]
                if not now_rows:
                    continue
                cur = self._conn.cursor()
                cur.executemany(
                    """INSERT INTO servers
                       (ip, motd, version, players, max_players, cracked,
                        first_seen, last_seen, source)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                       ON CONFLICT(ip) DO UPDATE SET
                         motd=excluded.motd, version=excluded.version,
                         players=excluded.players, max_players=excluded.max_players,
                         cracked=excluded.cracked, last_seen=excluded.last_seen,
                         source=excluded.source""",
                    now_rows,
                )
                self._conn.commit()
            except Exception as exc:
                print(f"[db writer] batch failed: {exc}", flush=True)
                try:
                    self._conn.rollback()
                except Exception:
                    pass

    def submit(self, rows):
        if rows:
            self._queue.put(list(rows))

    def query_since(self, since, limit=5000):
        try:
            limit = max(1, min(int(limit or 5000), 20000))
        except Exception:
            limit = 5000
        cur = self._conn.cursor()
        cur.execute(
            """SELECT ip, motd, version, players, max_players, cracked,
                      first_seen, last_seen, source
               FROM servers WHERE last_seen >= ? ORDER BY last_seen DESC LIMIT ?""",
            (float(since or 0), limit),
        )
        out = []
        for r in cur.fetchall():
            out.append({
                "ip": r[0], "motd": r[1], "version": r[2],
                "players": r[3], "max_players": r[4],
                "cracked": bool(r[5]), "first_seen": r[6],
                "last_seen": r[7], "source": r[8],
            })
        return out

    def stats(self):
        cur = self._conn.cursor()
        cur.execute("SELECT COUNT(*), COALESCE(SUM(players),0), COALESCE(SUM(max_players),0) FROM servers")
        n, online, maxp = cur.fetchone()
        return {"servers": n or 0, "players_online": online or 0,
                "slots_total": maxp or 0, "now": time.time()}

    def close(self):
        self._stop.set()
        try:
            self._queue.put(None)
        except Exception:
            pass
        try:
            self._conn.close()
        except Exception:
            pass


# ==================== jobs & clients ====================

class Chunk:
    __slots__ = ("chunk_id", "kind", "targets", "subnet", "range", "ports", "exclude",
                 "state", "worker", "lease_expires", "done_count")

    def __init__(self, chunk_id, kind="list", targets=None, subnet="", range="",
                 ports=None, exclude=None):
        self.chunk_id = chunk_id
        # "list" (explicit ip:port targets) | "spec" (subnet+ports) |
        # "range" (start-end+ports). One typed block is always exactly one
        # chunk and runs on exactly one worker — never subdivided.
        self.kind = kind
        self.targets = targets or []
        self.subnet = subnet or ""
        self.range = range or ""
        self.ports = list(ports or [])
        self.exclude = list(exclude or [])
        self.state = "pending"  # pending | leased | done
        self.worker = None
        self.lease_expires = 0.0
        self.done_count = 0

    def size(self):
        if self.kind == "spec":
            return piece_target_count(self.subnet, self.exclude, len(self.ports))
        if self.kind == "range":
            return range_host_count(self.range) * max(1, len(self.ports))
        return len(self.targets)


class Job:
    def __init__(self, job_id, owner_id, total, options):
        self.job_id = job_id
        self.owner_id = owner_id
        self.total = total
        self.done = 0
        self.status = "active"  # active | loading | done | canceled
        self.options = options or {}
        self.chunks = []
        self.created = time.time()
        self.seq = 0
        self.buffer = []  # [(seq, result)] capped, for catch-up pulls
        # Staging area for streamed uploads (job_begin/job_add/job_commit).
        self.target_list = []
        self.seen = set()
        # Prefix specs: [{"subnet": "10.0.0.0/12", "ports": [25565]}].
        self.spec_list = []

    def progress(self):
        return {"job_id": self.job_id, "total": self.total, "done": self.done,
                "status": self.status, "chunks": len(self.chunks)}


class Client:
    def __init__(self, client_id, name, network, conn, addr, worker, slots):
        self.client_id = client_id
        self.name = name
        self.network = network
        self.conn = conn
        self.addr = addr
        self.worker = bool(worker)
        self.slots = max(1, int(slots or 1))
        self.busy = 0
        self.last_seen = time.time()
        self.lock = threading.Lock()

    def free_slots(self):
        with self.lock:
            if not self.worker:
                return 0
            return max(0, self.slots - self.busy)


class DistServer:
    def __init__(self, db, token, allowlist=None):
        self.db = db
        self.token = token
        self.allowlist = list(allowlist or [])
        self.lock = threading.Lock()
        self.clients = {}  # client_id -> Client
        self.jobs = {}     # job_id -> Job
        self._rr = 0
        self._stop = threading.Event()
        self._sched = threading.Thread(target=self._scheduler, daemon=True)
        self._sched.start()

    # ---------- helpers ----------

    def log(self, msg):
        print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)

    def _client_by_conn(self, conn):
        with self.lock:
            for c in self.clients.values():
                if c.conn is conn:
                    return c
        return None

    def _owner_conn(self, job):
        with self.lock:
            owner = self.clients.get(job.owner_id)
            return owner.conn if owner else None

    # ---------- main loops ----------

    def _scheduler(self):
        while not self._stop.is_set():
            try:
                self._reap_dead_clients()
                self._expire_leases()
                self._reap_stale_loading()
                self._assign_pending()
            except Exception as exc:
                self.log(f"scheduler error: {exc}")
            self._stop.wait(SCHEDULER_TICK)

    def _reap_dead_clients(self):
        now = time.time()
        dead = []
        with self.lock:
            for cid, c in self.clients.items():
                if now - c.last_seen > HEARTBEAT_TIMEOUT:
                    dead.append(cid)
        for cid in dead:
            self._drop_client(cid, "heartbeat timeout")

    def _drop_client(self, client_id, reason):
        with self.lock:
            client = self.clients.pop(client_id, None)
            jobs = list(self.jobs.values())
        if client is None:
            return
        self.log(f"client {client.name} ({client_id[:8]}) dropped: {reason}")
        try:
            client.conn.close()
        except Exception:
            pass
        # Requeue its leased chunks.
        with self.lock:
            for job in jobs:
                for ch in job.chunks:
                    if ch.state == "leased" and ch.worker == client_id:
                        ch.state = "pending"
                        ch.worker = None
                        ch.lease_expires = 0.0

    def _expire_leases(self):
        now = time.time()
        with self.lock:
            for job in self.jobs.values():
                if job.status != "active":
                    continue
                for ch in job.chunks:
                    if ch.state == "leased" and ch.lease_expires < now:
                        ch.state = "pending"
                        ch.worker = None
                        ch.lease_expires = 0.0

    def _reap_stale_loading(self):
        now = time.time()
        with self.lock:
            stale = [jid for jid, j in self.jobs.items()
                     if j.status == "loading" and now - j.created > LOADING_TIMEOUT]
            for jid in stale:
                del self.jobs[jid]
        for jid in stale:
            self.log(f"job {jid} dropped (upload never committed)")

    def _assign_pending(self):
        with self.lock:
            workers = [c for c in self.clients.values() if c.free_slots() > 0]
            active = [j for j in self.jobs.values() if j.status == "active"
                      and any(c.state == "pending" for c in j.chunks)]
            if not workers or not active:
                return
            # Round-robin across jobs so concurrent jobs share workers fairly.
            active.sort(key=lambda j: j.created)
            assignments = []  # (client, job, chunk)
            start = self._rr % max(1, len(active))
            ordered = active[start:] + active[:start]
            progressed = True
            no_capacity = False
            while progressed and not no_capacity:
                progressed = False
                for job in ordered:
                    chunk = next((c for c in job.chunks if c.state == "pending"), None)
                    if chunk is None:
                        continue
                    worker = next((w for w in workers if w.free_slots() > 0), None)
                    if worker is None:
                        # No free worker right now: stop collecting but STILL
                        # send the assignments already collected below.
                        no_capacity = True
                        break
                    chunk.state = "leased"
                    chunk.worker = worker.client_id
                    chunk.lease_expires = time.time() + LEASE_SECONDS
                    with worker.lock:
                        worker.busy += 1
                    assignments.append((worker, job, chunk))
                    progressed = True
                    self._rr += 1
        for worker, job, chunk in assignments:
            msg = {"type": "assign", "job_id": job.job_id,
                   "chunk_id": chunk.chunk_id, "kind": chunk.kind,
                   "targets": chunk.targets if chunk.kind == "list" else [],
                   "subnet": chunk.subnet, "range": chunk.range,
                   "ports": chunk.ports,
                   "exclude": chunk.exclude,
                   "options": {k: v for k, v in (job.options or {}).items()
                               if k != "ignore"}}
            try:
                worker.conn.send(msg)
            except Exception:
                with self.lock:
                    chunk.state = "pending"
                    chunk.worker = None
                    with worker.lock:
                        worker.busy = max(0, worker.busy - 1)

    # ---------- connection handling ----------

    def serve(self, listen_sock):
        while not self._stop.is_set():
            try:
                conn, addr = listen_sock.accept()
            except Exception:
                if self._stop.is_set():
                    break
                continue
            try:
                peer_ip = conn.getpeername()[0]
            except Exception:
                peer_ip = ""
            if not _check_allowlist(peer_ip, self.allowlist):
                self.log(f"rejected connection from {peer_ip or addr} (allowlist)")
                try:
                    conn.close()
                except Exception:
                    pass
                continue
            threading.Thread(target=self._handle_conn,
                             args=(conn, addr), daemon=True).start()

    def _handle_conn(self, raw_sock, addr):
        conn = NDJsonConnection(raw_sock)
        client = None
        try:
            raw_sock.settimeout(30.0)
            hello = conn.recv()
            client = self._handle_hello(conn, addr, hello)
            if client is None:
                return
            raw_sock.settimeout(None)
            while not self._stop.is_set():
                try:
                    msg = conn.recv()
                except (ConnectionError, FramingError):
                    break
                except socket.timeout:
                    continue
                try:
                    self._dispatch(client, msg)
                except Exception as exc:
                    self.log(f"dispatch error: {exc}")
        except Exception:
            pass
        finally:
            if client is not None:
                self._drop_client(client.client_id, "disconnect")
            else:
                try:
                    conn.close()
                except Exception:
                    pass

    def _handle_hello(self, conn, addr, hello):
        if not isinstance(hello, dict) or hello.get("type") != "hello":
            try:
                conn.send({"type": "welcome", "ok": False, "error": "expected hello"})
            except Exception:
                pass
            conn.close()
            return None
        if hello.get("version") != PROTOCOL_VERSION:
            try:
                conn.send({"type": "welcome", "ok": False,
                           "error": "protocol version mismatch"})
            except Exception:
                pass
            conn.close()
            return None
        token = str(hello.get("token") or "")
        if not secrets.compare_digest(token, self.token):
            try:
                conn.send({"type": "welcome", "ok": False, "error": "bad token"})
            except Exception:
                pass
            conn.close()
            return None
        client_id = str(hello.get("client_id") or uuid.uuid4().hex)
        name = str(hello.get("name") or f"client-{client_id[:6]}")[:64]
        network = str(hello.get("network") or "")[:64]
        worker = bool(hello.get("worker", True))
        try:
            slots = max(1, min(int(hello.get("slots", 2) or 2), 32))
        except Exception:
            slots = 2
        with self.lock:
            old = self.clients.pop(client_id, None)
            client = Client(client_id, name, network, conn, addr[0], worker, slots)
            self.clients[client_id] = client
        if old is not None:
            try:
                old.conn.close()
            except Exception:
                pass
        try:
            conn.send({"type": "welcome", "ok": True, "client_id": client_id,
                       "server_time": time.time()})
        except Exception:
            return None
        self.log(f"client {name} ({client_id[:8]}) from {addr[0]} "
                 f"worker={worker} slots={slots} net={network or '-'}")
        return client

    # ---------- requests ----------

    def _reply(self, conn, msg_id, ok, data=None, error=None):
        try:
            conn.send({"type": "result", "id": msg_id, "ok": bool(ok),
                       "data": data, "error": error})
        except Exception:
            pass

    def _dispatch(self, client, msg):
        if not isinstance(msg, dict):
            return
        mtype = msg.get("type")
        msg_id = msg.get("id")
        client.last_seen = time.time()

        if mtype == "heartbeat":
            try:
                client.worker = bool(msg.get("worker", client.worker))
                client.slots = max(1, min(int(msg.get("slots", client.slots)), 32))
                with client.lock:
                    client.busy = max(0, min(int(msg.get("busy", 0)), client.slots))
            except Exception:
                pass
            with self.lock:
                peers = [{
                    "client_id": c.client_id, "name": c.name, "network": c.network,
                    "worker": c.worker, "slots": c.slots, "busy": c.busy,
                    "last_seen": c.last_seen, "addr": c.addr,
                    "self": c.client_id == client.client_id,
                } for c in self.clients.values()]
                jobs = [j.progress() for j in self.jobs.values()
                        if j.status == "active"]
            self._reply(client.conn, msg_id, True, {"peers": peers, "jobs": jobs})
            return

        if mtype == "peers":
            with self.lock:
                peers = [{
                    "client_id": c.client_id, "name": c.name, "network": c.network,
                    "worker": c.worker, "slots": c.slots, "busy": c.busy,
                    "last_seen": c.last_seen, "addr": c.addr,
                    "self": c.client_id == client.client_id,
                } for c in self.clients.values()]
            self._reply(client.conn, msg_id, True, {"peers": peers})
            return

        if mtype == "jobs":
            with self.lock:
                jobs = []
                for j in self.jobs.values():
                    p = j.progress()
                    owner = self.clients.get(j.owner_id)
                    p["owner"] = owner.name if owner else j.owner_id[:8]
                    p["mine"] = j.owner_id == client.client_id
                    jobs.append(p)
            self._reply(client.conn, msg_id, True, {"jobs": jobs})
            return

        if mtype == "job_begin":
            # Start a streamed upload: client follows with job_add and/or
            # job_add_specs batches, then job_commit. Prefix specs keep even
            # /8-scale scans to kilobyte frames. chunk_size = hosts per
            # spec chunk (legacy list chunks stay fixed-size).
            options = msg.get("options") if isinstance(msg.get("options"), dict) else {}
            try:
                ignore = options.get("ignore")
                if isinstance(ignore, list) and len(ignore) > 200000:
                    options = dict(options)
                    options["ignore"] = ignore[:200000]
            except Exception:
                pass
            try:
                req_chunk = int(msg.get("chunk_size", DEFAULT_SPEC_HOSTS))
            except Exception:
                req_chunk = DEFAULT_SPEC_HOSTS
            job_id = uuid.uuid4().hex[:12]
            job = Job(job_id, client.client_id, 0, options)
            job.status = "loading"
            # Spec chunks: hosts per sub-prefix. Legacy list chunks keep the
            # classic fixed-size semantics.
            job.chunk_hosts = max(64, min(req_chunk, 65536))
            job.list_chunk = max(16, min(req_chunk, 5000))
            with self.lock:
                self.jobs[job_id] = job
            self._reply(client.conn, msg_id, True, {"job_id": job_id})
            return

        if mtype == "job_add":
            job = self.jobs.get(msg.get("job_id"))
            if job is None:
                self._reply(client.conn, msg_id, False, error="unknown job")
                return
            if job.owner_id != client.client_id:
                self._reply(client.conn, msg_id, False, error="not job owner")
                return
            if job.status != "loading":
                self._reply(client.conn, msg_id, False, error="job already committed")
                return
            targets = msg.get("targets")
            if not isinstance(targets, list):
                self._reply(client.conn, msg_id, False, error="bad payload")
                return
            added = 0
            with self.lock:
                for t in targets:
                    t = str(t or "").strip()
                    if not t or t in job.seen:
                        continue
                    if len(job.target_list) >= MAX_TARGETS_PER_JOB:
                        break
                    job.seen.add(t)
                    job.target_list.append(t)
                    added += 1
                job.total = len(job.target_list)
                total = job.total
            capped = total >= MAX_TARGETS_PER_JOB
            self._reply(client.conn, msg_id, True,
                        {"added": added, "total": total, "capped": capped})
            return

        if mtype == "job_add_specs":
            job = self.jobs.get(msg.get("job_id"))
            if job is None:
                self._reply(client.conn, msg_id, False, error="unknown job")
                return
            if job.owner_id != client.client_id:
                self._reply(client.conn, msg_id, False, error="not job owner")
                return
            if job.status != "loading":
                self._reply(client.conn, msg_id, False, error="job already committed")
                return
            specs = msg.get("specs")
            if not isinstance(specs, list):
                self._reply(client.conn, msg_id, False, error="bad payload")
                return
            added = 0
            with self.lock:
                for spec in specs[:SPEC_UPLOAD_BATCH * 2]:
                    if not isinstance(spec, dict):
                        continue
                    try:
                        ports = sorted({int(p) for p in (spec.get("ports") or [])
                                        if 1 <= int(p) <= 65535})
                    except Exception:
                        continue
                    if not ports or len(ports) > 64:
                        continue
                    import ipaddress as _ip
                    entry = None
                    if spec.get("subnet"):
                        subnet = str(spec.get("subnet") or "").strip()
                        try:
                            net = _ip.ip_network(subnet, strict=False)
                            if net.version != 4:
                                continue
                            subnet = str(net)
                        except Exception:
                            continue
                        key = ("s", subnet, tuple(ports))
                        if key in job.seen:
                            continue
                        job.seen.add(key)
                        entry = {"subnet": subnet, "ports": ports}
                    elif spec.get("range"):
                        rng = str(spec.get("range") or "").strip()
                        try:
                            left, right = rng.split("-", 1)
                            start = _ip.ip_address(left.strip())
                            end = _ip.ip_address(right.strip())
                            if start.version != 4 or end.version != 4 \
                                    or int(end) < int(start):
                                continue
                            rng = f"{start}-{end}"
                        except Exception:
                            continue
                        key = ("r", rng, tuple(ports))
                        if key in job.seen:
                            continue
                        job.seen.add(key)
                        entry = {"range": rng, "ports": ports}
                    else:
                        continue
                    job.spec_list.append(entry)
                    added += 1
                nspecs = len(job.spec_list)
            self._reply(client.conn, msg_id, True,
                        {"added": added, "specs": nspecs})
            return

        if mtype == "job_commit":
            job = self.jobs.get(msg.get("job_id"))
            if job is None:
                self._reply(client.conn, msg_id, False, error="unknown job")
                return
            if job.owner_id != client.client_id:
                self._reply(client.conn, msg_id, False, error="not job owner")
                return
            with self.lock:
                if job.status != "loading":
                    self._reply(client.conn, msg_id, False, error="job already committed")
                    return
                # One typed block = exactly one chunk on exactly one worker.
                # Blocks are never subdivided; the worker enumerates its block
                # locally in bounded batches.
                list_chunks = split_targets(
                    job.target_list, getattr(job, "list_chunk", DEFAULT_CHUNK_SIZE))
                blocks = list(job.spec_list)
                if len(list_chunks) + len(blocks) > MAX_CHUNKS_PER_JOB:
                    self._reply(client.conn, msg_id, False, error=(
                        f"too many blocks ({len(list_chunks) + len(blocks)} > "
                        f"{MAX_CHUNKS_PER_JOB}); use bigger CIDRs, not pasted lists"))
                    try:
                        del self.jobs[job.job_id]
                    except KeyError:
                        pass
                    return
                spec_total = 0
                for spec in blocks:
                    if "subnet" in spec:
                        spec_total += piece_target_count(
                            spec["subnet"], spec_excludes(spec["subnet"]),
                            len(spec["ports"]))
                    else:
                        spec_total += (range_host_count(spec.get("range", ""))
                                       * max(1, len(spec["ports"])))
                    if spec_total > MAX_SPEC_TARGETS:
                        break
                if spec_total > MAX_SPEC_TARGETS:
                    self._reply(client.conn, msg_id, False, error=(
                        f"scan too big (>{MAX_SPEC_TARGETS} host:ports); "
                        f"narrow the range"))
                    try:
                        del self.jobs[job.job_id]
                    except KeyError:
                        pass
                    return
                job.target_list = []
                job.spec_list = []
                job.seen = set()
                if not list_chunks and not blocks:
                    self._reply(client.conn, msg_id, False, error="no valid targets")
                    try:
                        del self.jobs[job.job_id]
                    except KeyError:
                        pass
                    return
                idx = 0
                for c in list_chunks:
                    job.chunks.append(Chunk(f"{job.job_id}:{idx}", kind="list",
                                            targets=c))
                    idx += 1
                for spec in blocks:
                    if "subnet" in spec:
                        job.chunks.append(Chunk(
                            f"{job.job_id}:{idx}", kind="spec",
                            subnet=spec["subnet"], ports=spec["ports"],
                            exclude=spec_excludes(spec["subnet"])))
                    else:
                        job.chunks.append(Chunk(
                            f"{job.job_id}:{idx}", kind="range",
                            range=spec["range"], ports=spec["ports"]))
                    idx += 1
                job.total = (sum(len(c) for c in list_chunks) + spec_total)
                job.status = "active"
            self.log(f"job {job.job_id} from {client.name}: {job.total} targets, "
                     f"{len(job.chunks)} chunks (1 block = 1 chunk)")
            self._reply(client.conn, msg_id, True,
                        {"job_id": job.job_id, "total": job.total,
                         "chunks": len(job.chunks)})
            return

        if mtype == "job_ignorelist":
            # Workers fetch the owner's ignore set once per job instead of
            # receiving it inside every chunk assign.
            job = self.jobs.get(msg.get("job_id"))
            if job is None:
                self._reply(client.conn, msg_id, False, error="unknown job")
                return
            ignore = []
            try:
                ignore = list((job.options or {}).get("ignore") or [])
            except Exception:
                pass
            self._reply(client.conn, msg_id, True, {"ignore": ignore[:200000]})
            return

        if mtype == "job_create":
            targets = msg.get("targets") or []
            if not isinstance(targets, list) or not targets:
                self._reply(client.conn, msg_id, False, error="no targets")
                return
            if len(targets) > MAX_TARGETS_PER_JOB:
                self._reply(client.conn, msg_id, False,
                            error=f"too many targets (max {MAX_TARGETS_PER_JOB})")
                return
            options = msg.get("options") if isinstance(msg.get("options"), dict) else {}
            try:
                chunk_size = max(16, min(int(msg.get("chunk_size", DEFAULT_CHUNK_SIZE)), 5000))
            except Exception:
                chunk_size = DEFAULT_CHUNK_SIZE
            chunks = split_targets(targets, chunk_size)
            if not chunks:
                self._reply(client.conn, msg_id, False, error="no valid targets")
                return
            job_id = uuid.uuid4().hex[:12]
            job = Job(job_id, client.client_id, sum(len(c) for c in chunks), options)
            for i, c in enumerate(chunks):
                job.chunks.append(Chunk(f"{job_id}:{i}", kind="list", targets=c))
            with self.lock:
                self.jobs[job_id] = job
            self.log(f"job {job_id} from {client.name}: {job.total} targets, "
                     f"{len(chunks)} chunks")
            self._reply(client.conn, msg_id, True,
                        {"job_id": job_id, "total": job.total, "chunks": len(chunks)})
            return

        if mtype == "job_cancel":
            job = self.jobs.get(msg.get("job_id"))
            if job is None:
                self._reply(client.conn, msg_id, False, error="unknown job")
                return
            if job.owner_id != client.client_id:
                self._reply(client.conn, msg_id, False, error="not job owner")
                return
            with self.lock:
                job.status = "canceled"
                for ch in job.chunks:
                    if ch.state == "leased":
                        w = self.clients.get(ch.worker)
                        if w:
                            with w.lock:
                                w.busy = max(0, w.busy - 1)
                    ch.state = "done" if ch.state == "done" else "pending"
                    ch.worker = None
            self._reply(client.conn, msg_id, True, job.progress())
            return

        if mtype == "job_fetch":
            job = self.jobs.get(msg.get("job_id"))
            if job is None:
                self._reply(client.conn, msg_id, False, error="unknown job")
                return
            try:
                after = int(msg.get("after_seq", 0) or 0)
            except Exception:
                after = 0
            with self.lock:
                items = [(s, r) for (s, r) in job.buffer if s > after]
                prog = job.progress()
            self._reply(client.conn, msg_id, True,
                        {"results": items, "progress": prog, "seq": job.seq})
            return

        if mtype == "result_batch":
            self._handle_result_batch(client, msg, msg_id)
            return

        if mtype == "db_push":
            rows = msg.get("servers") or []
            if not isinstance(rows, list):
                self._reply(client.conn, msg_id, False, error="bad payload")
                return
            clean = []
            now = time.time()
            for r in rows[:5000]:
                if not isinstance(r, dict) or not r.get("ip"):
                    continue
                try:
                    clean.append({
                        "ip": str(r["ip"])[:64],
                        "motd": str(r.get("motd", ""))[:300],
                        "version": str(r.get("version", ""))[:64],
                        "players": int(r.get("players", 0) or 0),
                        "max_players": int(r.get("max_players", 0) or 0),
                        "cracked": bool(r.get("cracked", False)),
                        "seen": float(r.get("last_seen", now) or now),
                        "source": client.name[:64],
                    })
                except Exception:
                    continue
            self.db.submit(clean)
            self._reply(client.conn, msg_id, True, {"queued": len(clean)})
            return

        if mtype == "db_pull":
            try:
                since = float(msg.get("since", 0) or 0)
            except Exception:
                since = 0
            try:
                limit = int(msg.get("limit", 5000) or 5000)
            except Exception:
                limit = 5000
            try:
                rows = self.db.query_since(since, limit)
                self._reply(client.conn, msg_id, True, {"servers": rows})
            except Exception as exc:
                self._reply(client.conn, msg_id, False, error=str(exc))
            return

        if mtype == "db_stats":
            try:
                self._reply(client.conn, msg_id, True, self.db.stats())
            except Exception as exc:
                self._reply(client.conn, msg_id, False, error=str(exc))
            return

        self._reply(client.conn, msg_id, False, error=f"unknown type {mtype!r}")

    def _handle_result_batch(self, client, msg, msg_id):
        job_id = msg.get("job_id")
        chunk_id = msg.get("chunk_id")
        with self.lock:
            job = self.jobs.get(job_id)
        if job is None:
            self._reply(client.conn, msg_id, False, error="unknown job")
            return
        if job.status != "active":
            self._reply(client.conn, msg_id, True, {"ignored": True})
            return
        results = msg.get("results") or []
        try:
            done_targets = int(msg.get("done_targets", 0) or 0)
        except Exception:
            done_targets = 0
        if not isinstance(results, list):
            results = []
        # Normalize + attribute.
        now = time.time()
        clean_hits = []
        for r in results[:5000]:
            d = denormalize_result_from_wire(r) if isinstance(r, dict) else None
            if not d or not d.get("ip"):
                continue
            d["seen"] = now
            d["source"] = client.name[:64]
            clean_hits.append(d)
        owner_conn = self._owner_conn(job)
        with self.lock:
            chunk = next((c for c in job.chunks if c.chunk_id == chunk_id), None)
            if chunk is not None and chunk.state == "leased" and chunk.worker == client.client_id:
                # done_targets is incremental per batch; accumulate it.
                chunk.done_count += max(0, done_targets)
                if chunk.done_count >= chunk.size():
                    chunk.state = "done"
                    chunk.worker = None
                    with client.lock:
                        client.busy = max(0, client.busy - 1)
            job.done = min(job.total, job.done + done_targets)
            pushed = []
            for hit in clean_hits:
                job.seq += 1
                job.buffer.append((job.seq, normalize_result_for_wire(hit)))
                pushed.append((job.seq, hit))
            if len(job.buffer) > JOB_RESULT_BUFFER_CAP:
                del job.buffer[:len(job.buffer) - JOB_RESULT_BUFFER_CAP]
            if job.done >= job.total and all(c.state == "done" for c in job.chunks):
                job.status = "done"
            prog = job.progress()
        # Live-forward hits + progress to the owner (best effort).
        if owner_conn is not None:
            try:
                for seq, hit in pushed:
                    owner_conn.send({"type": "job_result", "job_id": job_id,
                                     "seq": seq, "result": normalize_result_for_wire(hit)})
                owner_conn.send({"type": "job_update", "job_id": job_id,
                                 "progress": prog})
            except Exception:
                pass
        if clean_hits:
            self.db.submit(clean_hits)
        self._reply(client.conn, msg_id, True, {"accepted": len(clean_hits), "progress": prog})

    def stop(self):
        self._stop.set()


# ==================== entry ====================

def _check_allowlist(addr, allowlist):
    if not allowlist:
        return True
    try:
        ip = ipaddress.ip_address(addr)
    except Exception:
        return False
    for net in allowlist:
        try:
            if ip in ipaddress.ip_network(net, strict=False):
                return True
        except Exception:
            continue
    return False


def main(argv=None):
    ap = argparse.ArgumentParser(description="Distributed scan coordinator + shared DB")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--db", default="dist_server.db")
    ap.add_argument("--token", default="",
                    help="shared secret (generated + saved if omitted)")
    ap.add_argument("--token-file", default="dist_token.txt")
    ap.add_argument("--cert", default="dist_server.crt")
    ap.add_argument("--key", default="dist_server.key")
    ap.add_argument("--no-tls", action="store_true",
                    help="plaintext mode (trusted LAN testing only)")
    ap.add_argument("--allow", action="append", default=[],
                    help="optional allowed client CIDR (repeatable)")
    args = ap.parse_args(argv)

    token = args.token.strip()
    if not token and os.path.exists(args.token_file):
        try:
            with open(args.token_file, "r", encoding="utf-8") as f:
                token = f.readline().strip()
        except Exception:
            token = ""
    if not token:
        token = new_token()
        try:
            with open(args.token_file, "w", encoding="utf-8") as f:
                f.write(token + "\n")
            os.chmod(args.token_file, 0o600)
        except Exception as exc:
            print(f"warning: could not save token file: {exc}")
        print(f"generated token (share with clients): {token}")

    ctx = None
    if not args.no_tls:
        if not (os.path.exists(args.cert) and os.path.exists(args.key)):
            print("generating self-signed TLS certificate...")
            try:
                generate_self_signed_cert(args.cert, args.key)
            except Exception as exc:
                print(f"TLS cert generation failed (need 'cryptography' pkg): {exc}")
                return 2
        try:
            print(f"server cert fingerprint: {cert_fingerprint(args.cert)}")
            print("(clients pin this on first connect)")
        except Exception:
            pass
        ctx = make_server_context(args.cert, args.key)

    db = Database(args.db)
    server = DistServer(db, token, allowlist=args.allow)

    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lsock.bind((args.host, args.port))
    lsock.listen(100)
    if ctx is not None:
        lsock = ctx.wrap_socket(lsock, server_side=True)
    mode = "plaintext" if args.no_tls else "TLS"
    print(f"dist server listening on {args.host}:{args.port} ({mode}), "
          f"db={args.db}, allowlist={args.allow or 'any'}")
    try:
        server.serve(lsock)
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()
        db.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
