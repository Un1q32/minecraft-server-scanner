"""Client agent for distributed scanning (Qt-free; safe for headless use).

DistAgent maintains one persistent (TLS-optional) connection to the control
server and multiplexes three roles over it:

  * owner      submit jobs, receive live results + progress pushes
  * worker     receive chunk assigns, handshake-scan them with ping_server,
               stream result batches back (concurrent chunk slots)
  * db client  push local finds / pull the shared database

All network callbacks fire on background threads; the Qt tab marshals them
to the GUI with after(). ping_fn is injected (scanner.ping_server) so this
module never imports scanner (no import cycle).
"""

import socket
import ssl
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

from dist_common import (
    DEFAULT_PORT,
    NDJsonConnection,
    denormalize_result_from_wire,
    load_config,
    make_client_context,
    normalize_result_for_wire,
    peer_cert_fingerprint,
    save_config,
)


class DistError(Exception):
    pass


class DistAgent:
    def __init__(self, ping_fn=None):
        self.ping_fn = ping_fn  # (ip_port) -> result dict | None
        self.cfg = load_config()
        self._conn = None
        self._reader = None
        self._hb_thread = None
        self._stop = threading.Event()
        self._req_lock = threading.Lock()
        self._next_id = 1
        self._pending = {}  # id -> [event, box]
        self._pending_lock = threading.Lock()
        self._assign_lock = threading.Lock()
        self._active_chunks = {}  # chunk_id -> True (slot accounting)
        self._worker_slots = 2
        self._worker_enabled = True
        self._chunk_workers = 100
        self.client_id = uuid.uuid4().hex
        # Callbacks (background threads): set by UI.
        self.on_status = None    # (connected: bool, message: str)
        self.on_peers = None     # (peers: list)
        self.on_jobs = None      # (jobs: list)
        self.on_job_result = None  # (job_id, seq, result: dict)
        self.on_job_update = None  # (job_id, progress: dict)
        self.on_assign_done = None  # (job_id, chunk_id, hits: int)
        self.connected = False

    # ---------- config ----------

    def get_config(self):
        return dict(self.cfg)

    def update_config(self, **kwargs):
        for k, v in kwargs.items():
            if k in self.cfg:
                self.cfg[k] = v
        save_config(self.cfg)

    # ---------- connection ----------

    def _emit_status(self, connected, message):
        self.connected = connected
        cb = self.on_status
        if cb:
            try:
                cb(connected, message)
            except Exception:
                pass

    def connect(self, timeout=15):
        self.disconnect()
        self._stop.clear()
        host = (self.cfg.get("server_host") or "127.0.0.1").strip()
        port = int(self.cfg.get("server_port") or DEFAULT_PORT)
        use_tls = bool(self.cfg.get("use_tls", True))
        token = self.cfg.get("token") or ""
        if not token:
            raise DistError("no token configured")
        raw = socket.create_connection((host, port), timeout=timeout)
        raw.settimeout(timeout)
        if use_tls:
            ctx = make_client_context()
            tls = ctx.wrap_socket(raw, server_hostname=host)
            fp = peer_cert_fingerprint(tls)
            known = (self.cfg.get("server_fingerprint") or "").strip().lower()
            if known and known != fp.lower():
                try:
                    tls.close()
                except Exception:
                    pass
                raise DistError(
                    "server certificate changed! Possible MITM. "
                    "If the server was reinstalled, clear the saved "
                    "fingerprint in dist_config.json.")
            if not known:
                self.cfg["server_fingerprint"] = fp.lower()
                save_config(self.cfg)
            sock = tls
        else:
            sock = raw
        conn = NDJsonConnection(sock)
        # hello
        conn.send({
            "type": "hello", "version": 1, "token": token,
            "client_id": self.client_id,
            "name": (self.cfg.get("client_name") or socket.gethostname())[:64],
            "network": (self.cfg.get("network_label") or "")[:64],
            "worker": bool(self.cfg.get("worker_enabled", True)),
            "slots": int(self.cfg.get("worker_slots", 2) or 2),
        })
        hello_reply = conn.recv()
        if not isinstance(hello_reply, dict) or not hello_reply.get("ok"):
            err = (hello_reply or {}).get("error", "rejected") if isinstance(hello_reply, dict) else "rejected"
            try:
                conn.close()
            except Exception:
                pass
            raise DistError(f"server rejected connection: {err}")
        self._worker_enabled = bool(self.cfg.get("worker_enabled", True))
        self._worker_slots = max(1, min(int(self.cfg.get("worker_slots", 2) or 2), 32))
        try:
            self._chunk_workers = max(1, min(int(self.cfg.get("chunk_workers", 100) or 100), 500))
        except Exception:
            self._chunk_workers = 100
        try:
            # The connect-time timeout was only for the handshake; the reader
            # thread needs a blocking socket or it dies on the first quiet
            # 15s window and the client goes silently deaf.
            sock.settimeout(None)
        except Exception:
            pass
        self._conn = conn
        self._pending = {}
        self._reader = threading.Thread(target=self._reader_loop, daemon=True)
        self._reader.start()
        self._hb_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
        self._hb_thread.start()
        self._emit_status(True, f"connected to {host}:{port} "
                                f"({'TLS' if use_tls else 'plaintext'})")
        return True

    def disconnect(self):
        self._stop.set()
        conn, self._conn = self._conn, None
        if conn:
            try:
                conn.close()
            except Exception:
                pass
        with self._pending_lock:
            for _id, (ev, box) in list(self._pending.items()):
                box["error"] = "disconnected"
                try:
                    ev.set()
                except Exception:
                    pass
            self._pending.clear()
        if self.connected:
            self._emit_status(False, "disconnected")

    def _reader_loop(self):
        conn = self._conn
        while not self._stop.is_set() and conn is not None:
            try:
                msg = conn.recv()
            except Exception:
                break
            try:
                self._route(msg)
            except Exception:
                pass
        if not self._stop.is_set():
            self._emit_status(False, "connection lost")
            # Auto-reconnect with backoff in background.
            threading.Thread(target=self._reconnect_loop, daemon=True).start()

    def _reconnect_loop(self):
        delay = 2
        while not self._stop.is_set() and not self.connected:
            time.sleep(delay)
            if self._stop.is_set() or self.connected:
                break
            try:
                self.connect()
                return
            except Exception:
                pass
            delay = min(60, delay * 2)

    def _route(self, msg):
        if not isinstance(msg, dict):
            return
        if msg.get("type") == "result" and "id" in msg:
            with self._pending_lock:
                slot = self._pending.pop(msg["id"], None)
            if slot:
                ev, box = slot
                box["ok"] = bool(msg.get("ok"))
                box["data"] = msg.get("data")
                box["error"] = msg.get("error")
                try:
                    ev.set()
                except Exception:
                    pass
            return
        mtype = msg.get("type")
        if mtype == "assign":
            threading.Thread(target=self._run_chunk, args=(msg,), daemon=True).start()
        elif mtype == "job_result":
            cb = self.on_job_result
            if cb:
                try:
                    cb(msg.get("job_id"), msg.get("seq"),
                       denormalize_result_from_wire(msg.get("result")))
                except Exception:
                    pass
        elif mtype == "job_update":
            cb = self.on_job_update
            if cb:
                try:
                    cb(msg.get("job_id"), msg.get("progress") or {})
                except Exception:
                    pass

    def _request(self, payload, timeout=30):
        conn = self._conn
        if conn is None:
            raise DistError("not connected")
        with self._req_lock:
            rid = self._next_id
            self._next_id += 1
        ev = threading.Event()
        box = {}
        with self._pending_lock:
            self._pending[rid] = (ev, box)
        payload = dict(payload)
        payload["id"] = rid
        try:
            conn.send(payload)
        except Exception as exc:
            with self._pending_lock:
                self._pending.pop(rid, None)
            raise DistError(f"send failed: {exc}")
        if not ev.wait(timeout):
            with self._pending_lock:
                self._pending.pop(rid, None)
            raise DistError("request timed out")
        if not box.get("ok"):
            raise DistError(str(box.get("error") or "server error"))
        return box.get("data")

    def _heartbeat_loop(self):
        while not self._stop.is_set():
            try:
                with self._assign_lock:
                    busy = len(self._active_chunks)
                data = self._request({
                    "type": "heartbeat",
                    "worker": self._worker_enabled,
                    "slots": self._worker_slots,
                    "busy": busy,
                }, timeout=20)
                if isinstance(data, dict):
                    if self.on_peers and "peers" in data:
                        try:
                            self.on_peers(data["peers"])
                        except Exception:
                            pass
                    if self.on_jobs and "jobs" in data:
                        try:
                            self.on_jobs(data["jobs"])
                        except Exception:
                            pass
            except Exception:
                pass
            for _ in range(15):
                if self._stop.is_set():
                    break
                time.sleep(1)

    # ---------- owner API ----------

    def submit_job(self, targets, options=None, chunk_size=None):
        data = self._request({
            "type": "job_create",
            "targets": list(targets or []),
            "options": options or {},
            "chunk_size": chunk_size or self.cfg.get("chunk_size", 256),
        }, timeout=60)
        return data  # {job_id, total, chunks}

    def cancel_job(self, job_id):
        return self._request({"type": "job_cancel", "job_id": job_id})

    def fetch_job_results(self, job_id, after_seq=0):
        return self._request({"type": "job_fetch", "job_id": job_id,
                              "after_seq": after_seq}, timeout=60)

    def list_peers(self):
        return self._request({"type": "peers"}, timeout=20).get("peers", [])

    def list_jobs(self):
        return self._request({"type": "jobs"}, timeout=20).get("jobs", [])

    # ---------- shared DB API ----------

    def db_push(self, servers):
        return self._request({"type": "db_push", "servers": servers}, timeout=60)

    def db_pull(self, since=0, limit=5000):
        return self._request({"type": "db_pull", "since": since,
                              "limit": limit}, timeout=60).get("servers", [])

    def db_stats(self):
        return self._request({"type": "db_stats"}, timeout=20)

    # ---------- worker ----------

    def set_worker(self, enabled, slots=None):
        self._worker_enabled = bool(enabled)
        if slots is not None:
            try:
                self._worker_slots = max(1, min(int(slots), 32))
            except Exception:
                pass
        self.update_config(worker_enabled=self._worker_enabled,
                           worker_slots=self._worker_slots)

    def _slot_acquire(self):
        with self._assign_lock:
            if len(self._active_chunks) >= self._worker_slots:
                return False
            return True

    def _run_chunk(self, msg):
        job_id = msg.get("job_id")
        chunk_id = msg.get("chunk_id")
        targets = msg.get("targets") or []
        if not self._worker_enabled or self.ping_fn is None:
            return
        if not self._slot_acquire():
            return  # over capacity; lease expires and server requeues
        with self._assign_lock:
            if chunk_id in self._active_chunks:
                return
            self._active_chunks[chunk_id] = True
        try:
            self._execute_chunk(job_id, chunk_id, targets)
        finally:
            with self._assign_lock:
                self._active_chunks.pop(chunk_id, None)
            cb = self.on_assign_done
            if cb:
                try:
                    cb(job_id, chunk_id, 0)
                except Exception:
                    pass

    def _execute_chunk(self, job_id, chunk_id, targets):
        ping = self.ping_fn
        workers = max(1, min(self._chunk_workers, max(1, len(targets))))
        hits = []
        done = 0
        lock = threading.Lock()
        last_flush = [time.time()]

        def flush(final=False):
            with lock:
                batch = hits[:]
                del hits[:]
                n_done = done
            if not batch and not final:
                return
            try:
                # done_targets is incremental per batch.
                with lock:
                    pass
                self._request({
                    "type": "result_batch", "job_id": job_id,
                    "chunk_id": chunk_id,
                    "results": [normalize_result_for_wire(r) for r in batch],
                    "done_targets": n_done - flush.sent,
                }, timeout=60)
                flush.sent = n_done
            except Exception:
                # Put hits back for a final retry; progress may double-count
                # on retry, server clamps done at total.
                with lock:
                    hits[:0] = batch
                if final:
                    pass
        flush.sent = 0

        def one(target):
            nonlocal done
            try:
                r = ping(target)
            except Exception:
                r = None
            with lock:
                done += 1
                if r:
                    hits.append(r)
                need_flush = len(hits) >= 50 or (time.time() - last_flush[0]) > 2.0
            if need_flush:
                last_flush[0] = time.time()
                flush()

        with ThreadPoolExecutor(max_workers=workers) as ex:
            list(ex.map(one, targets))
        flush(final=True)
