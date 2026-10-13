"""Shared protocol helpers for distributed Minecraft-server scanning.

Wire format: newline-delimited JSON (NDJSON) frames over a single TCP
connection, optionally wrapped in TLS. One persistent connection per client
carries both directions:

  client -> server : {"type": ..., "id": <int>, ...}      (requests)
  server -> client : {"type": "result", "id": <int>, "ok": bool, ...}
  server -> client : {"type": <push>, ...}                (no "id")

Authentication: bearer token in the initial "hello" frame.
Server identity: TLS + TOFU certificate pinning (SHA-256 fingerprint stored
in the client config on first connect). No CA, no reverse proxy, no extra
setup: forward one TCP port and share the token + fingerprint.
"""

import base64
import hashlib
import json
import os
import socket
import ssl
import struct
import threading

PROTOCOL_VERSION = 1
DEFAULT_PORT = 8443
DEFAULT_CHUNK_SIZE = 256
MAX_FRAME_BYTES = 32 * 1024 * 1024
CONFIG_FILE = "dist_config.json"


# ---------------- framing ----------------

class FramingError(Exception):
    pass


class NDJsonConnection:
    """Newline-delimited JSON over a (TLS-optional) socket."""

    def __init__(self, sock):
        self.sock = sock
        self._send_lock = threading.Lock()
        self._buf = b""
        try:
            # Low-latency pushes for live scan results.
            self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except Exception:
            pass

    def send(self, obj):
        raw = (json.dumps(obj, separators=(",", ":")) + "\n").encode("utf-8")
        if len(raw) > MAX_FRAME_BYTES:
            raise FramingError("frame too large")
        with self._send_lock:
            self.sock.sendall(raw)

    def recv(self):
        """Next decoded object. Raises ConnectionError on EOF, FramingError
        on oversized/garbage frames."""
        while b"\n" not in self._buf:
            try:
                data = self.sock.recv(65536)
            except socket.timeout:
                raise
            if not data:
                raise ConnectionError("peer closed connection")
            self._buf += data
            if len(self._buf) > MAX_FRAME_BYTES + 1024:
                raise FramingError("frame too large")
        line, self._buf = self._buf.split(b"\n", 1)
        if not line.strip():
            return self.recv()
        try:
            return json.loads(line.decode("utf-8"))
        except Exception as exc:
            raise FramingError(f"bad frame: {exc}")

    def close(self):
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        try:
            self.sock.close()
        except Exception:
            pass


# ---------------- TLS ----------------

def generate_self_signed_cert(cert_path, key_path, hostname="mc-dist"):
    """Create a self-signed cert+key with the cryptography package."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    import datetime

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, hostname),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(hostname)]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    try:
        os.chmod(key_path, 0o600)
    except Exception:
        pass
    return cert_path, key_path


def cert_fingerprint(cert_path):
    """SHA-256 fingerprint (hex) of a PEM cert file."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization

    with open(cert_path, "rb") as f:
        data = f.read()
    cert = x509.load_pem_x509_certificate(data)
    return cert.fingerprint(hashes.SHA256()).hex()


def peer_cert_fingerprint(tls_sock):
    """SHA-256 fingerprint (hex) of the peer's DER cert on a live socket."""
    der = tls_sock.getpeercert(binary_form=True)
    return hashlib.sha256(der).hexdigest()


def make_server_context(cert_path, key_path):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
    return ctx


def make_client_context():
    # Self-signed server cert: we verify via TOFU pinning, not a CA.
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


# ---------------- chunking ----------------

def split_targets(targets, chunk_size=DEFAULT_CHUNK_SIZE):
    """Split an expanded ['ip:port', ...] list into dislocation-free chunks.

    Order is preserved so progress reporting stays monotonic. Duplicates are
    removed (first occurrence wins) to avoid double-scanning shared ranges.
    """
    try:
        chunk_size = max(1, int(chunk_size or DEFAULT_CHUNK_SIZE))
    except Exception:
        chunk_size = DEFAULT_CHUNK_SIZE
    seen = set()
    unique = []
    for t in targets or []:
        t = str(t or "").strip()
        if not t or t in seen:
            continue
        seen.add(t)
        unique.append(t)
    return [unique[i:i + chunk_size] for i in range(0, len(unique), chunk_size)] or []


# ---------------- config ----------------

DEFAULT_CONFIG = {
    "server_host": "127.0.0.1",
    "server_port": DEFAULT_PORT,
    "use_tls": True,
    "token": "",
    "client_name": "",
    "network_label": "",
    "server_fingerprint": "",
    "worker_enabled": True,
    "worker_slots": 2,
    "chunk_workers": 100,
    "chunk_size": DEFAULT_CHUNK_SIZE,
}


def load_config(path=CONFIG_FILE):
    cfg = dict(DEFAULT_CONFIG)
    try:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                for k, v in data.items():
                    if k in cfg:
                        cfg[k] = v
    except Exception:
        pass
    return cfg


def save_config(cfg, path=CONFIG_FILE):
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump({k: cfg.get(k) for k in DEFAULT_CONFIG}, f, indent=2)
    except Exception:
        pass


# ---------------- misc ----------------

def new_token(nbytes=24):
    return base64.urlsafe_b64encode(os.urandom(nbytes)).decode("ascii")


def normalize_result_for_wire(result):
    """Make a ping_server() dict JSON-safe (tuples -> lists)."""
    if not isinstance(result, dict):
        return None
    out = dict(result)
    sample = out.get("players_sample") or []
    norm = []
    for item in sample:
        try:
            if isinstance(item, (list, tuple)) and len(item) >= 2:
                norm.append([str(item[0] or ""), str(item[1] or "")])
            elif isinstance(item, dict):
                norm.append([str(item.get("id") or ""), str(item.get("name") or "")])
        except Exception:
            continue
    out["players_sample"] = norm
    return out


def denormalize_result_from_wire(result):
    """Restore wire dict to ping_server() shape (lists -> tuples)."""
    if not isinstance(result, dict):
        return None
    out = dict(result)
    sample = out.get("players_sample") or []
    norm = []
    for item in sample:
        try:
            if isinstance(item, (list, tuple)) and len(item) >= 2:
                norm.append((str(item[0] or ""), str(item[1] or "")))
            elif isinstance(item, dict):
                norm.append((str(item.get("id") or ""), str(item.get("name") or "")))
        except Exception:
            continue
    out["players_sample"] = norm
    return out
