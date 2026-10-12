# === Minecraft Scanner by Cev-API ===

import shodan
import codecs
import socket
import struct
import json
import re
import os
import random
import time
import shutil
import subprocess
import ipaddress
import urllib.request
import urllib.error
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import init, Fore, Style
import nbtlib
from nbtlib import Compound, String, Byte

# Hide console window
if os.name == "nt": __import__("ctypes").windll.user32.ShowWindow(__import__("ctypes").windll.kernel32.GetConsoleWindow(), 0)

# Qt (PySide6) UI + threading
import threading
try:
    from PySide6.QtCore import Qt, QTimer, QThread
    from PySide6.QtGui import QIcon, QPixmap, QImage, QColor
    from PySide6.QtWidgets import (
        QApplication, QCheckBox, QComboBox, QDialog, QFileDialog, QGridLayout,
        QHBoxLayout, QHeaderView, QInputDialog, QLabel, QLineEdit, QMainWindow,
        QMessageBox, QPlainTextEdit, QPushButton, QRadioButton, QSplitter,
        QSpinBox, QTabWidget, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
    )
    from qt_helpers import (
        QtBaseMixin, ResultTable, make_table_sortable, q_ask_open, q_ask_save,
        q_ask_string, q_error, q_info, ask_reason_with_whitelist,
        ensure_shodan_key_ui as _qt_ensure_shodan_key_ui,
        SudoPasswordDialog, ui_after,
    )
except ImportError as _qt_err:
    raise SystemExit(
        "PySide6 is required for the Qt UI (pip install PySide6). "
        f"Import failed: {_qt_err}"
    )

import base64  
import io      
try:
    from PIL import Image
    _PIL_AVAILABLE = True
except Exception:
    _PIL_AVAILABLE = False
import hashlib
import uuid
import zlib
try:
    from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.serialization import load_der_public_key
    from cryptography.hazmat.backends import default_backend
    _CRYPTO_AVAILABLE = True
except Exception:
    _CRYPTO_AVAILABLE = False

init(autoreset=True)

SHODAN_KEY_PATH = os.path.join(os.getcwd(), "shodan_key.txt")
GLOBAL_IP_LOG = "ips.txt"
TIMEOUT = 3
PROTOCOL_VERSION = 772
MAX_WORKERS = 100
SERVERS_DAT_PATH = os.path.expandvars(r"%APPDATA%\.minecraft\servers.dat")
BACKUP_PATH = SERVERS_DAT_PATH + ".bak"

IGNORE_FILE = "ignore.txt"
SAVED_FILE = "saved.txt"
DEFAULT_JSONL_FILE = "minecraft_servers.json"
USER_LOG_FILE = "user_log.json"
SERVER_MONITOR_FILE = "server_monitor_log.json"
DEFAULT_MONITOR_INTERVAL = 60
CRACKED_CACHE_FILE = "known_cracked_servers.json"
CRACKED_LOG_FILE = "cracked_scan.log"
WHITELIST_LOG_FILE = "whitelist_scan.log"
CRACKED_VERIFY_WORKERS = 50
MC_ACCOUNTS_FILE = "mc_accounts.json"
PRISM_ACCOUNTS_PATH = os.path.expandvars(r"%APPDATA%\PrismLauncher\accounts.json")
PROXIES_FILE = "proxies.json"
PROXY_TEST_HOST = "api.minecraftservices.com"
PROXY_TEST_PORT = 443
# Cracked (offline-mode) whitelist probes run in parallel with no throttle and
# never touch Mojang auth. Online-mode probes still pace themselves with
# WHITELIST_PROBE_DELAY and Mojang backoff, just as before.
WHITELIST_VERIFY_WORKERS = 20
WHITELIST_PROBE_DELAY = 2.5
MOJANG_RATE_LIMIT_COOLDOWN = 45
MOJANG_JOIN_RETRIES = 2
NETWORK_SCAN_WORKERS = 500
NETWORK_SCAN_DEFAULT_PORTS = "25565"
NETWORK_SCAN_MAX_HOSTS = 4096
# --- masscan backend (fast SYN port discovery before Minecraft handshake) ---
MASSCAN_BIN = shutil.which("masscan") or "masscan"
MASSCAN_DEFAULT_RATE = 10000
MASSCAN_DEFAULT_WAIT = 2
MASSCAN_MAX_HOSTS = 1000000
MASSCAN_OUTPUT_TIMEOUT_MARGIN = 30

# Never trust a server-provided length.  Apart from protecting against broken
# servers, this prevents a single scan target from reserving gigabytes of RAM.
MAX_STATUS_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_FAVICON_RESPONSE_BYTES = 512 * 1024
MAX_ICON_CACHE_ENTRIES = 512

_CRACKED_CACHE_LOCK = threading.Lock()
_WHITELIST_LOG_LOCK = threading.Lock()
# Throttle for online-mode (Mojang-authenticated) whitelist probes only.
# Cracked/offline probes never touch this. The lock spaces the *start* of
# each online probe by WHITELIST_PROBE_DELAY, matching the old serial pacing
# even though probes now run in a thread pool.
_WHITELIST_ONLINE_THROTTLE_LOCK = threading.Lock()
_WHITELIST_LAST_ONLINE_PROBE = {}
# Remembers each server's protocol number from earlier status pings so the
# whitelist check can open its single login connection straight away instead
# of doing a status ping first (Paper kicks rapid reconnects with
# "Connection throttled").
_PROTOCOL_CACHE = {}
_PROTOCOL_CACHE_LOCK = threading.Lock()

def _remember_protocol(ip_port, protocol):
    try:
        protocol = int(protocol)
    except Exception:
        return
    try:
        with _PROTOCOL_CACHE_LOCK:
            _PROTOCOL_CACHE[ip_port] = protocol
    except Exception:
        pass

def _cached_protocol(ip_port):
    try:
        with _PROTOCOL_CACHE_LOCK:
            return _PROTOCOL_CACHE.get(ip_port)
    except Exception:
        return None
# When True, every whitelist verification (in all scan tabs) routes through
# proxies and rotates across all accounts to avoid rate limiting.
_WHITELIST_USE_PROXIES = False

def set_whitelist_proxy_mode(enabled):
    global _WHITELIST_USE_PROXIES
    _WHITELIST_USE_PROXIES = bool(enabled)

def whitelist_proxy_mode():
    return _WHITELIST_USE_PROXIES

def _load_cracked_cache():
    if not os.path.exists(CRACKED_CACHE_FILE):
        return {}
    try:
        with open(CRACKED_CACHE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except Exception:
        return {}

_CRACKED_CACHE = _load_cracked_cache()

class MinecraftSessionError(Exception):
    pass

def _save_cracked_cache_locked():
    try:
        with open(CRACKED_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(_CRACKED_CACHE, f, indent=2)
    except Exception:
        pass

def get_cached_cracked_entry(ip_port):
    with _CRACKED_CACHE_LOCK:
        entry = _CRACKED_CACHE.get(ip_port)
        return dict(entry) if entry else None

def record_cracked_server(ip_port, message="", extra=None):
    data = {
        "message": message or "",
        "first_seen": time.time(),
        "last_seen": time.time()
    }
    if isinstance(extra, dict):
        data.update({
            "motd": extra.get("motd", ""),
            "version": extra.get("version", ""),
            "players": extra.get("players", 0),
            "max_players": extra.get("max_players", 0)
        })
    with _CRACKED_CACHE_LOCK:
        existing = _CRACKED_CACHE.get(ip_port)
        if existing:
            data["first_seen"] = existing.get("first_seen", data["first_seen"])
        _CRACKED_CACHE[ip_port] = data
        _save_cracked_cache_locked()
    try:
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        line = f"{ts} | {ip_port} | {message or 'CRACKED'}\n"
        with open(CRACKED_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line)
    except Exception:
        pass

ICON_ENABLED = True           
ICON_SIZE = 24                
ICON_COL_EXTRA_PAD = 24       
ICON_FETCH_TIMEOUT = 2        
ICON_THREADS = 10             
ICON_PLACEHOLDER = "#ffffff"  
SKIP_CRACKED_VERSION_KEYWORDS = tuple(
    s.lower() for s in (
        "proxy",
        "e4mc",
        "maintenance",
        "maintainance",
        "§4maintenance"
    )
)


# ========================================

def _load_key_from_cwd():
    if os.path.exists(SHODAN_KEY_PATH):
        with open(SHODAN_KEY_PATH, "r", encoding="utf-8") as f:
            k = f.readline().strip()
            return k or None
    return None

def _save_key_to_cwd(k: str):
    with open(SHODAN_KEY_PATH, "w", encoding="utf-8") as f:
        f.write(k.strip() + "\n")

def ensure_shodan_key_ui(parent) -> str | None:
    """
    Main-thread only. If no key file exists, prompt the user and save it.
    Returns the key or None if the user cancels.
    (Qt port: password-masked QInputDialog via qt_helpers.)
    """
    return _qt_ensure_shodan_key_ui(parent)

# ========================================

def _load_mc_accounts():
    if not os.path.exists(MC_ACCOUNTS_FILE):
        return {"accounts": [], "active_uuid": ""}
    try:
        with open(MC_ACCOUNTS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return {"accounts": [], "active_uuid": ""}
        data.setdefault("accounts", [])
        data.setdefault("active_uuid", "")
        return data
    except Exception:
        return {"accounts": [], "active_uuid": ""}

def _save_mc_accounts(data):
    try:
        with open(MC_ACCOUNTS_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass

def _account_key(account):
    return (account.get("uuid") or account.get("name") or "").strip()

def _normalize_mc_account(name, profile_id, access_token, refresh_token=""):
    profile_id = (profile_id or "").replace("-", "").strip()
    return {
        "name": (name or "").strip(),
        "uuid": profile_id,
        "access_token": (access_token or "").strip(),
        "refresh_token": (refresh_token or "").strip(),
        "msa_client_id": "",
        "token_source": "manual",
        "source": "manual",
        "imported_at": time.time()
    }

def get_active_mc_account():
    data = _load_mc_accounts()
    accounts = [a for a in data.get("accounts", []) if a.get("access_token") and a.get("uuid") and a.get("name")]
    if not accounts:
        return None
    active_uuid = data.get("active_uuid")
    for account in accounts:
        if account.get("uuid") == active_uuid:
            return account
    return accounts[0]

def upsert_mc_accounts(accounts, active_uuid=None):
    data = _load_mc_accounts()
    existing = {}
    for account in data.get("accounts", []):
        key = _account_key(account)
        if key:
            existing[key] = account
    for account in accounts:
        key = _account_key(account)
        if not key:
            continue
        merged = dict(existing.get(key, {}))
        merged.update(account)
        existing[key] = merged
    data["accounts"] = list(existing.values())
    if active_uuid:
        data["active_uuid"] = active_uuid
    elif not data.get("active_uuid") and data["accounts"]:
        data["active_uuid"] = data["accounts"][0].get("uuid", "")
    _save_mc_accounts(data)
    return data

def import_prism_accounts(path=PRISM_ACCOUNTS_PATH):
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    imported = []
    for raw in data.get("accounts", []) if isinstance(data, dict) else []:
        profile = raw.get("profile") or {}
        ygg = raw.get("ygg") or {}
        xrp_mc = raw.get("xrp-mc") or {}
        msa = raw.get("msa") or {}
        name = profile.get("name") or raw.get("name") or ""
        profile_id = profile.get("id") or raw.get("profileId") or ""
        token_source = ""
        access_token = ""
        if ygg.get("token"):
            access_token = ygg.get("token")
            token_source = "Prism ygg"
        elif xrp_mc.get("token"):
            access_token = xrp_mc.get("token")
            token_source = "Prism xrp-mc (fallback)"
        elif raw.get("accessToken"):
            access_token = raw.get("accessToken")
            token_source = "Prism accessToken"
        refresh_token = msa.get("refresh_token") or raw.get("refreshToken") or ""
        account = _normalize_mc_account(name, profile_id, access_token, refresh_token)
        account["source"] = "Prism Launcher"
        account["token_source"] = token_source
        account["has_xrp_mc_token"] = bool(xrp_mc.get("token"))
        account["has_ygg_token"] = bool(ygg.get("token"))
        account["msa_client_id"] = raw.get("msa-client-id") or raw.get("msaClientId") or ""
        if account["name"] and account["uuid"] and account["access_token"]:
            imported.append(account)
    if imported:
        upsert_mc_accounts(imported, active_uuid=imported[0].get("uuid"))
    return imported

def minecraft_sha1_hexdigest(*parts):
    digest = hashlib.sha1()
    for part in parts:
        digest.update(part)
    value = int.from_bytes(digest.digest(), "big", signed=True)
    return format(value, "x")

def verify_minecraft_join(account, server_hash):
    query = urllib.parse.urlencode({
        "username": account.get("name", ""),
        "serverId": server_hash
    })
    req = urllib.request.Request(
        "https://sessionserver.mojang.com/session/minecraft/hasJoined?" + query,
        headers={"User-Agent": "MC-Scanner"}
    )
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=6) as resp:
                raw = resp.read().decode("utf-8")
                if resp.status == 200 and raw:
                    data = json.loads(raw)
                    expected_id = (account.get("uuid") or "").replace("-", "").lower()
                    returned_id = (data.get("id") or "").replace("-", "").lower()
                    returned_name = (data.get("name") or "").lower()
                    if returned_id == expected_id or returned_name == (account.get("name") or "").lower():
                        return True
        except urllib.error.HTTPError as exc:
            if exc.code != 204:
                raise
        except Exception:
            return False
    return False

def minecraft_join_server(account, server_hash, verify=False):
    payload = json.dumps({
        "accessToken": account.get("access_token", ""),
        "selectedProfile": account.get("uuid", ""),
        "serverId": server_hash
    }).encode("utf-8")
    req = urllib.request.Request(
        "https://sessionserver.mojang.com/session/minecraft/join",
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": "MC-Scanner"},
        method="POST"
    )
    with urllib.request.urlopen(req, timeout=6) as resp:
        if not (200 <= resp.status < 300):
            raise MinecraftSessionError(f"Join failed: HTTP {resp.status}")
    if verify and not verify_minecraft_join(account, server_hash):
        raise MinecraftSessionError("Mojang hasJoined did not verify after join")
    return True

def _http_json(url, payload, headers=None, timeout=12):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", "User-Agent": "MC-Scanner", **(headers or {})},
        method="POST"
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read().decode("utf-8")
        return json.loads(raw) if raw else {}

def refresh_minecraft_account(account):
    refresh_token = account.get("refresh_token") or ""
    client_id = account.get("msa_client_id") or "00000000402b5328"
    if not refresh_token:
        return None
    form = urllib.parse.urlencode({
        "client_id": client_id,
        "refresh_token": refresh_token,
        "grant_type": "refresh_token",
        "redirect_uri": "https://login.live.com/oauth20_desktop.srf",
        "scope": "XboxLive.signin offline_access"
    }).encode("utf-8")
    token_req = urllib.request.Request(
        "https://login.live.com/oauth20_token.srf",
        data=form,
        headers={"Content-Type": "application/x-www-form-urlencoded", "User-Agent": "MC-Scanner"},
        method="POST"
    )
    with urllib.request.urlopen(token_req, timeout=12) as resp:
        msa = json.loads(resp.read().decode("utf-8"))
    msa_access = msa.get("access_token")
    if not msa_access:
        return None
    xbl = _http_json("https://user.auth.xboxlive.com/user/authenticate", {
        "Properties": {
            "AuthMethod": "RPS",
            "SiteName": "user.auth.xboxlive.com",
            "RpsTicket": "d=" + msa_access
        },
        "RelyingParty": "http://auth.xboxlive.com",
        "TokenType": "JWT"
    })
    xbl_token = xbl.get("Token")
    uhs = ((xbl.get("DisplayClaims") or {}).get("xui") or [{}])[0].get("uhs")
    xsts = _http_json("https://xsts.auth.xboxlive.com/xsts/authorize", {
        "Properties": {
            "SandboxId": "RETAIL",
            "UserTokens": [xbl_token]
        },
        "RelyingParty": "rp://api.minecraftservices.com/",
        "TokenType": "JWT"
    })
    xsts_token = xsts.get("Token")
    uhs = (((xsts.get("DisplayClaims") or {}).get("xui") or [{}])[0].get("uhs")) or uhs
    mc = _http_json("https://api.minecraftservices.com/authentication/login_with_xbox", {
        "identityToken": f"XBL3.0 x={uhs};{xsts_token}"
    })
    mc_token = mc.get("access_token")
    if not mc_token:
        return None
    profile_req = urllib.request.Request(
        "https://api.minecraftservices.com/minecraft/profile",
        headers={"Authorization": "Bearer " + mc_token, "User-Agent": "MC-Scanner"}
    )
    with urllib.request.urlopen(profile_req, timeout=12) as resp:
        profile = json.loads(resp.read().decode("utf-8"))
    refreshed = dict(account)
    refreshed["access_token"] = mc_token
    refreshed["refresh_token"] = msa.get("refresh_token") or refresh_token
    refreshed["uuid"] = (profile.get("id") or refreshed.get("uuid") or "").replace("-", "")
    refreshed["name"] = profile.get("name") or refreshed.get("name") or ""
    refreshed["msa_client_id"] = client_id
    refreshed["token_source"] = "Minecraft Services refresh"
    upsert_mc_accounts([refreshed], active_uuid=refreshed.get("uuid"))
    return refreshed

def ensure_minecraft_session_join(account, server_hash, cooldown=None, retries=None):
    if cooldown is None:
        cooldown = MOJANG_RATE_LIMIT_COOLDOWN
    if retries is None:
        retries = MOJANG_JOIN_RETRIES
    rate_attempts = 0
    refreshed_once = False
    while True:
        try:
            minecraft_join_server(account, server_hash, verify=False)
            return account
        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                if rate_attempts < retries:
                    rate_attempts += 1
                    time.sleep(cooldown)
                    continue
                raise MinecraftSessionError(
                    f"Mojang sessionserver rate limited join after {retries + 1} attempt(s)"
                )
            if exc.code not in (401, 403):
                raise
            if refreshed_once:
                raise MinecraftSessionError(f"Session token rejected by Mojang HTTP {exc.code}")
            try:
                refreshed = refresh_minecraft_account(account)
            except Exception:
                refreshed = None
            if not refreshed:
                raise MinecraftSessionError(f"Session token rejected by Mojang HTTP {exc.code}")
            account = refreshed
            refreshed_once = True
            continue
        except MinecraftSessionError:
            raise

# ==================== PROXIES ====================

def parse_proxy_line(line):
    """
    Parse one proxy line.
      ip:port:user:pass        -> SOCKS5 (with username/password auth)
      ip:port                  -> HTTP proxy (CONNECT tunnel)
      socks5:// or http:// prefix is also accepted.
    Returns a dict or None.
    """
    line = (line or "").strip()
    if not line:
        return None
    low = line.lower()
    proxy_type = None
    if low.startswith("socks5://"):
        proxy_type = "socks5"
        line = line[len("socks5://"):]
    elif low.startswith("http://"):
        proxy_type = "http"
        line = line[len("http://"):]
    elif low.startswith("socks4://"):
        proxy_type = "socks5"
        line = line[len("socks4://"):]
    parts = line.split(":")
    if len(parts) == 4:
        host, port, user, password = parts
        try:
            port = int(port)
        except ValueError:
            return None
        if not host or not (0 < port < 65536):
            return None
        return {
            "host": host,
            "port": port,
            "user": user,
            "password": password,
            "type": proxy_type or "socks5",
            "working": None,
            "message": "",
            "last_tested": 0
        }
    if len(parts) == 2:
        host, port = parts
        try:
            port = int(port)
        except ValueError:
            return None
        if not host or not (0 < port < 65536):
            return None
        return {
            "host": host,
            "port": port,
            "user": "",
            "password": "",
            "type": proxy_type or "http",
            "working": None,
            "message": "",
            "last_tested": 0
        }
    return None

def load_proxies():
    if not os.path.exists(PROXIES_FILE):
        return []
    try:
        with open(PROXIES_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except Exception:
        return []

def save_proxies(proxies):
    try:
        with open(PROXIES_FILE, "w", encoding="utf-8") as f:
            json.dump(proxies, f, indent=2)
    except Exception:
        pass

def get_working_proxies():
    """
    Return proxies usable for scanning. Prefers proxies that passed a test;
    if none have been tested yet, returns the untested ones so scans can run
    without requiring a full pre-test of the list.
    """
    proxies = load_proxies()
    usable = [p for p in proxies if p.get("working") is not False]
    working = [p for p in usable if p.get("working") is True]
    return working or usable

def proxy_display(p):
    base = f"{p.get('host')}:{p.get('port')}"
    if p.get("user"):
        base += f":{p.get('user')}"
    return base

def _socks5_connect(sock, proxy, target_host, target_port):
    # Greeting: SOCKS5, offer no-auth (0x00) AND username/password (0x02) so
    # proxies that only accept one of them don't reply "no acceptable method".
    sock.sendall(bytes([0x05, 0x02, 0x00, 0x02]))
    resp = recv_exact(sock, 2)
    if len(resp) != 2 or resp[0] != 0x05:
        raise ConnectionError("Bad SOCKS5 greeting response")
    if resp[1] == 0x02:
        user = (proxy.get("user") or "").encode("utf-8")
        password = (proxy.get("password") or "").encode("utf-8")
        if len(user) > 255 or len(password) > 255:
            raise ValueError("Proxy credentials too long")
        sock.sendall(bytes([0x01, len(user)]) + user + bytes([len(password)]) + password)
        auth = recv_exact(sock, 2)
        if len(auth) != 2 or auth[1] != 0x00:
            raise ConnectionError("SOCKS5 auth rejected")
    elif resp[1] == 0x00:
        pass  # no-auth accepted
    else:
        raise ConnectionError(f"SOCKS5 no acceptable auth method ({resp[1]})")
    host_bytes = target_host.encode("utf-8")
    if len(host_bytes) > 255:
        raise ValueError("Proxy target host too long")
    req = bytes([0x05, 0x01, 0x00, 0x03, len(host_bytes)]) + host_bytes + struct.pack(">H", target_port)
    sock.sendall(req)
    rep = recv_exact(sock, 4)
    if len(rep) != 4 or rep[0] != 0x05 or rep[1] != 0x00:
        code = rep[1] if len(rep) > 1 else -1
        raise ConnectionError(f"SOCKS5 connect failed (code {code})")
    atyp = rep[3]
    if atyp == 0x01:
        recv_exact(sock, 4)
    elif atyp == 0x04:
        recv_exact(sock, 16)
    elif atyp == 0x03:
        n = recv_exact(sock, 1)[0]
        recv_exact(sock, n)
    recv_exact(sock, 2)

def _http_connect(sock, proxy, target_host, target_port):
    authority = f"{target_host}:{target_port}"
    headers = [
        f"CONNECT {authority} HTTP/1.1",
        f"Host: {authority}",
        "Proxy-Connection: Keep-Alive",
        "User-Agent: MC-Scanner",
    ]
    user = proxy.get("user") or ""
    password = proxy.get("password") or ""
    if user:
        token = base64.b64encode(f"{user}:{password}".encode("utf-8")).decode("ascii")
        headers.append(f"Proxy-Authorization: Basic {token}")
    req = ("\r\n".join(headers) + "\r\n\r\n").encode("utf-8")
    sock.sendall(req)
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("Proxy closed during CONNECT")
        data += chunk
    head = data.split(b"\r\n", 1)[0].decode("utf-8", errors="ignore")
    m = re.search(r"\s(\d{3})\s", head)
    code = int(m.group(1)) if m else 0
    if code not in (200, 201):
        raise ConnectionError(f"HTTP proxy CONNECT failed ({head.strip()})")

def create_proxied_connection(proxy, target_host, target_port, timeout=6):
    """
    Connect to (target_host, target_port) through the proxy. Tries the proxy's
    configured type first, then the other type as a fallback (handles lists that
    mix up SOCKS5 and HTTP entries).
    """
    primary = (proxy.get("type") or "http").lower()
    if primary == "socks5":
        order = ("socks5", "http")
    else:
        order = ("http", "socks5")
    last_err = None
    for ptype in order:
        sock = None
        try:
            sock = socket.create_connection((proxy.get("host"), proxy.get("port")), timeout=timeout)
            sock.settimeout(timeout)
            if ptype == "socks5":
                _socks5_connect(sock, proxy, target_host, target_port)
            else:
                _http_connect(sock, proxy, target_host, target_port)
            return sock
        except Exception as exc:
            last_err = exc
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass
    raise ConnectionError(str(last_err))

def open_connection(host, port, proxy=None, timeout=6):
    """Open a TCP connection to (host, port), optionally through a proxy."""
    if proxy:
        return create_proxied_connection(proxy, host, port, timeout=timeout)
    return socket.create_connection((host, port), timeout=timeout)

def test_proxy(proxy, target_host=PROXY_TEST_HOST, target_port=PROXY_TEST_PORT, timeout=6):
    try:
        sock = create_proxied_connection(proxy, target_host, target_port, timeout=timeout)
        try:
            sock.close()
        except Exception:
            pass
        return True, "OK"
    except Exception as exc:
        return False, str(exc)[:80]

def probe_proxies_async(proxies, callback, progress_cb=None):
    """Test each proxy in parallel, updating its 'working' flag, then save."""
    if not proxies:
        return
    total = len(proxies)
    lock = threading.Lock()
    counter = {"done": 0}

    def worker():
        with ThreadPoolExecutor(max_workers=min(100, max(1, total))) as executor:
            future_to_proxy = {}
            for p in proxies:
                future_to_proxy[executor.submit(_probe_proxy_worker, p)] = p
            for fut in as_completed(future_to_proxy):
                p = future_to_proxy[fut]
                try:
                    ok, msg = fut.result()
                except Exception as exc:
                    p["working"] = False
                    p["message"] = str(exc)[:80]
                    p["last_tested"] = time.time()
                    ok, msg = False, p["message"]
                try:
                    callback(p, ok, msg)
                except Exception:
                    pass
                with lock:
                    counter["done"] += 1
                    done = counter["done"]
                if progress_cb:
                    try:
                        progress_cb(done, total)
                    except Exception:
                        pass
        save_proxies(proxies)

    threading.Thread(target=worker, daemon=True).start()

def _probe_proxy_worker(p):
    ok, msg = test_proxy(p)
    p["working"] = ok
    p["message"] = msg
    p["last_tested"] = time.time()
    return ok, msg

# ==================== TOKEN IMPORT / PROBE ====================

def decode_jwt_payload(token):
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return None
        payload = parts[1]
        pad = "=" * (-len(payload) % 4)
        raw = base64.urlsafe_b64decode(payload + pad)
        return json.loads(raw.decode("utf-8"))
    except Exception:
        return None

def extract_jwt_account(token):
    """Decode a JWT MC access token into an account dict, or None."""
    payload = decode_jwt_payload(token)
    if not payload:
        return None
    pfd = payload.get("pfd") or []
    name = ""
    profile_id = ""
    for entry in pfd:
        if entry.get("type") == "mc":
            name = entry.get("name") or ""
            profile_id = entry.get("id") or ""
            break
    if not profile_id:
        profile_id = ((payload.get("profiles") or {}).get("mc")) or ""
    if not profile_id:
        return None
    return {
        "name": name,
        "uuid": profile_id.replace("-", "").lower(),
        "access_token": token,
        "refresh_token": "",
        "msa_client_id": "",
        "xuid": payload.get("xuid", ""),
        "token_source": "JWT access token",
        "source": "token import",
        "imported_at": time.time()
    }

def import_tokens_from_text(text):
    """
    Import access / refresh tokens from pasted text.
      - username:M.C...   -> MSA refresh token (Artifacts)
      - M.C...            -> MSA refresh token (no name)
      - eyJ... (JWT)      -> Minecraft access token
    Returns a list of account dicts (deduped, not yet saved).
    """
    imported = []
    seen = set()
    nameless = 0
    for raw_line in (text or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        # Accept both the documented refresh-token form and the common
        # USERNAME:ACCESS_TOKEN export form.  Keep the username because it is
        # required when building the login-start packet.
        m = re.match(r'^([A-Za-z0-9_]{1,16}):(.+)$', line)
        if m:
            name, supplied_token = m.group(1), m.group(2).strip()
            if not supplied_token:
                continue
            is_refresh = supplied_token.startswith("M.")
            key = ("refresh" if is_refresh else "access", supplied_token)
            if key in seen:
                continue
            seen.add(key)
            if is_refresh:
                imported.append({"name": name, "uuid": "", "access_token": "",
                    "refresh_token": supplied_token, "msa_client_id": "00000000402b5328",
                    "token_source": "MSA refresh token", "source": "token import",
                    "imported_at": time.time()})
            else:
                imported.append({"name": name, "uuid": "", "access_token": supplied_token,
                    "refresh_token": "", "msa_client_id": "", "token_source": "username:token",
                    "source": "token import", "imported_at": time.time()})
            continue
        m2 = re.match(r'^(M\.[A-Za-z0-9_.!*\-]+)$', line)
        if m2:
            refresh_token = m2.group(1)
            key = ("refresh", refresh_token)
            if key in seen:
                continue
            seen.add(key)
            nameless += 1
            imported.append({
                "name": f"token-{nameless}",
                "uuid": "",
                "access_token": "",
                "refresh_token": refresh_token,
                "msa_client_id": "00000000402b5328",
                "token_source": "MSA refresh token",
                "source": "token import",
                "imported_at": time.time()
            })
            continue
        if line.startswith("eyJ"):
            account = extract_jwt_account(line)
            if account:
                key = ("access", account.get("access_token"))
                if key in seen:
                    continue
                seen.add(key)
                imported.append(account)
            continue
    return imported

def probe_account_refresh(a):
    try:
        refreshed = refresh_minecraft_account(a)
    except Exception as exc:
        return a, False, f"refresh failed ({str(exc)[:60]})"
    if not refreshed:
        return a, False, "refresh produced no token"
    return refreshed, True, "OK (refreshed)"

def probe_account(account):
    """
    Test one account and enrich it if possible.
    Returns (account, ok, message).
    """
    a = dict(account)
    try:
        if a.get("access_token"):
            req = urllib.request.Request(
                "https://api.minecraftservices.com/minecraft/profile",
                headers={"Authorization": "Bearer " + a["access_token"], "User-Agent": "MC-Scanner"}
            )
            try:
                with urllib.request.urlopen(req, timeout=12) as resp:
                    if resp.status == 200:
                        profile = json.loads(resp.read().decode("utf-8"))
                        a["uuid"] = (profile.get("id") or a.get("uuid") or "").replace("-", "").lower()
                        a["name"] = profile.get("name") or a.get("name") or ""
                        a["token_source"] = "JWT access token"
                        return a, True, "OK"
                    return a, False, f"HTTP {resp.status}"
            except urllib.error.HTTPError as exc:
                if exc.code in (401, 403):
                    if a.get("refresh_token"):
                        return probe_account_refresh(a)
                    return a, False, f"token invalid (HTTP {exc.code})"
                try:
                    detail = exc.read().decode("utf-8", errors="replace")[:180]
                except Exception:
                    detail = ""
                return a, False, f"HTTP {exc.code}" + (f": {detail}" if detail else "")
        if a.get("refresh_token"):
            return probe_account_refresh(a)
        return a, False, "no token present"
    except Exception as exc:
        return a, False, str(exc)[:80]

def probe_accounts_async(accounts, callback, progress_cb=None):
    """Probe/enrich a list of accounts in the background, saving results."""
    def worker():
        total = len(accounts)
        done = 0
        updated = []
        for a in accounts:
            acc, ok, msg = probe_account(a)
            if acc.get("uuid"):
                updated.append(acc)
            callback(acc, ok, msg)
            done += 1
            if progress_cb:
                progress_cb(done, total)
        if updated:
            upsert_mc_accounts(updated)
    if accounts:
        threading.Thread(target=worker, daemon=True).start()

def get_all_mc_accounts():
    data = _load_mc_accounts()
    return [a for a in data.get("accounts", []) if a.get("access_token") and a.get("uuid") and a.get("name")]

def read_mc_byte_array_from_bytes(buf, pos):
    length, pos = read_varint_from_bytes(buf, pos)
    end = pos + length
    if end > len(buf):
        raise ValueError("Byte array length outside buffer")
    return buf[pos:end], end

def _extract_ip_port_from_text(s):
    m = re.search(r'([0-9a-zA-Z\.\-]+):([0-9]{1,5})', s.strip())
    if not m:
        return None
    return f"{m.group(1)}:{int(m.group(2))}"

def load_ignore_set():
    s = set()
    if os.path.exists(IGNORE_FILE):
        with open(IGNORE_FILE, "r", encoding="utf-8") as f:
            for line in f:
                ip_port = _extract_ip_port_from_text(line)
                if ip_port:
                    s.add(ip_port)
    return s

IGNORE_SET = load_ignore_set()

def is_ignored(ip_port):
    return ip_port in IGNORE_SET

def refresh_ignore_set(ip_port_added=None):  #
    global IGNORE_SET
    if ip_port_added:
        IGNORE_SET.add(ip_port_added)
    else:
        IGNORE_SET = load_ignore_set()

# ========================================

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def ask_yes_no(prompt):
    return input(f"{prompt} (y/n): ").strip().lower().startswith('y')

def sanitize_query_for_filename(query):
    return re.sub(r'[^a-zA-Z0-9]+', '_', query.strip().lower()).strip('_')

def is_valid_ip_port(entry):
    return re.match(r"^\d{1,3}(\.\d{1,3}){3}:\d{1,5}$", entry)

def get_ip_only(line_or_ip):  #
    if " |" in line_or_ip:
        line_or_ip = line_or_ip.split(" |")[0]
    return _extract_ip_port_from_text(line_or_ip) or line_or_ip

# Common formatter so all tabs show exactly the same line format
def format_result_line(ip_port, motd, players_online, players_max, version):  #
    return f"{ip_port} | MOTD: {sanitize_motd(motd)} | Players: {players_online}/{players_max} | Version: {version}"

# Sorting helpers for Treeviews
def _players_key(val):  # "6/73" -> 6
    try:
        return int(str(val).split("/", 1)[0])
    except:
        return -1

def _ip_key(val):  # "a.b.c.d:port" -> (a,b,c,d,port)
    s = str(val)
    try:
        host, port = s.split(":")
        port = int(port)
    except:
        host, port = s, 0
    parts = host.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        try:
            return tuple(int(p) for p in parts) + (port,)
        except:
            return (0, 0, 0, 0, port)
    return (999, 999, 999, 999, str(host), port)

def _version_key(val):  # "1.21.1" -> (1,21,1)
    t = []
    for token in str(val).strip().split("."):
        if token.isdigit():
            t.append(int(token))
        else:
            nums = re.findall(r'\d+', token)
            t.extend(int(n) for n in nums) if nums else t.append(0)
    return tuple(t) if t else (0,)

def make_tree_sortable(tree, column_key_funcs):  #
    """Qt port: delegate header sorting to the ResultTable (custom keys)."""
    try:
        make_table_sortable(tree, column_key_funcs)
    except Exception:
        pass


# Robust parser for "IP | MOTD: ... | Players: x/y | Version: ..."
def parse_formatted_line(line):  #
    ip = get_ip_only(line)
    motd = ""
    players = ""
    version = ""
    try:
        m_motd = re.search(r"\bMOTD:\s*(.*?)\s*\|\s*Players:", line)
        if m_motd:
            motd = m_motd.group(1).strip()
        m_pl = re.search(r"\bPlayers:\s*([^|]+)", line)
        if m_pl:
            players = m_pl.group(1).strip()
        m_ver = re.search(r"\bVersion:\s*(.*)$", line)
        if m_ver:
            version = m_ver.group(1).strip()
    except:
        pass
    return ip, motd, players, version

def collect_version_options(rows):
    versions = []
    seen = set()
    for row in rows or []:
        version = ""
        if isinstance(row, dict):
            version = row.get("version", "")
        elif isinstance(row, (list, tuple)) and len(row) >= 4:
            version = row[3]
        version = sanitize_motd(version)
        if not version or version.upper() == "N/A":
            continue
        key = version.lower()
        if key in seen:
            continue
        seen.add(key)
        versions.append(version)
    versions.sort(key=_version_key)
    return ["All versions"] + versions

def version_filter_allows(version, selected):
    selected = (selected or "All versions").strip()
    if not selected or selected.lower() == "all versions":
        return True
    version_norm = sanitize_motd(version).lower()
    selected_norm = sanitize_motd(selected).lower()
    return selected_norm in version_norm or version_norm in selected_norm
    
def sanitize_motd(m):
    m = "" if m is None else str(m)
    m = re.sub(r"§[0-9A-FK-ORa-fk-or]", "", m)  # strip legacy MC color/style codes
    return re.sub(r"\s+", " ", m.replace("\r", " ").replace("\n", " ")).strip()

MC_TRANSLATE_MESSAGES = {
    "multiplayer.disconnect.unverified_username": "Failed to verify username",
    "multiplayer.disconnect.not_whitelisted": "You are not whitelisted on this server",
    "multiplayer.disconnect.banned": "You are banned from this server",
    "multiplayer.disconnect.outdated_client": "Outdated client",
    "multiplayer.disconnect.outdated_server": "Outdated server",
    "disconnect.loginFailedInfo.invalidSession": "Invalid session",
    "disconnect.loginFailedInfo.serversUnavailable": "Authentication servers are unavailable",
}

def minecraft_text_component_to_plain(value):
    if value is None:
        return ""
    if isinstance(value, str):
        raw = value.strip()
        if raw.startswith("{") or raw.startswith("["):
            try:
                return minecraft_text_component_to_plain(json.loads(raw))
            except Exception:
                return sanitize_motd(raw)
        return sanitize_motd(raw)
    if isinstance(value, list):
        return sanitize_motd(" ".join(minecraft_text_component_to_plain(v) for v in value))
    if isinstance(value, dict):
        parts = []
        text = value.get("text")
        if text:
            parts.append(str(text))
        translate = value.get("translate")
        if translate:
            translated = MC_TRANSLATE_MESSAGES.get(str(translate), str(translate))
            parts.append(translated)
        if value.get("with"):
            parts.append(" ".join(minecraft_text_component_to_plain(v) for v in value.get("with") or []))
        if value.get("extra"):
            parts.append(" ".join(minecraft_text_component_to_plain(v) for v in value.get("extra") or []))
        return sanitize_motd(" ".join(p for p in parts if p))
    return sanitize_motd(value)

def should_skip_cracked_probe(entry):
    """
    Heuristic skip for proxies/non-standard servers that hang the faux login phase.
    """
    version_raw = (entry.get("version") or "")
    version_norm = version_raw.strip().lower()
    version_plain = sanitize_motd(version_raw).lower()
    if version_norm:
        for key in SKIP_CRACKED_VERSION_KEYWORDS:
            if key in version_norm or key in version_plain:
                return True
    return False


# ==================== SHODAN ====================

def get_user_query():
    user_input = input('\nEnter Shodan Search Query (excluding "minecraft"): ').strip()
    if user_input.lower().startswith("minecraft"):
        user_input = user_input[len("minecraft"):].strip()
    full_query = f"minecraft {user_input}"
    return full_query

def search_shodan(query, api_key):
    api = shodan.Shodan(api_key)
    try:
        results = api.search(query)
        return results.get('matches', [])
    except shodan.APIError as e:
        # Let caller decide how to handle (invalid key, rate limit, etc.)
        raise


def parse_description_from_raw(data_string):
    desc_match = re.search(r"Description:\s*(.*?)\s*Online Players:", data_string, re.DOTALL)
    return sanitize_motd(desc_match.group(1).strip() if desc_match else "N/A")

def parse_players(data_string):
    match = re.search(r"Online Players:\s*(\d+)\s*Maximum Players:\s*(\d+)", data_string)
    if match:
        return f"{match.group(1)}/{match.group(2)}"
    return "N/A"

def parse_version(data_string):
    match = re.search(r"Version:\s*(.*?)\s*\(", data_string)
    return match.group(1).strip() if match else "N/A"

def save_shodan_results(servers, filepath):
    ip_set = set()
    skipped_ignored = 0
    with open(filepath, "w", encoding="utf-8") as f:
        for server in servers:
            ip = server.get("ip_str")
            port = server.get("port", 25565)
            data = server.get("data", "")

            motd = parse_description_from_raw(data)
            players = parse_players(data)
            version = parse_version(data)
            ip_port = f"{ip}:{port}"

            if is_ignored(ip_port):
                skipped_ignored += 1
                continue
            ip_set.add(ip_port)
            line = f"{ip_port} | MOTD: {motd} | Players: {players} | Version: {version}"
            f.write(line + "\n")

    update_global_ip_log(ip_set)
    if skipped_ignored:
        print(Fore.YELLOW + f"Skipped {skipped_ignored} ignored entrie(s).")

def update_global_ip_log(new_entries):
    updated_lines = {}
    if os.path.exists(GLOBAL_IP_LOG):
        with open(GLOBAL_IP_LOG, 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip():
                    ip = line.strip().split(' |')[0]
                    updated_lines[ip] = line.strip()

    for entry in new_entries:
        if entry not in updated_lines and not is_ignored(entry):
            updated_lines[entry] = f"{entry} | MOTD: N/A | Players: N/A | Version: N/A"

    with open(GLOBAL_IP_LOG, 'w', encoding='utf-8') as f:
        for line in sorted(updated_lines.values()):
            f.write(line + "\n")

def read_servers(file):
    entries = []
    with open(file, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            # Try to extract an ip:port anywhere in the line (handles "ip:port" or "ip:port | ..." or noisy lines)
            ip_port = _extract_ip_port_from_text(line)
            if ip_port:
                entries.append(ip_port)
                continue
            # Fallback: split on common separators and look for a token that matches host:port
            tokens = re.split(r"[\s|,;]+", line)
            found = False
            for t in tokens:
                t = t.strip()
                if not t:
                    continue
                m = re.match(r'^([0-9a-zA-Z\.\-]+):([0-9]{1,5})$', t)
                if m:
                    entries.append(f"{m.group(1)}:{int(m.group(2))}")
                    found = True
                    break
            if not found:
                # No valid ip:port found on this line; skip it
                continue
    return entries

def split_host_port(entry):
    match = re.match(r'^([0-9a-zA-Z\.\-]+):([0-9]+)', entry.strip())
    if match:
        return match.group(1), int(match.group(2))
    raise ValueError(f"Invalid entry format: {entry}")

def _probe_cracked_entry(entry):
    ip = entry.get("ip")
    if not ip:
        return None, "Missing IP"
    try:
        host, port = split_host_port(ip)
    except ValueError as exc:
        return None, str(exc)
    result, message = is_cracked_server(host, port)
    return result, message

def run_cracked_verifier_async(entries, callback, progress_cb=None):
    """
    entries: list of ping_server dicts.
    callback(entry, result, message, was_cached) invoked from the worker thread.
    progress_cb(done, total) invoked after each entry is processed.
    """
    def worker():
        total = len(entries)
        completed = 0
        pending = []
        for entry in entries:
            ip = entry.get("ip")
            cached = get_cached_cracked_entry(ip)
            if cached:
                callback(entry, True, cached.get("message") or "Cached cracked server", True)
                completed += 1
                if progress_cb:
                    progress_cb(completed, total)
            else:
                pending.append(entry)
        if not pending:
            return
        with ThreadPoolExecutor(max_workers=CRACKED_VERIFY_WORKERS) as executor:
            future_to_entry = {executor.submit(_probe_cracked_entry, entry): entry for entry in pending}
            for fut in as_completed(future_to_entry):
                entry = future_to_entry[fut]
                try:
                    result, message = fut.result()
                except Exception as exc:
                    result, message = None, str(exc)
                if result is True:
                    record_cracked_server(entry.get("ip"), message, extra=entry)
                callback(entry, result, message, False)
                completed += 1
                if progress_cb:
                    progress_cb(completed, total)
    if not entries:
        return
    threading.Thread(target=worker, daemon=True).start()

# ==================== PING ====================

def varint_encode(number):
    out = bytearray()
    while True:
        temp = number & 0b01111111
        number >>= 7
        if number != 0:
            temp |= 0b10000000
        out.append(temp)
        if number == 0:
            break
    return bytes(out)

def write_string(s):
    encoded = s.encode('utf-8')
    return varint_encode(len(encoded)) + encoded

def varint_decode(sock):
    number = 0
    for i in range(5):
        byte = sock.recv(1)
        if not byte:
            raise IOError("Socket closed")
        byte = byte[0] 
        number |= (byte & 0x7F) << (7 * i)
        if not (byte & 0x80):
            break
    return number

def recv_bounded(sock, length, limit):
    """Read a server-provided payload only after applying a hard size limit."""
    if length < 0 or length > limit:
        raise ValueError(f"Packet too large ({length} bytes; limit {limit})")
    data = bytearray()
    while len(data) < length:
        chunk = sock.recv(min(65536, length - len(data)))
        if not chunk:
            raise IOError("Socket closed")
        data.extend(chunk)
    return bytes(data)

def parse_description(desc):
    if isinstance(desc, str):
        return sanitize_motd(desc)
    elif isinstance(desc, dict):
        if 'text' in desc:
            return sanitize_motd(desc['text'])
        elif 'extra' in desc:
            return sanitize_motd(''.join([x.get('text', '') for x in desc['extra']]))
    return ''

def ping_server(entry, proxy=None):
    try:
        host, port = split_host_port(entry)
        with open_connection(host, port, proxy=proxy, timeout=TIMEOUT) as sock:
            sock.settimeout(TIMEOUT)

            handshake = (
                varint_encode(0x00) +
                varint_encode(PROTOCOL_VERSION) +
                write_string(host) +
                struct.pack('>H', port) +
                varint_encode(1)
            )
            sock.send(varint_encode(len(handshake)) + handshake)
            sock.send(varint_encode(1) + b'\x00')

            _ = varint_decode(sock)
            _ = varint_decode(sock)
            json_length = varint_decode(sock)
            data = recv_bounded(sock, json_length, MAX_STATUS_RESPONSE_BYTES).decode('utf-8')
            response = json.loads(data)

            motd = parse_description(response.get('description', ''))
            players = response.get('players', {}).get('online', 0)
            max_players = response.get('players', {}).get('max', 0)
            # sample is a list of dicts like {"id": "uuid", "name": "playername"}
            sample = response.get('players', {}).get('sample', []) or []

            # Normalize sample to list of tuples (id, name)
            players_sample = []
            for p in sample:
                try:
                    pid = str(p.get('id') or "")
                    pname = str(p.get('name') or "")
                    players_sample.append((pid, pname))
                except Exception:
                    continue

            # cracked detection: if any reported player id matches the offline-mode UUID for that name
            def _offline_uuid_for_name(name: str) -> str:
                # Replicate Java's UUID.nameUUIDFromBytes("OfflinePlayer:" + name)
                h = hashlib.md5()
                h.update(b"OfflinePlayer:")
                h.update(name.encode('utf-8'))
                d = bytearray(h.digest())
                # set variant and version bits like Java's nameUUIDFromBytes (version 3)
                d[6] = (d[6] & 0x0f) | 0x30
                d[8] = (d[8] & 0x3f) | 0x80
                return str(uuid.UUID(bytes=bytes(d)))

            cracked = False
            for pid, pname in players_sample:
                if not pname:
                    continue
                try:
                    off_uuid = _offline_uuid_for_name(pname).replace('-', '').lower()
                    reported = pid.replace('-', '').lower()
                    if reported == off_uuid:
                        cracked = True
                        break
                except Exception:
                    continue

            result = {
                'ip': f"{host}:{port}",
                'players': players,
                'max_players': max_players,
                'motd': motd,
                'version': response.get('version', {}).get('name', 'N/A'),
                'protocol': response.get('version', {}).get('protocol', PROTOCOL_VERSION),
                'players_sample': players_sample,
                'cracked': cracked
            }
            _remember_protocol(result['ip'], result['protocol'])
            return result
    except:
        return None

def format_player_list(sample):
    """
    Returns a comma-separated string of player names from the sample, or "-" if none.
    """
    names = []
    for item in sample or []:
        name = None
        if isinstance(item, (list, tuple)) and len(item) >= 2:
            name = item[1]
        elif isinstance(item, dict):
            name = item.get("name")
        if isinstance(name, str) and name.strip():
            names.append(name.strip())
    return ", ".join(names) if names else "-"


# ==================== CRACKED SERVER CHECKER ====================

PACKET_LENGTH_LIMIT_LOGIN = 100000
DEFAULT_STATUS_PROTOCOL = 773
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_]{1,16}$")

def recv_varint(sock):
    value = 0
    shift = 0
    while True:
        raw = sock.recv(1)
        if not raw:
            raise ConnectionError("Socket closed while reading varint")
        byte = raw[0]
        value |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            return value
        shift += 7
        if shift > 35:
            raise ValueError("Varint too big")

def recv_exact(sock, length):
    data = b""
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise ConnectionError("Socket closed while reading data")
        data += chunk
    return data

def recv_mc_string(sock):
    length = recv_varint(sock)
    raw = recv_exact(sock, length)
    return raw.decode("utf-8", errors="ignore")

def read_varint_from_bytes(buf, pos):
    value = 0
    shift = 0
    while True:
        if pos >= len(buf):
            raise ValueError("Buffer ended while reading varint")
        byte = buf[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            break
        shift += 7
        if shift > 35:
            raise ValueError("Varint too big in buffer")
    return value, pos

def read_mc_string_from_bytes(buf, pos):
    length, pos = read_varint_from_bytes(buf, pos)
    end = pos + length
    if end > len(buf):
        raise ValueError("String length outside buffer")
    raw = buf[pos:end]
    pos = end
    return raw.decode("utf-8", errors="ignore"), pos

class EncryptedSocket:
    def __init__(self, sock, shared_secret):
        backend = default_backend()
        self.sock = sock
        self.decryptor = Cipher(
            algorithms.AES(shared_secret),
            modes.CFB8(shared_secret),
            backend=backend
        ).decryptor()
        self.encryptor = Cipher(
            algorithms.AES(shared_secret),
            modes.CFB8(shared_secret),
            backend=backend
        ).encryptor()

    def recv(self, length):
        data = self.sock.recv(length)
        return self.decryptor.update(data) if data else data

    def sendall(self, data):
        self.sock.sendall(self.encryptor.update(data))

    def close(self):
        self.sock.close()

def send_mc_packet(sock, body):
    sock.sendall(varint_encode(len(body)) + body)

def unpack_login_packet(packet_data, compression_threshold):
    if compression_threshold >= 0:
        data_len, pos = read_varint_from_bytes(packet_data, 0)
        if data_len == 0:
            return packet_data[pos:]
        return zlib.decompress(packet_data[pos:])
    return packet_data

def offline_uuid_nodash(name):
    h = hashlib.md5()
    h.update(b"OfflinePlayer:")
    h.update(name.encode("utf-8"))
    data = bytearray(h.digest())
    data[6] = (data[6] & 0x0F) | 0x30
    data[8] = (data[8] & 0x3F) | 0x80
    return uuid.UUID(bytes=bytes(data)).hex

# --- Modloader (Forge / NeoForge) detection ---------------------------------
# NeoForge/Forge servers advertise themselves in the status ping
# ("modinfo"/"forgeData"/"isModded" keys, or "neoforge"/"forge" in the
# version string) and later via login plugin channels ("neoforge:", "forge:",
# "fml:"). We surface a warning so modded hits are not mistaken for vanilla.

def detect_modloader_from_status(data, version_hint=""):
    """Return (loader, detail) e.g. ("NeoForge", "...") or (None, "")."""
    try:
        blob = json.dumps(data or {}).lower()
    except Exception:
        blob = ""
    version_name = ""
    try:
        version_name = str(((data or {}).get("version") or {}).get("name") or "")
    except Exception:
        version_name = ""
    if not version_name and version_hint:
        version_name = str(version_hint or "")
    low_version = (version_name or "").lower()

    has_neoforge_marker = (
        "neoforge" in blob or "neoforge" in low_version
    )
    if has_neoforge_marker:
        detail = version_name or "status lists NeoForge markers"
        return "NeoForge", detail

    modinfo = (data or {}).get("modinfo") if isinstance(data, dict) else None
    forge_data = (data or {}).get("forgeData") if isinstance(data, dict) else None
    is_modded = (data or {}).get("isModded") if isinstance(data, dict) else None
    if isinstance(modinfo, dict):
        mod_type = str(modinfo.get("type") or "")
        mods = modinfo.get("modList") or modinfo.get("mods") or []
        try:
            n = len(mods)
        except Exception:
            n = 0
        return "Forge", f"{mod_type or 'modinfo'} ({n} mods) {version_name}".strip()
    if forge_data is not None:
        return "Forge", f"forgeData present {version_name}".strip()
    if is_modded is True:
        return "Modded", f"isModded {version_name}".strip()

    for marker, loader in (
        ("forge", "Forge"),
        ("fml", "Forge"),
        ("fabric", "Fabric"),
        ("quilt", "Quilt"),
        ("paper", "Paper"),
        ("spigot", "Spigot"),
        ("bungeecord", "BungeeCord"),
        ("velocity", "Velocity"),
    ):
        if marker in low_version or (blob and f'"{marker}"' in blob):
            return loader, version_name or f"status mentions {marker}"
    if version_hint and "neoforge" in str(version_hint).lower():
        return "NeoForge", str(version_hint)
    return None, ""


def detect_modloader_from_channel(channel):
    low = (channel or "").lower()
    if "neoforge" in low:
        return "NeoForge", channel
    if "forge" in low or low.startswith("fml:") or low == "fml":
        return "Forge", channel
    return None, ""


def mod_warning_text(loader, detail=""):
    detail = (detail or "").strip()
    base = f"{loader} modded server"
    if detail and detail.lower() != loader.lower():
        short = detail if len(detail) <= 80 else detail[:77] + "..."
        return f"WARNING: {base} ({short}) - client mods required"
    return f"WARNING: {base} - client mods required"


def append_mod_warning(message, mod_warning):
    if not mod_warning:
        return message or ""
    if mod_warning.lower() in (message or "").lower():
        return message or ""
    return f"{message} [{mod_warning}]" if message else f"[{mod_warning}]"


def get_server_status_full(host, port=25565, proxy=None):
    """Status ping returning (protocol, sample_names, sample_hint, status_data).

    status_data is the raw status JSON dict (or {} on failure). This never
    touches Mojang auth; it is safe for cracked servers.
    """
    sock = None
    try:
        sock = open_connection(host, port, proxy=proxy, timeout=4)
        handshake = (
            varint_encode(0) +
            varint_encode(DEFAULT_STATUS_PROTOCOL) +
            write_string(host) +
            struct.pack(">H", port) +
            varint_encode(1)
        )
        sock.sendall(varint_encode(len(handshake)) + handshake)
        sock.sendall(varint_encode(1) + b"\x00")

        _ = recv_varint(sock)
        _ = recv_varint(sock)
        json_length = recv_varint(sock)
        status_json = recv_bounded(sock, json_length, MAX_STATUS_RESPONSE_BYTES).decode("utf-8", errors="ignore")
        data = json.loads(status_json)
        if not isinstance(data, dict):
            data = {}

        proto = data.get("version", {}).get("protocol", DEFAULT_STATUS_PROTOCOL)

        sample_names = []
        sample_hint = None
        players = data.get("players") or {}
        samples = players.get("sample") or []
        any_sample = False
        any_offline_match = False
        for player in samples:
            name = player.get("name")
            pid = player.get("id")
            if not name or not pid:
                continue
            any_sample = True
            sample_names.append(name)
            offline_id = offline_uuid_nodash(name)
            reported = pid.replace("-", "").lower()
            if offline_id == reported:
                any_offline_match = True

        if any_sample:
            sample_hint = True if any_offline_match else False
        else:
            sample_hint = None

        return proto, sample_names, sample_hint, data
    except Exception:
        return DEFAULT_STATUS_PROTOCOL, [], None, {}
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def get_server_status_info(host, port=25565, proxy=None):
    proto, sample_names, sample_hint, _data = get_server_status_full(host, port, proxy=proxy)
    return proto, sample_names, sample_hint

def get_server_protocol(host, port=25565):
    proto, _, _ = get_server_status_info(host, port)
    return proto

def build_login_start(username, protocol):
    body = varint_encode(0)
    body += write_string(username)
    if protocol >= 759:
        uid = uuid.uuid4()
        body += uid.int.to_bytes(16, "big")
    return body

def pick_username(sample_names):
    valid = [name for name in sample_names if USERNAME_PATTERN.match(name)]
    if valid:
        return random.choice(valid)
    return "Notch"

def login_probe(host, port=25565):
    protocol, sample_names, sample_offline_hint = get_server_status_info(host, port)
    username = pick_username(sample_names)
    sock = None
    saw_encryption_request = False
    compression_threshold = -1

    try:
        sock = socket.create_connection((host, port), timeout=6)
        sock.settimeout(2.0)

        handshake = (
            varint_encode(0) +
            varint_encode(protocol) +
            write_string(host) +
            struct.pack(">H", port) +
            varint_encode(2)
        )
        sock.sendall(varint_encode(len(handshake)) + handshake)
        login_start = build_login_start(username, protocol)
        sock.sendall(varint_encode(len(login_start)) + login_start)

        while True:
            packet_length = recv_varint(sock)
            if packet_length > PACKET_LENGTH_LIMIT_LOGIN:
                raise ValueError("Packet too large")
            packet_data = recv_exact(sock, packet_length)

            if compression_threshold >= 0:
                data_len, pos = read_varint_from_bytes(packet_data, 0)
                if data_len == 0:
                    buf = packet_data[pos:]
                else:
                    buf = zlib.decompress(packet_data[pos:])
            else:
                buf = packet_data
                pos = 0

            packet_id, pos = read_varint_from_bytes(buf, 0)

            if packet_id == 0x03:
                threshold, _ = read_varint_from_bytes(buf, pos)
                compression_threshold = threshold
                continue

            if packet_id == 0x01:  # Encryption Request
                saw_encryption_request = True
                if sample_offline_hint is True:
                    return True, "CRACKED by players.sample UUID (but got Encryption Request; mixed signals)"
                return False, "ONLINE-MODE (Mojang auth required)"

            if packet_id == 0x02:  # Login Success
                msg = f"CRACKED (offline-mode) - login success as {username}"
                if sample_offline_hint is True:
                    msg += " [players.sample also indicates offline-mode]"
                elif sample_offline_hint is False:
                    msg += " [players.sample looks online-mode]"
                return True, msg

            if packet_id == 0x04:  # Login Plugin Request
                is_offline = (not saw_encryption_request) or (sample_offline_hint is True)
                if is_offline:
                    return True, "CRACKED (offline-mode behind proxy/login plugin)"
                return False, "ONLINE-MODE + login plugin (secure/proxied)"

            if packet_id == 0x00:  # Disconnect
                reason, _ = read_mc_string_from_bytes(buf, pos)
                low = (reason or "").lower()
                clean = sanitize_motd(reason).lower()
                if "whitelist" in clean or "white list" in clean:
                    return True, f"CRACKED (whitelist message: {sanitize_motd(reason)})"
                if "outdated client" in low or "outdated server" in low:
                    return None, "VERSION MISMATCH (outdated client or server)"
                if "rate" in low and "limit" in low:
                    return None, "RATE-LIMITED, slow down probes"

                if sample_offline_hint is True:
                    return True, f"CRACKED by players.sample UUID (disconnect: {reason})"
                if sample_offline_hint is False and saw_encryption_request:
                    return False, f"ONLINE-MODE (disconnect: {reason})"
                return None, f"UNKNOWN MODE (disconnect: {reason})"

            # Unknown login packets are ignored.

    except socket.timeout:
        if sample_offline_hint is True:
            return True, "CRACKED by players.sample UUID, but login probe timed out"
        return None, "Timed out waiting for login response"
    except Exception as exc:
        if sample_offline_hint is True:
            return True, f"CRACKED by players.sample UUID, but login probe errored: {str(exc)[:60]}"
        return None, f"Error: {str(exc)[:80]}"
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass

def is_cracked_server(host, port=25565):
    """
    Returns (result, message) where result is True/False/None (cracked/online/unknown).
    """
    return login_probe(host, port)

def build_authenticated_login_start(account, protocol):
    body = varint_encode(0)
    body += write_string(account.get("name", "Player")[:16])
    if protocol >= 759:
        try:
            profile_uuid = uuid.UUID(hex=account.get("uuid", ""))
        except Exception:
            profile_uuid = uuid.uuid4()
        body += profile_uuid.int.to_bytes(16, "big")
    return body

def parse_disconnect_reason(buf, pos):
    try:
        reason, _ = read_mc_string_from_bytes(buf, pos)
        return minecraft_text_component_to_plain(reason)
    except Exception:
        return ""

def read_login_plugin_channel(buf, pos):
    """Extract the channel string from a Login Plugin Request (0x04) packet."""
    try:
        _msg_id, pos = read_varint_from_bytes(buf, pos)
        channel, _ = read_mc_string_from_bytes(buf, pos)
        return channel or ""
    except Exception:
        return ""


def _throttle_online_whitelist_probe(account=None):
    """Space out online-mode (Mojang) probes by WHITELIST_PROBE_DELAY.

    Cracked/offline probes never call this. Spacing is per account, so bulk
    scans rotating many tokens stay parallel while each individual account
    keeps the same pacing as the old serial loop (which also protects that
    account from Mojang sessionserver rate limits).
    """
    if WHITELIST_PROBE_DELAY <= 0:
        return
    try:
        key = _account_key(account) if account else ""
    except Exception:
        key = ""
    if not key:
        key = "shared"
    with _WHITELIST_ONLINE_THROTTLE_LOCK:
        last = _WHITELIST_LAST_ONLINE_PROBE.get(key, 0.0)
        now = time.monotonic()
        wait = WHITELIST_PROBE_DELAY - (now - last)
        if wait > 0:
            time.sleep(wait)
            now = time.monotonic()
        _WHITELIST_LAST_ONLINE_PROBE[key] = now


def _compute_mod_warning(status_data, version_hint):
    """NeoForge/Forge warning from status data and/or the version string."""
    try:
        loader, detail = detect_modloader_from_status(status_data or {}, version_hint or "")
        if loader:
            return mod_warning_text(loader, detail)
    except Exception:
        pass
    if version_hint and "neoforge" in str(version_hint).lower():
        return mod_warning_text("NeoForge", str(version_hint))
    return ""


def whitelist_login_probe(host, port=25565, account=None, protocol=None, proxy=None, version_hint=""):
    """Whitelist check using exactly ONE login connection to the server.

    Paper and similar servers kick rapid reconnects ("Connection throttled"),
    so this probe deliberately opens a single game connection per attempt:
      - The protocol comes from the scan entry (or a remembered earlier ping).
        A status ping — a different, non-throttled connection type — is only
        used when the protocol is unknown, and once more to recover from a
        version-mismatch disconnect (stale protocol).
      - One Login Start is sent: account credentials when the account has a
        UUID (offline servers simply accept it — no Mojang involved),
        otherwise a random offline name.
      - Encryption Request means online-mode: the Mojang session join runs on
        this same connection (still spaced per account by WHITELIST_PROBE_DELAY
        and still with the original 429 backoff, except the cooldown sleep
        never holds the game connection open).
      - Anything else is answered without ever contacting Mojang.
    NeoForge/Forge warnings come from the version hint, login plugin channels
    and disconnect text (plus status data when a status ping was needed).
    Returns (result, message) with result True/False/None.
    """
    ip_port = f"{host}:{port}"
    status_data = {}
    did_fresh_status = False
    if protocol is None:
        protocol = _cached_protocol(ip_port)
    if protocol is None:
        try:
            protocol, _, _, status_data = get_server_status_full(host, port, proxy=proxy)
        except Exception:
            protocol = DEFAULT_STATUS_PROTOCOL
            status_data = {}
        if protocol is not None:
            _remember_protocol(ip_port, protocol)
        did_fresh_status = True
    try:
        protocol = int(protocol)
    except Exception:
        protocol = DEFAULT_STATUS_PROTOCOL
    mod_warning = _compute_mod_warning(status_data, version_hint)

    def _single_login_attempt(current_protocol):
        """Open the single login connection.

        Returns (result, message, action) where action is "done",
        "retry_rate" (Mojang 429: caller sleeps with no open connection, then
        retries with a fresh one) or "retry_version" (stale protocol: caller
        refreshes via status, then retries once).
        """
        use_auth_start = bool(account is not None and account.get("uuid"))
        # A second connection is only ever opened for UUID-less imports
        # (USERNAME:TOKEN never probed) that turn out to be online-mode:
        # resolve the profile, then reconnect once with a proper Login Start.
        for _conn_index in range(2):
            if use_auth_start:
                login_start = build_authenticated_login_start(account, current_protocol)
                login_name = (account.get("name") or "Player")[:16] or "Player"
            else:
                login_name = "Player" + str(random.randint(1000, 9999))
                login_start = build_login_start(login_name, current_protocol)
            sock = None
            compression_threshold = -1
            encrypted = False
            mojang_used = False
            saw_encryption = False
            reconnect_needed = False
            try:
                sock = open_connection(host, port, proxy=proxy, timeout=6)
                sock.settimeout(2.5)
                handshake = (
                    varint_encode(0) +
                    varint_encode(current_protocol) +
                    write_string(host) +
                    struct.pack(">H", port) +
                    varint_encode(2)
                )
                send_mc_packet(sock, handshake)
                send_mc_packet(sock, login_start)

                while True:
                    packet_length = recv_varint(sock)
                    if packet_length > PACKET_LENGTH_LIMIT_LOGIN:
                        raise ValueError("Packet too large")
                    packet_data = recv_exact(sock, packet_length)
                    buf = unpack_login_packet(packet_data, compression_threshold)
                    packet_id, pos = read_varint_from_bytes(buf, 0)

                    if packet_id == 0x03:
                        compression_threshold, _ = read_varint_from_bytes(buf, pos)
                        continue

                    if packet_id == 0x01 and not encrypted:
                        saw_encryption = True
                        server_id, pos = read_mc_string_from_bytes(buf, pos)
                        public_key_bytes, pos = read_mc_byte_array_from_bytes(buf, pos)
                        verify_token, pos = read_mc_byte_array_from_bytes(buf, pos)
                        if account is None:
                            return None, append_mod_warning("No Minecraft account selected (online-mode server needs Mojang auth)", mod_warning), "done"
                        if not account.get("uuid"):
                            resolved, ok, detail = probe_account(account)
                            if not (ok and resolved.get("uuid")):
                                return None, append_mod_warning(f"Token profile lookup failed: {detail}", mod_warning), "done"
                            account.clear()
                            account.update(resolved)
                            upsert_mc_accounts([account], active_uuid=account.get("uuid"))
                            use_auth_start = True
                            reconnect_needed = True
                            _throttle_online_whitelist_probe(account)
                            break
                        if not _CRYPTO_AVAILABLE:
                            return None, append_mod_warning("cryptography package is not available", mod_warning), "done"
                        _throttle_online_whitelist_probe(account)
                        public_key = load_der_public_key(public_key_bytes, backend=default_backend())
                        shared_secret = os.urandom(16)
                        server_hash = minecraft_sha1_hexdigest(
                            server_id.encode("ascii", errors="ignore"),
                            shared_secret,
                            public_key_bytes
                        )
                        try:
                            # Fail fast on 429: the caller sleeps the cooldown
                            # with no game connection open, then retries with
                            # a fresh single connection.
                            ensure_minecraft_session_join(account, server_hash, cooldown=0, retries=0)
                        except urllib.error.HTTPError as exc:
                            try:
                                detail = exc.read().decode("utf-8", errors="replace")[:180]
                            except Exception:
                                detail = ""
                            return None, append_mod_warning(f"Mojang join failed: HTTP {exc.code}" + (f": {detail}" if detail else ""), mod_warning), "done"
                        except MinecraftSessionError as exc:
                            if "rate limited" in str(exc).lower():
                                return None, f"Mojang sessionserver rate limited join ({exc})", "retry_rate"
                            return None, append_mod_warning(f"Auth/session failed before server login ({exc})", mod_warning), "done"
                        mojang_used = True
                        encrypted_secret = public_key.encrypt(shared_secret, rsa_padding.PKCS1v15())
                        encrypted_token = public_key.encrypt(verify_token, rsa_padding.PKCS1v15())
                        response = varint_encode(0x01)
                        response += varint_encode(len(encrypted_secret)) + encrypted_secret
                        response += varint_encode(len(encrypted_token)) + encrypted_token
                        send_mc_packet(sock, response)
                        sock = EncryptedSocket(sock, shared_secret)
                        encrypted = True
                        continue

                    if packet_id == 0x00:
                        reason = parse_disconnect_reason(buf, pos)
                        low = reason.lower()
                        if "whitelist" in low or "white list" in low or "not whitelisted" in low:
                            msg = f"WHITELISTED ({reason})"
                            if not mojang_used and not saw_encryption:
                                msg += " [offline-mode, no Mojang auth used]"
                            return True, append_mod_warning(msg, mod_warning), "done"
                        if "throttl" in low:
                            return None, append_mod_warning(f"Connection throttled, retry later ({reason})", mod_warning), "done"
                        if "outdated client" in low or "outdated server" in low:
                            return None, append_mod_warning(f"Version mismatch ({reason})", mod_warning), "retry_version"
                        if (
                            "multiplayer is disabled" in low or
                            "authentication" in low or
                            "invalid session" in low or
                            "verify username" in low or
                            "unverified_username" in low
                        ):
                            return None, append_mod_warning(f"Auth/session rejected ({reason})", mod_warning), "done"
                        # Modded servers often kick here with mod/channel mismatch text.
                        extra_warning = mod_warning
                        for marker in ("neoforge", "forge", "fml", "mod"):
                            if marker in low and marker not in extra_warning.lower():
                                extra_warning = append_mod_warning("", mod_warning_text("NeoForge" if marker == "neoforge" else "Forge", reason)) or extra_warning
                                break
                        msg = f"Not Whitelisted ({reason})"
                        if not mojang_used and not saw_encryption:
                            msg += " [offline-mode, no Mojang auth used]"
                        return False, append_mod_warning(msg, extra_warning), "done"

                    if packet_id == 0x02:
                        if saw_encryption:
                            return False, append_mod_warning("Not Whitelisted (login accepted)", mod_warning), "done"
                        msg = f"Not Whitelisted (offline login accepted as {login_name}) [offline-mode, no Mojang auth used]"
                        return False, append_mod_warning(msg, mod_warning), "done"

                    if packet_id == 0x04:
                        channel = read_login_plugin_channel(buf, pos)
                        warn = mod_warning
                        loader, _d = detect_modloader_from_channel(channel)
                        if loader:
                            warn = append_mod_warning(warn, mod_warning_text(loader, channel))
                        msg = f"Not Whitelisted (login plugin request{': ' + channel if channel else ''}; no immediate whitelist kick)"
                        if not mojang_used and not saw_encryption:
                            msg += " [offline-mode, no Mojang auth used]"
                        return False, append_mod_warning(msg, warn), "done"

                    if packet_id == 0x05:
                        msg = "Not Whitelisted (entered configuration; no immediate whitelist kick)"
                        if not mojang_used and not saw_encryption:
                            msg += " [offline-mode, no Mojang auth used]"
                        return False, append_mod_warning(msg, mod_warning), "done"

            except socket.timeout:
                return None, append_mod_warning("Timed out during whitelist probe", mod_warning), "done"
            except Exception as exc:
                return None, append_mod_warning(f"Whitelist probe error: {str(exc)[:80]}", mod_warning), "done"
            finally:
                if sock:
                    try:
                        sock.close()
                    except Exception:
                        pass
            if reconnect_needed:
                continue
            return None, append_mod_warning("Whitelist probe ended unexpectedly", mod_warning), "done"
        return None, append_mod_warning("Minecraft profile UUID is missing; test the token first", mod_warning), "done"

    rate_attempt = 0
    while True:
        result, message, action = _single_login_attempt(protocol)
        if action == "retry_rate" and rate_attempt < MOJANG_JOIN_RETRIES:
            # Same budget as the old join retries, but the cooldown sleep
            # happens with no game connection open, and the retry uses one
            # fresh single connection (safe for Paper-style throttles).
            rate_attempt += 1
            if MOJANG_RATE_LIMIT_COOLDOWN > 0:
                time.sleep(MOJANG_RATE_LIMIT_COOLDOWN)
            continue
        if action == "retry_version" and not did_fresh_status:
            try:
                protocol, _, _, status_data = get_server_status_full(host, port, proxy=proxy)
                _remember_protocol(ip_port, protocol)
                try:
                    protocol = int(protocol)
                except Exception:
                    protocol = DEFAULT_STATUS_PROTOCOL
                mod_warning = _compute_mod_warning(status_data, version_hint)
                did_fresh_status = True
            except Exception:
                return result, message
            continue
        return result, message

def _probe_whitelist_entry(entry, account, proxy=None):
    ip = entry.get("ip")
    if not ip:
        return None, "Missing IP"
    try:
        host, port = split_host_port(ip)
    except ValueError as exc:
        return None, str(exc)
    protocol = entry.get("protocol")
    try:
        protocol = int(protocol) if protocol is not None else None
    except Exception:
        protocol = None
    version_hint = entry.get("version", "") or ""
    return whitelist_login_probe(host, port, account=account, protocol=protocol, proxy=proxy, version_hint=version_hint)

def whitelist_result_label(result, message):
    if result is True:
        base = "Whitelisted"
    elif result is False:
        base = "Not Whitelisted"
    else:
        base = "Unknown"
    detail = sanitize_motd(message or "").strip()
    if not detail:
        return base
    # Preserve modloader warnings (e.g. NeoForge) past the truncation limit.
    warnings = []
    for m in re.finditer(r"\[(?:WARNING:[^\]]*|NEOFORGE[^\]]*|FORGE[^\]]*|MODDED[^\]]*)\]", detail, re.IGNORECASE):
        warnings.append(m.group(0))
    for w in warnings:
        detail = detail.replace(w, "").strip()
    detail = re.sub(r"\s{2,}", " ", detail).strip()
    if base == "Not Whitelisted" and detail.lower().startswith("not whitelisted"):
        detail = detail[len("Not Whitelisted"):].strip()
        if detail.startswith(":"):
            detail = detail[1:].strip()
        if detail.startswith("(") and detail.endswith(")"):
            detail = detail[1:-1].strip()
    if len(detail) > 90:
        detail = detail[:87] + "..."
    label = f"{base}: {detail}" if detail else base
    if warnings:
        warn_suffix = " ".join(dict.fromkeys(warnings))
        if warn_suffix.lower() not in label.lower():
            label = f"{label} {warn_suffix}"
    return label

def log_whitelist_probe(entry, result, message, account=None):
    try:
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        ip = entry.get("ip", "")
        protocol = entry.get("protocol", "")
        version = sanitize_motd(entry.get("version", ""))
        account_name = (account or {}).get("name", "")
        token_source = (account or {}).get("token_source", "")
        if result is True:
            status = "WHITELIST"
        elif result is False:
            status = "NOT_WHITELISTED"
        else:
            status = "UNKNOWN"
        line = (
            f"{ts} | {ip} | protocol={protocol} | version={version} | "
            f"account={account_name} | token={token_source} | {status} | "
            f"{minecraft_text_component_to_plain(message or '')}\n"
        )
        with _WHITELIST_LOG_LOCK:
            with open(WHITELIST_LOG_FILE, "a", encoding="utf-8") as f:
                f.write(line)
    except Exception:
        pass

def open_whitelist_log_file(parent=None):
    try:
        if not os.path.exists(WHITELIST_LOG_FILE):
            with open(WHITELIST_LOG_FILE, "w", encoding="utf-8") as f:
                f.write("")
        if os.name == "nt":
            os.startfile(os.path.abspath(WHITELIST_LOG_FILE))
        else:
            q_info(parent, "Whitelist Log", os.path.abspath(WHITELIST_LOG_FILE))
    except Exception as exc:
        if parent is not None:
            q_error(parent, "Whitelist Log", f"Could not open log: {exc}")

def check_selected_whitelist(parent, tree):
    """Manually probe the currently selected result rows.

    Cracked (offline-mode) servers are checked without any Minecraft account;
    only online-mode servers need the active token for Mojang auth.
    (Qt port: identical logic, QMessageBox via qt_helpers.)
    """
    account = get_active_mc_account()
    selected = tree.selection()
    if not selected:
        q_info(parent, "Check Whitelist", "Select one or more server rows first.")
        return
    columns = list(tree["columns"])
    if "whitelist" not in columns:
        q_info(parent, "Check Whitelist", "This result view has no whitelist column.")
        return
    entries = []
    for iid in selected:
        values = tree.item(iid, "values")
        row = dict(zip(columns, values))
        if row.get("ip"):
            entries.append({"ip": row["ip"], "version": row.get("version", ""), "protocol": row.get("protocol")})
            tree.set(iid, "whitelist", "Queued")
    if not entries:
        return
    def on_update(entry, result, message):
        label = whitelist_result_label(result, message)
        ip = entry.get("ip")
        for iid in tree.get_children(""):
            vals = tree.item(iid, "values")
            if vals and vals[columns.index("ip")] == ip:
                parent.after(0, lambda i=iid, v=label: tree.set(i, "whitelist", v))
                break
    def progress(done, total):
        parent.after(0, lambda: setattr(parent, "_whitelist_manual_status", f"Whitelist check: {done}/{total}"))
    run_whitelist_verifier_async(entries, account, on_update, progress_cb=progress)

def check_selected_cracked(parent, tree):
    """Manually probe the currently selected result rows for offline-mode.
    (Qt port: identical logic, QMessageBox via qt_helpers.)"""
    selected = tree.selection()
    if not selected:
        q_info(parent, "Check Cracked", "Select one or more server rows first.")
        return
    columns = list(tree["columns"])
    if "cracked" not in columns:
        q_info(parent, "Check Cracked", "This result view has no cracked column.")
        return
    entries = []
    for iid in selected:
        values = tree.item(iid, "values")
        row = dict(zip(columns, values))
        if row.get("ip"):
            entries.append({"ip": row["ip"]})
            tree.set(iid, "cracked", "Queued")
    if not entries:
        return
    def on_update(entry, result, message, was_cached):
        if was_cached or result is True:
            label = "Yes (cached)" if was_cached else "Yes"
        elif result is False:
            label = "No"
        else:
            label = "Unknown"
        ip = entry.get("ip")
        for iid in tree.get_children(""):
            vals = tree.item(iid, "values")
            if vals and vals[columns.index("ip")] == ip:
                parent.after(0, lambda i=iid, v=label: tree.set(i, "cracked", v))
                break
    def progress(done, total):
        try:
            if hasattr(parent, "set_status"):
                parent.after(0, lambda d=done, t=total: parent.set_status(f"Cracked check: {d}/{t}"))
        except Exception:
            pass
    run_cracked_verifier_async(entries, on_update, progress_cb=progress)

def run_whitelist_verifier_async(entries, account, callback, progress_cb=None, workers=None):
    """Whitelist probes: cracked answers fast, online-mode keeps its delay.

    Cracked (offline-mode) servers are answered by the offline-first probe
    without Mojang auth, so they run fully parallel with no throttle. Only
    online-mode servers take the Mojang path, which is still spaced by
    WHITELIST_PROBE_DELAY with the original sessionserver 429 backoff.
    """
    # Proxy mode: route through working proxies and rotate accounts in parallel.
    if _WHITELIST_USE_PROXIES:
        proxies = get_working_proxies()
        accounts = get_all_mc_accounts() or [a for a in [account] if a]
        if proxies and (accounts or True):
            def adapted(entry, result, message, acc=None, proxy=None):
                callback(entry, result, message)
            run_bulk_whitelist_verifier_async(entries, accounts, proxies, adapted, progress_cb=progress_cb, workers=workers)
            return
    if not entries:
        return
    total = len(entries)
    try:
        max_workers = int(workers) if workers else 0
    except Exception:
        max_workers = 0
    if max_workers < 1:
        max_workers = max(1, min(WHITELIST_VERIFY_WORKERS, total))
    lock = threading.Lock()
    counter = {"done": 0}

    def _one(entry):
        try:
            result, message = _probe_whitelist_entry(entry, account)
        except Exception as exc:
            result, message = None, str(exc)
        log_whitelist_probe(entry, result, message, account=account)
        try:
            callback(entry, result, message)
        except Exception:
            pass
        with lock:
            counter["done"] += 1
            done = counter["done"]
        if progress_cb:
            try:
                progress_cb(done, total)
            except Exception:
                pass

    def run():
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(_one, entry) for entry in entries]
            for fut in as_completed(futures):
                try:
                    fut.result()
                except Exception:
                    pass

    threading.Thread(target=run, daemon=True).start()

def _is_token_auth_failure(message):
    """True when a whitelist probe failed because the account token was rejected
    by Mojang (HTTP 401/403) and could not be refreshed — i.e. the token is bad
    and should be excluded from the rest of the scan."""
    low = (message or "").lower()
    if "auth/session failed" in low:
        return True
    if "session token rejected" in low:
        return True
    if "invalid session" in low or "unverified_username" in low:
        return True
    return bool(re.search(r"mojang join failed: http (401|403)", low))

def run_bulk_whitelist_verifier_async(entries, accounts, proxies, callback, progress_cb=None, workers=None):
    """
    Run whitelist probes in parallel, cycling through accounts and proxies to
    avoid rate limiting. Parallelism is bounded by the number of working proxies
    (one probe connection per proxy). Each probe uses a different account on a
    rotating basis so no single account gets hammered by Mojang's sessionserver.
    When a probe fails with a Mojang 401/403 token rejection, that token is
    excluded for the rest of the scan and the SAME server is retried with a
    different token.
    callback(entry, result, message, account, proxy) invoked from worker threads.
    """
    usable = [p for p in (proxies or []) if p.get("working") is not False]
    working_proxies = [p for p in usable if p.get("working") is True]
    if not working_proxies:
        working_proxies = usable  # no pre-test needed; untested proxies are used as-is
    accounts = [a for a in (accounts or []) if a and a.get("access_token")]
    if not accounts:
        accounts = [a for a in [get_active_mc_account()] if a]
    if not entries:
        return
    total = len(entries)
    if workers is None or workers < 1:
        workers = max(1, len(working_proxies)) if working_proxies else WHITELIST_VERIFY_WORKERS
    lock = threading.Lock()
    counter = {"done": 0}
    excluded = set()            # account keys rejected by Mojang -> skip for rest of scan
    account_lock = threading.Lock()
    account_counter = {"idx": 0}

    def _next_account(local_tried):
        """Pick the next account, skipping excluded/bad tokens and ones already tried."""
        with account_lock:
            n = len(accounts)
            for i in range(n):
                acc = accounts[(account_counter["idx"] + i) % n]
                key = _account_key(acc)
                if key in excluded or key in local_tried:
                    continue
                account_counter["idx"] += 1
                return acc
        return None

    def worker_loop(worker_id):
        proxy = working_proxies[worker_id % len(working_proxies)] if working_proxies else None
        for idx in range(worker_id, total, workers):
            entry = entries[idx]
            account_used = None
            result, message = None, ""
            local_tried = set()
            if not accounts:
                # No tokens at all: offline (cracked) servers still resolve
                # without Mojang auth; online-mode hits report missing auth.
                try:
                    result, message = _probe_whitelist_entry(entry, None, proxy=proxy)
                except Exception as exc:
                    result, message = None, str(exc)
            else:
                while True:
                    account = _next_account(local_tried)
                    if account is None:
                        if result is None:
                            result, message = None, "No usable tokens left (all excluded for auth failure)"
                        break
                    key = _account_key(account)
                    local_tried.add(key)
                    account_used = account
                    try:
                        result, message = _probe_whitelist_entry(entry, account, proxy=proxy)
                    except Exception as exc:
                        result, message = None, str(exc)
                    if _is_token_auth_failure(message):
                        # token is bad for Mojang auth -> exclude it and retry this
                        # same server with a different token.
                        with account_lock:
                            excluded.add(key)
                        continue
                    break
            log_whitelist_probe(entry, result, message, account=account_used)
            try:
                callback(entry, result, message, account_used, proxy)
            except Exception:
                pass
            with lock:
                counter["done"] += 1
                done = counter["done"]
            if progress_cb:
                try:
                    progress_cb(done, total)
                except Exception:
                    pass

    def run():
        try:
            with ThreadPoolExecutor(max_workers=workers) as executor:
                futures = [executor.submit(worker_loop, i) for i in range(workers)]
                for fut in as_completed(futures):
                    fut.result()
        except Exception:
            pass

    if entries:
        threading.Thread(target=run, daemon=True).start()

def run_status_scan_async(servers, callback, progress_cb=None, proxy=None, workers=400):
    """
    Ping a list of server strings ('ip:port') in parallel to find live hosts.
    Uses the real IP by default, or routes through a single proxy if provided.
    callback(server, result_dict_or_None) per completed host; progress_cb(done, total).
    """
    if not servers:
        return
    total = len(servers)
    lock = threading.Lock()
    counter = {"done": 0}

    def run():
        with ThreadPoolExecutor(max_workers=max(1, min(workers, total))) as executor:
            futures = [executor.submit(_status_scan_worker, s, proxy) for s in servers]
            for fut in as_completed(futures):
                try:
                    server, result = fut.result()
                except Exception:
                    server, result = "", None
                try:
                    callback(server, result)
                except Exception:
                    pass
                with lock:
                    counter["done"] += 1
                    done = counter["done"]
                if progress_cb:
                    try:
                        progress_cb(done, total)
                    except Exception:
                        pass

    threading.Thread(target=run, daemon=True).start()

def _status_scan_worker(server, proxy):
    try:
        return server, ping_server(server, proxy=proxy)
    except Exception:
        return server, None

def parse_ports(text):
    ports = []
    for part in re.split(r"[,\s]+", text.strip()):
        if not part:
            continue
        if "-" in part:
            start, end = part.split("-", 1)
            try:
                start_i, end_i = int(start), int(end)
            except ValueError:
                continue
            for port in range(max(1, start_i), min(65535, end_i) + 1):
                ports.append(port)
        else:
            try:
                port = int(part)
            except ValueError:
                continue
            if 1 <= port <= 65535:
                ports.append(port)
    return list(dict.fromkeys(ports)) or [25565]

def fetch_asn_prefixes(asn):
    match = re.fullmatch(r"AS?(\d+)", str(asn).strip(), re.IGNORECASE)
    if not match:
        raise ValueError(f"Invalid ASN: {asn}")
    asn_num = match.group(1)
    url = f"https://api.bgpview.io/asn/{asn_num}/prefixes"
    req = urllib.request.Request(url, headers={"User-Agent": "MC-Scanner"})
    with urllib.request.urlopen(req, timeout=12) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    prefixes = []
    for item in data.get("data", {}).get("ipv4_prefixes", []) or []:
        prefix = item.get("prefix")
        if prefix:
            prefixes.append(prefix)
    if not prefixes:
        raise RuntimeError(f"No IPv4 prefixes returned for AS{asn_num}")
    return prefixes

def expand_ip_range(start_ip, end_ip, remaining):
    start = ipaddress.ip_address(start_ip.strip())
    end = ipaddress.ip_address(end_ip.strip())
    if start.version != 4 or end.version != 4 or int(end) < int(start):
        return []
    out = []
    current = int(start)
    while current <= int(end) and len(out) < remaining:
        out.append(str(ipaddress.ip_address(current)))
        current += 1
    return out

def expand_scan_targets(target_text, ports, max_hosts=NETWORK_SCAN_MAX_HOSTS):
    hosts = []
    seen = set()

    def add_host(host):
        if len(hosts) >= max_hosts:
            return
        if host not in seen:
            seen.add(host)
            hosts.append(host)

    tokens = _split_target_tokens(target_text)

    for token in tokens:
        if len(hosts) >= max_hosts:
            break
        try:
            if re.match(r"^AS?\d+$", token, re.I):
                for prefix in fetch_asn_prefixes(token):
                    if len(hosts) >= max_hosts:
                        break
                    try:
                        net = ipaddress.ip_network(prefix, strict=False)
                    except ValueError:
                        continue
                    for ip in net.hosts():
                        add_host(str(ip))
                        if len(hosts) >= max_hosts:
                            break
                continue
            if "-" in token and "/" not in token:
                left, right = token.split("-", 1)
                for ip in expand_ip_range(left, right, max_hosts - len(hosts)):
                    add_host(ip)
                continue
            if "/" in token:
                net = ipaddress.ip_network(token, strict=False)
                if net.version != 4:
                    continue
                for ip in net.hosts():
                    add_host(str(ip))
                    if len(hosts) >= max_hosts:
                        break
                continue
            host, explicit_port = split_host_port(token) if ":" in token else (token, None)
            ipaddress.ip_address(host)
            add_host(f"{host}:{explicit_port}" if explicit_port else host)
        except Exception:
            continue

    targets = []
    for host in hosts:
        if ":" in host and is_valid_ip_port(host):
            targets.append(host)
        else:
            for port in ports:
                targets.append(f"{host}:{port}")
    return [target for target in dict.fromkeys(targets) if not is_ignored(target)]


# ==================== MASSCAN BACKEND ====================
# Two-phase scan for speed:
#   Phase 1 (masscan): fast SYN scan finds open TCP ports across huge ranges.
#   Phase 2 (Python): Minecraft status handshake (ping_server) only on open ports.
# This avoids a full TCP+handshake per host and is orders of magnitude faster
# than the pure-Python ThreadPool scan for CIDR/ASN sweeps.

def is_masscan_available():
    """True when a masscan binary can be executed."""
    exe = shutil.which("masscan")
    if not exe:
        if MASSCAN_BIN and os.path.isabs(MASSCAN_BIN) and os.path.exists(MASSCAN_BIN):
            exe = MASSCAN_BIN
        else:
            return False
    try:
        proc = subprocess.run(
            [exe, "-V"],
            capture_output=True, text=True, timeout=8
        )
        out = (proc.stdout or "") + (proc.stderr or "")
        return "masscan" in out.lower() or proc.returncode == 0
    except Exception:
        return False


def masscan_status_line():
    exe = shutil.which("masscan")
    if not exe:
        return "masscan: not found (Python fallback)"
    try:
        proc = subprocess.run([exe, "-V"], capture_output=True, text=True, timeout=8)
        out = ((proc.stdout or "") + " " + (proc.stderr or "")).strip().splitlines()
        ver = out[0].strip() if out else "found"
        return f"masscan: {exe} ({ver[:60]})"
    except Exception as exc:
        return f"masscan: {exe} (check failed: {exc})"


def _masscan_count_hosts(spec, cap=MASSCAN_MAX_HOSTS):
    """Estimate host count for a masscan target spec without enumerating.
    cap=None disables the cap."""
    try:
        if "/" in spec:
            net = ipaddress.ip_network(spec, strict=False)
            if net.version != 4:
                return 0
            n = net.num_addresses - 2 if net.num_addresses > 2 else net.num_addresses
            n = max(0, n)
            return n if cap is None else min(n, cap + 1)
        if "-" in spec:
            left, right = spec.split("-", 1)
            start = int(ipaddress.ip_address(left.strip()))
            end = int(ipaddress.ip_address(right.strip()))
            if end < start:
                return 0
            n = end - start + 1
            return n if cap is None else min(n, cap + 1)
        ipaddress.ip_address(spec)
        return 1
    except Exception:
        return 0


_IPV4_RANGE_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})\s*-\s*(\d{1,3}(?:\.\d{1,3}){3})")

def _split_target_tokens(target_text):
    """Split target text on commas, semicolons, spaces and newlines.

    Spaced IPv4 ranges ('10.0.0.1 - 10.0.0.5') are rejoined first so they
    survive as one token; '#' starts a comment.
    """
    text = _IPV4_RANGE_RE.sub(r"\1-\2", target_text or "")
    tokens = []
    for line in text.splitlines():
        line = line.split("#", 1)[0]
        tokens.extend([p for p in re.split(r"[,;\s]+", line.strip()) if p])
    return tokens


def _masscan_estimate_probes(masscan_targets, ports):
    """Total SYN probes masscan will send (hosts x ports), arithmetic only."""
    try:
        nports = len(ports or [25565]) or 1
    except Exception:
        nports = 1
    total = 0
    for spec in masscan_targets or []:
        total += _masscan_count_hosts(spec, cap=None)
    return total * max(1, nports)


def _masscan_estimate_seconds(masscan_targets, ports, rate, wait):
    """Expected sweep duration in seconds (probes/rate + post-scan wait)."""
    try:
        rate = max(1, int(rate))
    except Exception:
        rate = MASSCAN_DEFAULT_RATE
    try:
        wait = max(0, int(wait))
    except Exception:
        wait = MASSCAN_DEFAULT_WAIT
    return _masscan_estimate_probes(masscan_targets, ports) / rate + wait


def _masscan_default_timeout(masscan_targets, ports, rate, wait):
    """Watchdog timeout scaled to the sweep size: expected + wait + margin.

    A fixed timeout killed big sweeps early: a /8 at 10kpps needs ~28min,
    so the old fixed 330s always 'ended' the scan around 20%.
    """
    try:
        expected = _masscan_estimate_seconds(masscan_targets, ports, rate, wait)
    except Exception:
        expected = 0
    return max(120, int(expected + MASSCAN_OUTPUT_TIMEOUT_MARGIN + 60))


def _format_masscan_eta(seconds):
    try:
        seconds = max(0, int(seconds))
    except Exception:
        return ""
    if seconds < 10:
        return ""
    if seconds < 120:
        return f" (~{seconds}s)"
    mins = seconds / 60
    if mins < 90:
        return f" (~{mins:.0f} min)"
    return f" (~{mins / 60:.1f} h)"


def _masscan_note_is_partial(note):
    low = (note or "").lower()
    return "timed out" in low or "partial" in low


def build_masscan_inputs(target_text, ports):
    """Convert GUI target text into masscan ranges + direct ip:port targets.

    Accepts any mix of IPs, CIDRs, start-end ranges, ASNs and hostnames,
    separated by commas, spaces, semicolons or newlines.

    Returns (masscan_targets, direct_targets):
      masscan_targets: list of 'IP', 'CIDR' or 'start-end' strings for masscan.
      direct_targets: list of 'ip:port' strings to ping directly (explicit ports
        outside the scan port list, or entries masscan cannot express).
    Hostnames are resolved to IPs for masscan; unresolvable names are skipped.

    Every valid range is passed through: masscan sweeps huge/multi ranges
    natively (timeout and progress scale with the size), so unlike the
    Python path there is no host budget that could silently drop a range.
    """
    ports = list(dict.fromkeys(int(p) for p in (ports or [25565]) if 1 <= int(p) <= 65535)) or [25565]
    port_set = set(ports)
    masscan_targets = []
    direct_targets = []
    seen_range = set()

    def add_range(spec):
        spec = spec.strip()
        if not spec or spec in seen_range:
            return
        if _masscan_count_hosts(spec, cap=None) <= 0:
            return
        seen_range.add(spec)
        masscan_targets.append(spec)

    def add_direct(ip_port):
        if ip_port not in direct_targets and not is_ignored(ip_port):
            direct_targets.append(ip_port)

    tokens = _split_target_tokens(target_text)

    for token in tokens:
        try:
            if re.match(r"^AS?\d+$", token, re.I):
                try:
                    prefixes = fetch_asn_prefixes(token)
                except Exception:
                    continue
                for prefix in prefixes:
                    try:
                        net = ipaddress.ip_network(prefix, strict=False)
                    except ValueError:
                        continue
                    if net.version != 4:
                        continue
                    add_range(str(net))
                continue
            if "/" in token:
                host_part = token.split("/")[0]
                if ":" in host_part and not host_part.replace(".", "").replace(":", "").strip().isdigit():
                    pass
                try:
                    net = ipaddress.ip_network(token, strict=False)
                except ValueError:
                    continue
                if net.version != 4:
                    continue
                add_range(str(net))
                continue
            if "-" in token and "/" not in token and ":" not in token:
                left, right = token.split("-", 1)
                try:
                    start = ipaddress.ip_address(left.strip())
                    end = ipaddress.ip_address(right.strip())
                except ValueError:
                    continue
                if start.version != 4 or end.version != 4 or int(end) < int(start):
                    continue
                add_range(f"{start}-{end}")
                continue
            if ":" in token:
                host, port_txt = token.rsplit(":", 1)
                host = host.strip()
                try:
                    explicit_port = int(port_txt.strip())
                except ValueError:
                    continue
                if not (1 <= explicit_port <= 65535):
                    continue
                try:
                    ipaddress.ip_address(host)
                    ip_str = host
                except ValueError:
                    try:
                        ip_str = socket.gethostbyname(host)
                    except Exception:
                        continue
                if explicit_port in port_set:
                    add_range(ip_str)
                else:
                    add_direct(f"{ip_str}:{explicit_port}")
                continue
            try:
                ipaddress.ip_address(token)
                add_range(token)
                continue
            except ValueError:
                pass
            try:
                ip_str = socket.gethostbyname(token)
            except Exception:
                continue
            add_range(ip_str)
        except Exception:
            continue

    return masscan_targets, [t for t in dict.fromkeys(direct_targets) if not is_ignored(t)]


def parse_masscan_json_file(path):
    """Parse masscan -oJ output file into ['ip:port', ...]."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = f.read()
    except FileNotFoundError:
        return []
    return parse_masscan_json_text(raw)


def parse_masscan_json_text(raw):
    """Parse masscan -oJ output text into ['ip:port', ...]."""
    raw = (raw or "").strip()
    if not raw:
        return []
    found = []
    try:
        data = json.loads(raw)
    except Exception:
        data = None
    if isinstance(data, list):
        for entry in data:
            if not isinstance(entry, dict):
                continue
            ip = entry.get("ip")
            for p in entry.get("ports") or []:
                try:
                    port = int((p or {}).get("port", 0))
                    status = str((p or {}).get("status", "open")).lower()
                except Exception:
                    continue
                if ip and 1 <= port <= 65535 and status == "open":
                    found.append(f"{ip}:{port}")
    elif isinstance(data, dict):
        ip = data.get("ip")
        for p in data.get("ports") or []:
            try:
                port = int((p or {}).get("port", 0))
            except Exception:
                continue
            if ip and 1 <= port <= 65535:
                found.append(f"{ip}:{port}")
    else:
        for line in raw.splitlines():
            line = line.strip().rstrip(",")
            if not line or line in ("[", "]"):
                continue
            try:
                entry = json.loads(line)
            except Exception:
                continue
            ip = entry.get("ip")
            for p in entry.get("ports") or []:
                try:
                    port = int((p or {}).get("port", 0))
                except Exception:
                    continue
                if ip and 1 <= port <= 65535:
                    found.append(f"{ip}:{port}")
    return [t for t in dict.fromkeys(found) if not is_ignored(t)]


_MASSCAN_DISCOVERED_RE = re.compile(r"Discovered\s+open\s+port\s+(\d{1,5})/(\w+)\s+on\s+(\S+)")

def parse_masscan_discovered_line(line):
    """Parse 'Discovered open port 25565/tcp on 1.2.3.4' (masscan --interactive)."""
    m = _MASSCAN_DISCOVERED_RE.search(line or "")
    if not m:
        return None
    try:
        port = int(m.group(1))
    except ValueError:
        return None
    host = m.group(3)
    if not host or not (1 <= port <= 65535):
        return None
    return f"{host}:{port}"


def _masscan_failure_markers(output):
    low = (output or "").lower()
    return ("sorry, try again" in low or "incorrect password" in low
            or "no tty present" in low or "sudo: " in low
            or "could not open file" in low
            or "permission denied" in low or "need to sudo" in low
            or "run as root" in low or "fail: " in low)


def _raise_masscan_error(returncode, output):
    """Raise the most helpful exception for a failed masscan run."""
    output = (output or "").strip()
    low = output.lower()
    if ("sorry, try again" in low or "incorrect password" in low
            or "no tty present" in low or "sudo: " in low):
        raise PermissionError(
            "sudo authentication failed (wrong password or not allowed "
            "to run masscan with sudo). " + output[:300]
        )
    if "could not open file" in low:
        raise RuntimeError(
            "masscan could not open its output destination. " + output[:300]
        )
    if "permission denied" in low or "need to sudo" in low or "run as root" in low:
        raise PermissionError(
            "masscan needs raw-socket privileges. Run as root/Administrator "
            "(Linux: sudo, Windows: admin + Npcap) or use Python backend. "
            + output[:300]
        )
    raise RuntimeError(f"masscan failed (exit {returncode}): {output[:500]}")


def _masscan_popen(cmd, sudo_password, merge_stderr=False, binary_stream=False):
    """Start masscan; feed a sudo password via stdin when given, then close it
    at once so sudo can never block on a tty prompt. With merge_stderr=True,
    stderr is folded into stdout (one pipe to drain, no deadlock possible).
    With binary_stream=True the stdout pipe is binary (for manual chunk reads)."""
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE if sudo_password is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT if merge_stderr else subprocess.PIPE,
        text=not binary_stream, bufsize=1 if not binary_stream else -1,
    )
    if sudo_password is not None:
        try:
            if binary_stream:
                proc.stdin.write((sudo_password + "\n").encode("utf-8", "replace"))
            else:
                proc.stdin.write(sudo_password + "\n")
        except Exception:
            pass
        try:
            proc.stdin.close()
        except Exception:
            pass
    return proc


_MASSCAN_PROGRESS_RE = re.compile(r"rate:\s*([\d.]+)-kpps,\s*([\d.]+)%\s*done")

def parse_masscan_progress(fragment):
    """Parse masscan's status line ('rate: 9.83-kpps, 12.34% done, ...').
    Returns (percent_float, rate_kpps_str) or None."""
    m = _MASSCAN_PROGRESS_RE.search(fragment or "")
    if not m:
        return None
    try:
        return float(m.group(2)), m.group(1)
    except ValueError:
        return None


def format_stream_status(opened, probed, found, pct=None, rate=None):
    """Status-bar text for a live masscan sweep."""
    if pct is None:
        return f"masscan: {opened} open | handshake: {probed} | Minecraft: {found}"
    if rate:
        return (f"masscan: {pct:.0f}% @ {rate}kpps | {opened} open | "
                f"handshake: {probed} | Minecraft: {found}")
    return f"masscan: {pct:.0f}% | {opened} open | handshake: {probed} | Minecraft: {found}"


def _drain_masscan_stdout(proc, timeout, frag_cb, progress_cb=None, note_cap=4096):
    """Feed \\r/\\n-separated stdout fragments to callbacks until EOF.

    masscan's progress line uses bare \\r (no newline), so the pipe is read
    in chunks and split on both characters; result lines use \\n. Progress
    fragments go to progress_cb(pct, rate); other fragments go to
    frag_cb(frag), which returns True when it consumed a result line.
    Unmatched text (capped) is returned for error notes.
    Returns (timed_out, other_text). Kills proc after timeout.
    """
    timed_out = {"hit": False}

    def _kill():
        try:
            if proc.poll() is None:
                timed_out["hit"] = True
                proc.kill()
        except Exception:
            pass

    watchdog = threading.Timer(timeout, _kill)
    watchdog.daemon = True
    other_parts = []
    other_len = 0

    def handle_fragment(frag):
        nonlocal other_len
        frag = (frag or "").strip()
        if not frag:
            return
        # NOTE: no early return after progress — masscan glues the \r status
        # text directly onto the next result line, so one fragment can hold
        # both ("...found=1Discovered open port ...").
        prog_matched = parse_masscan_progress(frag) is not None
        if prog_matched and progress_cb is not None:
            try:
                progress_cb(*parse_masscan_progress(frag))
            except Exception:
                pass
        try:
            matched = frag_cb(frag)
        except Exception:
            matched = False
        if not matched and not prog_matched and other_len < note_cap:
            other_parts.append(frag[:500])
            other_len += len(frag[:500])

    decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
    buf = ""
    try:
        watchdog.start()
        while True:
            try:
                chunk = proc.stdout.read1(65536)
            except Exception:
                break
            if not chunk:
                break
            try:
                buf += decoder.decode(chunk)
            except Exception:
                continue
            if "\r" in buf or "\n" in buf:
                parts = re.split(r"[\r\n]+", buf)
                buf = parts.pop()
                for frag in parts:
                    handle_fragment(frag)
        try:
            buf += decoder.decode(b"", final=True)
        except Exception:
            pass
        if buf.strip():
            handle_fragment(buf)
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            _kill()
            try:
                proc.wait(timeout=10)
            except Exception:
                pass
    finally:
        try:
            watchdog.cancel()
        except Exception:
            pass
        for stream in (getattr(proc, "stdout", None), getattr(proc, "stderr", None)):
            try:
                if stream:
                    stream.close()
            except Exception:
                pass
    return timed_out["hit"], "\n".join(other_parts).strip()[:note_cap]


def _masscan_proc_error_info(proc, output):
    """(returncode, failed_bool) for a finished masscan process."""
    try:
        returncode = proc.returncode
    except Exception:
        returncode = -1
    failed = (returncode not in (0, None)) or _masscan_failure_markers(output)
    return returncode, failed


def run_masscan_open_ports(masscan_targets, ports, rate=MASSCAN_DEFAULT_RATE,
                           wait=MASSCAN_DEFAULT_WAIT, timeout=None, exe=None,
                           use_sudo=False, sudo_password=None):
    """Run masscan SYN discovery. Returns (open_targets, stderr_note).

    open_targets is a list of 'ip:port' strings with TCP open.
    Raises FileNotFoundError when masscan is missing, PermissionError when raw
    sockets are denied (needs root/admin), TimeoutError on timeout.
    Results stream through stdout (`-oJ -`); no temp files are used.
    """
    exe = exe or shutil.which("masscan")
    if not exe:
        if MASSCAN_BIN and os.path.isabs(MASSCAN_BIN) and os.path.exists(MASSCAN_BIN):
            exe = MASSCAN_BIN
        else:
            raise FileNotFoundError("masscan binary not found. Install masscan or use Python backend.")
    ports = list(dict.fromkeys(int(p) for p in (ports or [25565]) if 1 <= int(p) <= 65535)) or [25565]
    try:
        rate = max(100, min(int(rate), 1000000))
    except Exception:
        rate = MASSCAN_DEFAULT_RATE
    try:
        wait = max(0, min(int(wait), 60))
    except Exception:
        wait = MASSCAN_DEFAULT_WAIT
    if not masscan_targets:
        return [], "no targets"

    port_spec = ",".join(str(p) for p in ports)
    base_cmd = [exe]
    if use_sudo:
        if not sudo_available():
            raise PermissionError(
                "sudo is not available on this system. Run as Administrator/root "
                "or use the Python backend."
            )
        # -S reads the password from stdin, -p "" suppresses sudo's own prompt.
        base_cmd = ["sudo", "-S", "-p", "", exe]
    cmd = base_cmd + list(masscan_targets) + [
        "-p", port_spec,
        "--open",
        "--rate", str(rate),
        "--wait", str(wait),
        "-oJ", "-",
    ]
    if timeout is None:
        timeout = _masscan_default_timeout(masscan_targets, ports, rate, wait)
    try:
        proc = _masscan_popen(cmd, sudo_password if use_sudo else None)
    except FileNotFoundError:
        raise FileNotFoundError("masscan binary not found. Install masscan or use Python backend.")
    try:
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            try:
                proc.kill()
            except Exception:
                pass
            try:
                stdout, stderr = proc.communicate(timeout=10)
            except Exception:
                stdout, stderr = "", ""
            raise TimeoutError(f"masscan timed out after {timeout}s")
    except TimeoutError:
        raise
    except Exception as exc:
        raise RuntimeError(f"masscan failed to run: {exc}")
    output = (stderr or "").strip()
    opened = parse_masscan_json_text(stdout or "")
    returncode, failed = _masscan_proc_error_info(proc, output)
    if failed:
        if opened:
            return opened, output[:500]
        _raise_masscan_error(returncode, output)
    return opened, (output[:500] if output else "")


_MASSCAN_LIST_LINE_RE = re.compile(r"open\s+tcp\s+(\d{1,5})\s+(\S+)")

def parse_masscan_list_line(line):
    """Parse one masscan -oL line ('open tcp 25565 1.2.3.4 ...') into 'ip:port'."""
    m = _MASSCAN_LIST_LINE_RE.search(line or "")
    if not m:
        return None
    try:
        port = int(m.group(1))
    except ValueError:
        return None
    host = m.group(2)
    if not host or not (1 <= port <= 65535):
        return None
    return f"{host}:{port}"


def sudo_available():
    """True when a sudo binary exists (Linux/macOS privilege escalation path)."""
    return os.name != "nt" and shutil.which("sudo") is not None


def sudo_noninteractive_ok(timeout=10):
    """True when sudo works without a password (root, passwordless sudo, cached creds)."""
    if not sudo_available():
        return False
    try:
        proc = subprocess.run(["sudo", "-n", "true"],
                              capture_output=True, text=True, timeout=timeout)
        return proc.returncode == 0
    except Exception:
        return False


def run_masscan_streaming(masscan_targets, ports, rate=MASSCAN_DEFAULT_RATE,
                          wait=MASSCAN_DEFAULT_WAIT, on_open=None, on_scan_progress=None,
                          timeout=None, exe=None, use_sudo=False, sudo_password=None):
    """Run masscan and call on_open(ip_port) live as open ports are found.

    masscan runs with `--interactive` (which flushes a `Discovered open
    port ...` line to stdout per hit) plus `-oL -` as a backup stream, so
    callers can handshake/display each host immediately instead of waiting
    for the whole sweep. Everything flows through pipes; no temp files are
    used, so there is nothing a privileged/unprivileged user mismatch can
    fail to open. Returns (found_list, note). Raises FileNotFoundError when
    masscan is missing, PermissionError when raw sockets are denied, and
    TimeoutError on timeout.

    When use_sudo is True, masscan runs under `sudo -S` (password fed via
    stdin when sudo_password is given, otherwise relies on cached/passwordless
    sudo so it can never hang on a tty prompt).
    """
    exe = exe or shutil.which("masscan")
    if not exe:
        if MASSCAN_BIN and os.path.isabs(MASSCAN_BIN) and os.path.exists(MASSCAN_BIN):
            exe = MASSCAN_BIN
        else:
            raise FileNotFoundError("masscan binary not found. Install masscan or use Python backend.")
    ports = list(dict.fromkeys(int(p) for p in (ports or [25565]) if 1 <= int(p) <= 65535)) or [25565]
    try:
        rate = max(100, min(int(rate), 1000000))
    except Exception:
        rate = MASSCAN_DEFAULT_RATE
    try:
        wait = max(0, min(int(wait), 60))
    except Exception:
        wait = MASSCAN_DEFAULT_WAIT
    if not masscan_targets:
        return [], "no targets"

    port_spec = ",".join(str(p) for p in ports)
    base_cmd = [exe]
    if use_sudo:
        if not sudo_available():
            raise PermissionError(
                "sudo is not available on this system. Run as Administrator/root "
                "or use the Python backend."
            )
        # -S reads the password from stdin, -p "" suppresses sudo's own prompt.
        base_cmd = ["sudo", "-S", "-p", "", exe]
    # --interactive prints (and flushes) one 'Discovered open port ...' line
    # per hit; -oL - mirrors the same hits as list lines on the same pipe.
    cmd = base_cmd + list(masscan_targets) + [
        "-p", port_spec,
        "--open",
        "--rate", str(rate),
        "--wait", str(wait),
        "--interactive",
        "-oL", "-",
    ]
    if timeout is None:
        timeout = _masscan_default_timeout(masscan_targets, ports, rate, wait)
    found = []
    seen = set()

    def emit(ip_port):
        if not ip_port or ip_port in seen or is_ignored(ip_port):
            return
        seen.add(ip_port)
        found.append(ip_port)
        if on_open:
            try:
                on_open(ip_port)
            except Exception:
                pass

    def handle_result(frag):
        ip_port = parse_masscan_discovered_line(frag)
        if ip_port is None:
            ip_port = parse_masscan_list_line(frag)
        if ip_port:
            emit(ip_port)
            return True
        return False

    try:
        proc = _masscan_popen(cmd, sudo_password if use_sudo else None,
                              merge_stderr=True, binary_stream=True)
    except FileNotFoundError:
        raise FileNotFoundError("masscan binary not found. Install masscan or use Python backend.")
    # One merged pipe: masscan's \r progress, flushed Discovered lines and
    # buffered -oL lines all arrive here; nothing can deadlock or stay hidden.
    timed_out, other = _drain_masscan_stdout(proc, timeout, handle_result,
                                             progress_cb=on_scan_progress)
    stderr = other
    if timed_out:
        if found:
            note = (stderr[:400] + " " if stderr else "") + f"[partial: timed out after {timeout}s]"
            return found, note.strip()
        raise TimeoutError(f"masscan timed out after {timeout}s")
    returncode, failed = _masscan_proc_error_info(proc, stderr)
    if failed:
        # An old masscan may not know --interactive; retry plainly (batched).
        if "interactive" in (stderr or "") and "unknown" in (stderr or "").lower():
            return _run_masscan_streaming_plain(
                base_cmd, masscan_targets, port_spec, rate, wait,
                timeout, found, seen, emit, sudo_password if use_sudo else None,
                on_scan_progress=on_scan_progress)
        if found:
            return found, stderr[:500]
        _raise_masscan_error(returncode, stderr)
    return found, (stderr[:500] if stderr else "")


def _run_masscan_streaming_plain(base_cmd, masscan_targets, port_spec, rate, wait,
                                 timeout, found, seen, emit, sudo_password,
                                 on_scan_progress=None):
    """Fallback for masscan builds without --interactive: same merged stream
    with only -oL - list lines (still live in chunks, no temp files)."""
    cmd = base_cmd + list(masscan_targets) + [
        "-p", port_spec,
        "--open",
        "--rate", str(rate),
        "--wait", str(wait),
        "-oL", "-",
    ]
    try:
        proc = _masscan_popen(cmd, sudo_password,
                              merge_stderr=True, binary_stream=True)
    except FileNotFoundError:
        raise FileNotFoundError("masscan binary not found. Install masscan or use Python backend.")

    def handle_result(frag):
        ip_port = parse_masscan_list_line(frag)
        if ip_port:
            emit(ip_port)
            return True
        return False

    timed_out, other = _drain_masscan_stdout(proc, timeout, handle_result,
                                             progress_cb=on_scan_progress)
    stderr = other
    if timed_out:
        if found:
            note = (stderr[:400] + " " if stderr else "") + f"[partial: timed out after {timeout}s]"
            return found, note.strip()
        raise TimeoutError(f"masscan timed out after {timeout}s")
    returncode, failed = _masscan_proc_error_info(proc, stderr)
    if failed:
        if found:
            return found, stderr[:500]
        _raise_masscan_error(returncode, stderr)
    return found, (stderr[:500] if stderr else "")


def merge_global_ip_log(updated_ips):
    """Merge {ip_port: line} results into the global ips.txt log."""
    existing = {}
    if os.path.exists(GLOBAL_IP_LOG):
        try:
            with open(GLOBAL_IP_LOG, 'r', encoding='utf-8') as f:
                for line in f:
                    if line.strip():
                        ip = line.strip().split(' |')[0]
                        existing[ip] = line.strip()
        except Exception:
            pass
    existing.update({k: v for k, v in (updated_ips or {}).items() if not is_ignored(k)})
    try:
        with open(GLOBAL_IP_LOG, 'w', encoding='utf-8') as f:
            for line in sorted(existing.values()):
                f.write(line + "\n")
    except Exception:
        pass


class UserLogManager:
    """
    Thread-safe store that tracks the last seen server for each player name.
    """
    def __init__(self):
        self._entries = {}  # player -> {"ip": ..., "motd": ..., "last_seen": ts}
        self._lock = threading.Lock()
        self._tab = None
        self._load_from_disk()

    def attach_tab(self, tab: "UserLogTab"):
        self._tab = tab
        tab.bind_manager(self)
        tab.request_refresh(initial=True)

    def snapshot(self):
        with self._lock:
            return [
                {
                    "player": player,
                    "ip": data["ip"],
                    "motd": data["motd"],
                    "last_seen": data["last_seen"]
                }
                for player, data in self._entries.items()
            ]

    def update_from_result(self, result: dict):
        sample = result.get("players_sample") or []
        if not sample:
            return
        ip = result.get("ip", "")
        motd = result.get("motd", "")
        now = time.time()
        changed = False
        with self._lock:
            for _pid, pname in sample:
                player = (pname or "").strip()
                if not player:
                    continue
                entry = self._entries.get(player)
                if not entry or entry["ip"] != ip or entry["motd"] != motd:
                    self._entries[player] = {"ip": ip, "motd": motd, "last_seen": now}
                else:
                    self._entries[player]["last_seen"] = now
                changed = True
        if changed:
            self._save_to_disk()
            self._notify_tab()

    def _notify_tab(self):
        if self._tab:
            self._tab.request_refresh()

    def _load_from_disk(self):
        if not os.path.exists(USER_LOG_FILE):
            return
        try:
            with open(USER_LOG_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            return
        if not isinstance(data, list):
            return
        entries = {}
        for row in data:
            try:
                player = (row.get("player") or "").strip()
                if not player:
                    continue
                ip = row.get("ip") or ""
                motd = row.get("motd") or ""
                ts = float(row.get("last_seen") or 0)
                entries[player] = {"ip": ip, "motd": motd, "last_seen": ts}
            except Exception:
                continue
        with self._lock:
            self._entries = entries

    def _save_to_disk(self):
        snapshot = self.snapshot()
        try:
            with open(USER_LOG_FILE, "w", encoding="utf-8") as f:
                json.dump(snapshot, f, indent=2)
        except Exception:
            pass


USER_LOG_MANAGER = UserLogManager()

def fetch_server_favicon_bytes(entry):  # returns raw PNG bytes or None
    try:
        host, port = split_host_port(entry)
        with socket.create_connection((host, port), timeout=ICON_FETCH_TIMEOUT) as sock:
            sock.settimeout(ICON_FETCH_TIMEOUT)
            handshake = (
                varint_encode(0x00) +
                varint_encode(PROTOCOL_VERSION) +
                write_string(host) +
                struct.pack('>H', port) +
                varint_encode(1)
            )
            sock.send(varint_encode(len(handshake)) + handshake)
            sock.send(varint_encode(1) + b'\x00')
            _ = varint_decode(sock)
            _ = varint_decode(sock)
            json_length = varint_decode(sock)
            data = recv_bounded(sock, json_length, MAX_FAVICON_RESPONSE_BYTES).decode('utf-8')
            response = json.loads(data)
            fav = response.get('favicon')
            if isinstance(fav, str) and fav.startswith('data:image'):
                b64 = fav.split(',', 1)[1]
                return base64.b64decode(b64)
    except Exception:
        pass
    return None

# GUI-friendly scan with streaming callbacks
def scan_servers_gui(servers, on_start=None, on_result=None, on_progress=None, login_probe=False):
    filtered = [s for s in servers if not is_ignored(s)]
    results, online_lines, updated_ips = [], [], {}
    total, done = len(filtered), 0

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        def task(ip):
            if on_start:
                try: on_start(ip)
                except Exception: pass
            return ping_server(ip)

        futures = {executor.submit(task, s): s for s in filtered}

        for fut in as_completed(futures):
            r = fut.result()
            done += 1

            if r:
                results.append(r)
                ip_key = r['ip']
                line = f"{ip_key} | MOTD: {r['motd']} | Players: {r['players']}/{r['max_players']} | Version: {r['version']}"
                updated_ips[ip_key] = line
                if r['players'] > 0:
                    online_lines.append(line)
                USER_LOG_MANAGER.update_from_result(r)
                if on_result:
                    try: on_result(r, line)
                    except Exception: pass

            if on_progress:
                try: on_progress(done, total)
                except Exception: pass

    existing = {}
    if os.path.exists(GLOBAL_IP_LOG):
        with open(GLOBAL_IP_LOG, 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip():
                    ip = line.strip().split(' |')[0]
                    existing[ip] = line.strip()
    existing.update({k: v for k, v in updated_ips.items() if not is_ignored(k)})

    with open(GLOBAL_IP_LOG, 'w', encoding='utf-8') as f:
        for line in sorted(existing.values()):
            f.write(line + "\n")

    return results, online_lines

# ==================== Server Monitor State ====================

def load_server_monitor_state():
    if not os.path.exists(SERVER_MONITOR_FILE):
        return {"servers": {}}
    try:
        with open(SERVER_MONITOR_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return {"servers": {}}
    if not isinstance(data, dict):
        return {"servers": {}}
    data.setdefault("servers", {})
    return data

def save_server_monitor_state(state):
    try:
        with open(SERVER_MONITOR_FILE, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2)
    except Exception:
        pass

def _ensure_monitor_server_entry(state, ip):
    if "servers" not in state:
        state["servers"] = {}
    entries = state["servers"]
    if ip not in entries:
        entries[ip] = {
            "ip": ip,
            "motd": "",
            "last_status": "unknown",
            "last_ping": 0,
            "players_online": 0,
            "max_players": 0,
            "version": "N/A",
            "cracked": False,
            "cracked_message": "",
            "cracked_last_check": 0,
            "player_log": {},
            "current_players": []
        }
    return entries[ip]

def update_server_monitor_entry(state, ip, result, timestamp):
    entry = _ensure_monitor_server_entry(state, ip)
    entry["motd"] = result.get("motd", "")
    entry["version"] = result.get("version", "N/A")
    entry["players_online"] = result.get("players", 0)
    entry["max_players"] = result.get("max_players", 0)
    entry["last_status"] = "online"
    entry["last_ping"] = timestamp
    entry["cracked"] = bool(result.get("cracked"))
    entry["cracked_message"] = result.get("cracked_message", "")
    entry["cracked_last_check"] = result.get("cracked_last_check", timestamp if "cracked_message" in result else entry.get("cracked_last_check", 0))
    sample = result.get("players_sample") or []
    log = entry.setdefault("player_log", {})
    current_ids = []
    for player_id, player_name in sample:
        uid = (player_id or "").strip()
        name = (player_name or "").strip()
        if not uid or not name:
            continue
        log[uid] = {"name": name, "last_seen": timestamp}
        current_ids.append(uid)
    entry["current_players"] = current_ids

def mark_server_offline_in_state(state, ip, timestamp):
    entry = _ensure_monitor_server_entry(state, ip)
    entry["last_status"] = "offline"
    entry["last_ping"] = timestamp
    entry["current_players"] = []

def format_timestamp(ts):
    if not ts:
        return "n/a"
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
    except Exception:
        return str(ts)

SERVER_MONITOR_TAB_INSTANCE = None

def register_monitor_tab(tab):
    global SERVER_MONITOR_TAB_INSTANCE
    SERVER_MONITOR_TAB_INSTANCE = tab

def add_ips_to_monitor_list(ips):
    if not ips:
        return 0, 0, 0
    state = load_server_monitor_state()
    added = 0
    invalid = 0
    duplicates = 0
    for raw in ips:
        ip = get_ip_only(raw)
        if not ip or not is_valid_ip_port(ip):
            invalid += 1
            continue
        if ip in state.get("servers", {}):
            duplicates += 1
            continue
        _ensure_monitor_server_entry(state, ip)
        added += 1
    if added:
        save_server_monitor_state(state)
        if SERVER_MONITOR_TAB_INSTANCE:
            try:
                SERVER_MONITOR_TAB_INSTANCE.reload_state()
            except Exception:
                pass
    return added, invalid, duplicates

def format_monitor_feedback(added, invalid, duplicates):
    if added:
        parts = [f"Added {added} server(s) to monitor list."]
        if duplicates:
            parts.append(f"{duplicates} already monitored.")
        if invalid:
            parts.append(f"{invalid} invalid entrie(s) skipped.")
        return " ".join(parts)
    parts = []
    if duplicates:
        parts.append(f"{duplicates} already monitored.")
    if invalid:
        parts.append(f"{invalid} invalid entrie(s) skipped.")
    if parts:
        return " ".join(parts)
    return "No new servers were added to the monitor list."

def verify_monitor_cracked_result(result):
    # Re-check cracked/online-mode status during each monitor ping cycle.
    ip = result.get("ip") if isinstance(result, dict) else None
    if not ip:
        return result

    probe_result = None
    message = ""
    checked_at = time.time()
    cached_before_probe = get_cached_cracked_entry(ip)

    try:
        host, port = split_host_port(ip)
        probe_result, message = is_cracked_server(host, port)
    except Exception as exc:
        message = f"Cracked check error: {str(exc)[:80]}"

    if probe_result is True:
        result["cracked"] = True
        result["cracked_message"] = message or "CRACKED"
        result["cracked_last_check"] = checked_at
        if not cached_before_probe:
            record_cracked_server(ip, result["cracked_message"], extra=result)
        return result

    if probe_result is False:
        result["cracked"] = False
        result["cracked_message"] = message or "ONLINE-MODE"
        result["cracked_last_check"] = checked_at
        return result

    if result.get("cracked"):
        fallback_message = message or "CRACKED by players.sample UUID during status ping"
        result["cracked"] = True
        result["cracked_message"] = fallback_message
        result["cracked_last_check"] = checked_at
        if not cached_before_probe:
            record_cracked_server(ip, fallback_message, extra=result)
        return result

    cached = cached_before_probe
    if cached:
        cached_message = cached.get("message") or "Cached cracked server"
        result["cracked"] = True
        result["cracked_message"] = f"{message}; cached fallback: {cached_message}" if message else f"Cached fallback: {cached_message}"
        result["cracked_last_check"] = checked_at
        return result

    result["cracked"] = False
    result["cracked_message"] = message or "UNKNOWN MODE"
    result["cracked_last_check"] = checked_at
    return result

def verify_monitor_cracked_results(results, progress_cb=None):
    # Runs cracked checks in parallel so the monitor does not serially hang on slow servers.
    if not results:
        return []

    verified = []
    total = len(results)
    done = 0
    workers = min(max(1, CRACKED_VERIFY_WORKERS), total)

    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_result = {executor.submit(verify_monitor_cracked_result, result): result for result in results}
        for fut in as_completed(future_to_result):
            try:
                verified.append(fut.result())
            except Exception:
                verified.append(future_to_result[fut])
            done += 1
            if progress_cb:
                try:
                    progress_cb(done, total)
                except Exception:
                    pass

    return verified

# ==================== NBT Export ====================

def list_txt_files():
    return [f for f in os.listdir() if f.endswith(".txt")]

def choose_input_file():
    txt_files = list_txt_files()
    if not txt_files:
        print("No .txt files found in the current folder.")
        exit(1)
    print("Available .txt files:")
    for idx, fname in enumerate(txt_files, 1):
        print(f"  {idx}) {fname}")
    choice = input("Select a file by number: ").strip()
    try:
        index = int(choice) - 1
        return txt_files[index]
    except (IndexError, ValueError):
        print("Invalid selection.")
        exit(1)

def backup_or_restore():
    if os.path.exists(BACKUP_PATH):
        if ask_yes_no("Backup already exists. Restore it before continuing?"):
            shutil.copyfile(BACKUP_PATH, SERVERS_DAT_PATH)
            print("Backup restored.")
        else:
            print("Proceeding with current servers.dat.")
    else:
        if ask_yes_no("No backup found. Create a backup of servers.dat before modifying?"):
            shutil.copyfile(SERVERS_DAT_PATH, BACKUP_PATH)
            print(f"Backup saved to: {BACKUP_PATH}")

def load_servers():
    if not os.path.exists(SERVERS_DAT_PATH):
        print("servers.dat not found. Creating new one.")
        return nbtlib.File({"servers": nbtlib.List[Compound]()})
    try:
        nbt_file = nbtlib.load(SERVERS_DAT_PATH)
        if "servers" not in nbt_file:
            nbt_file["servers"] = nbtlib.List[Compound]()
        return nbt_file
    except Exception as e:
        print(f"Error loading servers.dat: {e}")
        print("❌ Aborting to prevent overwrite.")
        exit(1)

def already_exists(server_list, ip):
    return any(entry['ip'] == ip for entry in server_list)

def import_to_minecraft_servers_dat():  # kept original cli flow - whatever?
    print("\n=== Minecraft Server List Importer ===")
    backup_or_restore()
    input_file = choose_input_file()
    print(f"Importing from: {input_file}")
    nbt_data = load_servers()
    if "servers" not in nbt_data:
        nbt_data["servers"] = nbtlib.List[Compound]()
    servers = nbt_data["servers"]
    existing_ips = {entry['ip'] for entry in servers}
    added_count = 0
    skipped_ignored = 0
    with open(input_file, "r", encoding="utf-8") as f:
        for line in f:
            ip = line.strip()
            if " |" in ip:
                ip = ip.split(" |")[0]
            ip_extracted = _extract_ip_port_from_text(ip)
            if ip_extracted:
                ip = ip_extracted
            if not is_valid_ip_port(ip):
                continue
            if is_ignored(ip):
                skipped_ignored += 1
                continue
            if ip in existing_ips:
                continue
            new_entry = Compound({
                "name": String(f"Imported {ip}"),
                "ip": String(ip),
                "hidden": Byte(0),
                "acceptTextures": Byte(1)
            })
            servers.append(new_entry)
            existing_ips.add(ip)
            added_count += 1
            print(f"Added {ip}")
    nbt_data.save(SERVERS_DAT_PATH)
    print(f"\n✅ Added {added_count} new servers.")
    if skipped_ignored:
        print(f"⚠️ Skipped {skipped_ignored} entrie(s) from ignore list.")
    print(f"📦 Total entries in servers.dat: {len(servers)}")

# GUI-friendly import
def import_file_to_servers_dat(path, do_backup=True):
    if do_backup and not os.path.exists(BACKUP_PATH):
        try:
            if os.path.exists(SERVERS_DAT_PATH):
                shutil.copyfile(SERVERS_DAT_PATH, BACKUP_PATH)
        except Exception as e:
            return False, f"Backup failed: {e}"

    try:
        nbt_data = load_servers()
        if "servers" not in nbt_data:
            nbt_data["servers"] = nbtlib.List[Compound]()
        servers = nbt_data["servers"]
        existing_ips = {entry['ip'] for entry in servers}
        added = 0
        skipped_ignored = 0
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                ip = get_ip_only(line.strip())
                if not is_valid_ip_port(ip):
                    continue
                if is_ignored(ip):
                    skipped_ignored += 1
                    continue
                if ip in existing_ips:
                    continue
                servers.append(Compound({
                    "name": String(f"Imported {ip}"),
                    "ip": String(ip),
                    "hidden": Byte(0),
                    "acceptTextures": Byte(1)
                }))
                existing_ips.add(ip)
                added += 1
        nbt_data.save(SERVERS_DAT_PATH)
        msg = f"Added {added} entries."
        if skipped_ignored:
            msg += f" Skipped {skipped_ignored} ignored."
        return True, msg
    except Exception as e:
        return False, f"Import failed: {e}"

# ==================== JSON search helpers ====================

from typing import List

def extract_ip_port_JSON(entry):
    return f"{entry.get('ip_str')}:{entry.get('port')}"

# Produce a fully formatted line directly from JSON entry
def extract_formatted_JSON(entry):  #
    ip_port = extract_ip_port_JSON(entry)
    data = entry.get("data", "")
    motd = parse_description_from_raw(data)
    players = parse_players(data)
    if "/" in players:
        online, maximum = players.split("/", 1)
    else:
        online, maximum = "N", "A"
    version = parse_version(data)
    return format_result_line(ip_port, motd, online, maximum, version)

def matches_JSON(entry, term):
    term_lower = term.lower()
    return (
        term_lower in str(entry.get("ip_str", "")).lower() or
        term_lower in str(entry.get("port", "")).lower() or
        term_lower in str(entry.get("data", "")).lower() or
        term_lower in str(entry.get("minecraft", "")).lower() or
        term_lower in str(entry.get("location", "")).lower() or
        term_lower in str(entry.get("version", "")).lower() or
        term_lower in str(entry.get("hostnames", "")).lower()
    )

def parse_boolean_expression_JSON(expression: str, entry) -> bool:
    tokens = re.findall(r'\(|\)|\w+(?:\.\w+)*|AND|OR|NOT', expression, flags=re.IGNORECASE)

    def eval_tokens(tokens_in):
        stack = []
        def resolve():
            result = stack.pop()
            while stack:
                op = stack.pop()
                if op == "AND":
                    result = result and stack.pop()
                elif op == "OR":
                    result = result or stack.pop()
            return result

        it = iter(tokens_in)
        for token in it:
            token_upper = token.upper()
            if token == "(":
                sub = []
                depth = 1
                for t in it:
                    if t == "(":
                        depth += 1
                    elif t == ")":
                        depth -= 1
                        if depth == 0:
                            break
                    sub.append(t)
                stack.append(eval_tokens(sub))
            elif token_upper in ("AND", "OR"):
                stack.append(token_upper)
            elif token_upper == "NOT":
                next_token = next(it)
                stack.append(not matches_JSON(entry, next_token))
            else:
                stack.append(matches_JSON(entry, token))
        return resolve()

    return eval_tokens(tokens)

def filter_entries_JSON(data: List[dict], query: str) -> List[str]:  
    out = []
    for entry in data:
        if parse_boolean_expression_JSON(query, entry):
            out.append(extract_formatted_JSON(entry))
    return out

def load_json_entries(file_path):
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File '{file_path}' not found.")
    entries = []
    with open(file_path, "r", encoding="utf-8") as f:
        for idx, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError as e:
                raise ValueError(f"Invalid JSON on line {idx}: {e}") from e
    return entries

def json_entries_to_rows(entries: List[dict]):
    rows = []
    seen = set()
    for entry in entries:
        formatted = extract_formatted_JSON(entry)
        ip, motd, players, version = parse_formatted_line(formatted)
        ip = get_ip_only(ip)
        if not is_valid_ip_port(ip):
            continue
        if is_ignored(ip):
            continue
        if ip in seen:
            continue
        rows.append((ip, motd, players, version))
        seen.add(ip)
    return rows

def json_search_load(file_path, query):
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File '{file_path}' not found.")
    with open(file_path, "r", encoding="utf-8") as f:
        data = [json.loads(line) for line in f if line.strip()]
    return filter_entries_JSON(data, query)

# ======================================

def append_with_reason(file_path, ip_port, reason, prefix):
    line = f"{ip_port} | {prefix}: {reason if reason else 'No reason'}".strip() 
    with open(file_path, "a", encoding="utf-8") as f:
        f.write(line + "\n")

def add_to_ignore(ip_port, reason):
    append_with_reason(IGNORE_FILE, ip_port, reason or "No reason", "Reason")
    refresh_ignore_set(ip_port)

def add_to_saved(ip_port, reason):
    append_with_reason(SAVED_FILE, ip_port, reason or "No reason", "Reason")
    
def parse_reason_line(line):
    ip = get_ip_only(line)
    reason = ""
    m = re.search(r"\|\s*Reason:\s*(.*)$", line)
    if m:
        reason = m.group(1).strip()
    return ip, reason

def load_reason_file(file_path):
    rows = []
    if os.path.exists(file_path):
        with open(file_path, "r", encoding="utf-8") as f:
            for ln in f:
                ln = ln.strip()
                if not ln:
                    continue
                ip, reason = parse_reason_line(ln)
                if is_valid_ip_port(ip):
                    rows.append((ip, reason))
    return rows

def save_reason_file(file_path, rows):
    with open(file_path, "w", encoding="utf-8") as f:
        for ip, reason in rows:
            f.write(f"{ip} | Reason: {reason or 'No reason'}\n")

def load_ips_rows(file_path=GLOBAL_IP_LOG):
    rows = []
    if os.path.exists(file_path):
        with open(file_path, "r", encoding="utf-8") as f:
            for ln in f:
                if not ln.strip():
                    continue
                ip, motd, players, version = parse_formatted_line(ln.strip())
                ip = get_ip_only(ip)
                if is_valid_ip_port(ip):
                    rows.append((ip, motd, players, version))
    return rows

def save_ips_rows(rows, file_path=GLOBAL_IP_LOG):
    with open(file_path, "w", encoding="utf-8") as f:
        for (ip, motd, players, version) in rows:
            players = players or "N/A"
            f.write(f"{ip} | MOTD: {sanitize_motd(motd)} | Players: {players} | Version: {version}\n")


# ==================== Qt server icons + GUI (PySide6) ====================
# ==================== Qt server icons ====================
# Qt port of _IconManager (previously tkinter PhotoImage based).
# Behavior is 1:1: per-IP favicon fetch with bounded caches, async lookup,
# icon shown on the IP cell of attached result tables.

class _IconManager:
    def __init__(self):
        self._cache_bytes = {}        # ip -> png bytes or None
        self._cache_icons = {}        # ip -> QIcon
        self._executor = ThreadPoolExecutor(max_workers=max(1, ICON_THREADS))
        self._attached = set()
        self._placeholder_icon = None

    def attach_to_tree(self, tree):
        if not ICON_ENABLED:
            return
        try:
            key = id(tree)
        except Exception:
            return
        if key in self._attached:
            return
        if not hasattr(tree, "_orig_insert"):
            try:
                tree._orig_insert = tree.insert
            except Exception:
                return

            mgr = self

            def _insert_wrapper(parent_ignored="", index_ignored="end", values=(), **kw):
                if "values" in kw:
                    values = kw["values"]
                new_iid = tree._orig_insert(parent_ignored, index_ignored, values=values)
                try:
                    if values and len(values) > 0:
                        ip = str(values[0])
                        if is_valid_ip_port(ip):
                            mgr._fetch_and_set_icon(tree, new_iid, ip)
                except Exception:
                    pass
                return new_iid

            try:
                tree.insert = _insert_wrapper  # type: ignore
            except Exception:
                return
        self._attached.add(key)

    def _fetch_and_set_icon(self, tree, iid, ip):
        if ip in self._cache_bytes:
            data = self._cache_bytes[ip]
            ui_after(0, lambda: self._apply_icon_to_item(tree, iid, ip, data))
            return

        def work():
            try:
                data = fetch_server_favicon_bytes(ip)
            except Exception:
                data = None
            if len(self._cache_bytes) >= MAX_ICON_CACHE_ENTRIES and ip not in self._cache_bytes:
                try:
                    self._cache_bytes.pop(next(iter(self._cache_bytes)), None)
                except Exception:
                    pass
            self._cache_bytes[ip] = data
            try:
                ui_after(0, lambda: self._apply_icon_to_item(tree, iid, ip, data))
            except Exception:
                pass

        try:
            self._executor.submit(work)
        except Exception:
            pass

    def _apply_icon_to_item(self, tree, iid, ip, png_bytes):
        try:
            icon = self._icon_for_ip(ip, png_bytes)
            tree.set_row_icon(iid, icon)
        except Exception:
            pass

    def _icon_for_ip(self, ip, png_bytes):
        if ip in self._cache_icons:
            return self._cache_icons[ip]
        icon = self._make_icon(png_bytes)
        if icon is None:
            icon = self._placeholder_icon_fn()
        if len(self._cache_icons) >= MAX_ICON_CACHE_ENTRIES and ip not in self._cache_icons:
            try:
                self._cache_icons.pop(next(iter(self._cache_icons)), None)
            except Exception:
                pass
        self._cache_icons[ip] = icon
        return icon

    def _make_icon(self, png_bytes):
        if not png_bytes:
            return None
        try:
            img = QImage.fromData(bytes(png_bytes))
            if img.isNull():
                return None
            pix = QPixmap.fromImage(img)
            if pix.isNull():
                return None
            try:
                pix = pix.scaled(
                    ICON_SIZE, ICON_SIZE,
                    Qt.KeepAspectRatio, Qt.SmoothTransformation,
                )
            except Exception:
                pass
            return QIcon(pix)
        except Exception:
            return None

    def _placeholder_icon_fn(self):
        if self._placeholder_icon is not None:
            return self._placeholder_icon
        try:
            pix = QPixmap(ICON_SIZE, ICON_SIZE)
            try:
                pix.fill(QColor(ICON_PLACEHOLDER))
            except Exception:
                pass
            self._placeholder_icon = QIcon(pix)
        except Exception:
            self._placeholder_icon = QIcon()
        return self._placeholder_icon


# singleton accessor
_ICON_MANAGER_SINGLETON = None


def _get_icon_manager():
    global _ICON_MANAGER_SINGLETON
    if _ICON_MANAGER_SINGLETON is None:
        _ICON_MANAGER_SINGLETON = _IconManager()
    return _ICON_MANAGER_SINGLETON


# ==================== GUI entry ====================


# ===== Qt port section: qt_account (PySide6, 1:1 behavior) =====
"""PySide6 port of AccountTab (scanner.py lines 4358-4636)
and sudo password dialog (lines 4637-4739). 1:1 behavior, Qt widgets only.

Backend symbols (reference as-is, provided by scanner.py):
    _load_mc_accounts, _save_mc_accounts, _account_key, get_active_mc_account,
    import_prism_accounts, PRISM_ACCOUNTS_PATH, _normalize_mc_account,
    upsert_mc_accounts, import_tokens_from_text, probe_accounts_async,
    probe_account, open_whitelist_log_file
"""

import os
import threading

from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)
from PySide6.QtCore import Qt, QTimer



class AccountTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._probe_results = {}   # account key -> (ok, message)
        self._row_keys = {}        # tree iid -> account key
        self.status_text = "Ready."
        self._build_ui()
        self.refresh()

    # -- helpers provided locally (contract assumes QtBaseMixin provides
    # -- after()/set_status(); defined here so the file is standalone) --
    def after(self, ms, func):
        QTimer.singleShot(int(ms), func)

    def set_status(self, msg):
        self.status_text = msg
        try:
            self.status_label.setText(msg)
        except Exception:
            pass

    def _build_ui(self):
        layout = QVBoxLayout(self)

        bar = QHBoxLayout()
        layout.addLayout(bar)
        btn_import_prism = QPushButton("Import Prism Accounts")
        btn_import_prism.clicked.connect(self.import_prism)
        bar.addWidget(btn_import_prism)
        btn_import_tokens = QPushButton("Import Tokens")
        btn_import_tokens.clicked.connect(self.import_tokens)
        bar.addWidget(btn_import_tokens)
        btn_add_manual = QPushButton("Add Manual Token")
        btn_add_manual.clicked.connect(self.add_manual)
        bar.addWidget(btn_add_manual)
        btn_set_active = QPushButton("Set Active")
        btn_set_active.clicked.connect(self.set_active)
        bar.addWidget(btn_set_active)
        btn_test = QPushButton("Test Selected")
        btn_test.clicked.connect(self.test_selected)
        bar.addWidget(btn_test)
        btn_probe = QPushButton("Probe All")
        btn_probe.clicked.connect(self.probe_accounts)
        bar.addWidget(btn_probe)
        btn_remove = QPushButton("Remove")
        btn_remove.clicked.connect(self.remove_selected)
        bar.addWidget(btn_remove)
        btn_remove_failed = QPushButton("Remove Failed")
        btn_remove_failed.clicked.connect(self.remove_failed)
        bar.addWidget(btn_remove_failed)
        btn_log = QPushButton("Open Whitelist Log")
        btn_log.clicked.connect(lambda: open_whitelist_log_file(self))
        bar.addWidget(btn_log)
        bar.addStretch(1)

        cols = ("active", "name", "uuid", "source", "token_source", "status")
        self.tree = ResultTable()
        self.tree.set_columns(cols)
        layout.addWidget(self.tree, 1)

        self.status_label = QLabel(self.status_text)
        layout.addWidget(self.status_label)

    def refresh(self):
        data = _load_mc_accounts()
        active_uuid = data.get("active_uuid", "")
        self.tree.delete(*self.tree.get_children())
        self._row_keys = {}
        count = 0
        for account in data.get("accounts", []):
            key = _account_key(account)
            if not key:
                continue
            count += 1
            active = "Yes" if (account.get("uuid") and account.get("uuid") == active_uuid) else ""
            iid = self.tree.insert(
                "",
                "end",
                values=(
                    active,
                    account.get("name", ""),
                    account.get("uuid", ""),
                    account.get("source", ""),
                    account.get("token_source", ""),
                    self._status_for(account, key)
                )
            )
            self._row_keys[iid] = key
        active = get_active_mc_account()
        if active:
            self.set_status(f"{count} account(s). Active: {active.get('name')}.")
        else:
            self.set_status(f"{count} account(s). No active account.")

    def _status_for(self, account, key):
        for k in (key, account.get("uuid"), account.get("name")):
            if k and k in self._probe_results:
                ok, msg = self._probe_results[k]
                return ("OK" if ok else "FAILED") + (f": {msg}" if msg else "")
        if account.get("access_token") and account.get("uuid") and account.get("name"):
            return "unverified"
        if account.get("refresh_token"):
            return "unverified (refresh)"
        return "-"

    def _selected_key(self):
        sel = self.tree.selection()
        if not sel:
            return ""
        return self._row_keys.get(sel[0], "")

    def _selected_keys(self):
        keys = []
        for iid in self.tree.selection():
            key = self._row_keys.get(iid, "")
            if key:
                keys.append(key)
        return keys

    def import_prism(self):
        path = PRISM_ACCOUNTS_PATH
        if not os.path.exists(path):
            picked = q_ask_open(
                self,
                "Pick Prism accounts.json",
                "accounts.json (accounts.json);;JSON (*.json);;All files (*.*)"
            )
            if not picked:
                return
            path = picked
        try:
            imported = import_prism_accounts(path)
            self.refresh()
            self.set_status(f"Imported {len(imported)} Prism account(s).")
        except Exception as exc:
            q_error(self, "Accounts", f"Import failed: {exc}")
            self.set_status(f"Import failed: {exc}")

    def add_manual(self):
        name = q_ask_string(self, "Minecraft Account", "Minecraft username:")
        if not name:
            return
        profile_id = q_ask_string(self, "Minecraft Account", "Profile UUID (with or without dashes):")
        if not profile_id:
            return
        access_token = q_ask_string(self, "Minecraft Account", "Session/access token:", show="*")
        if not access_token:
            return
        refresh_token = q_ask_string(self, "Minecraft Account", "Refresh token (optional):", show="*") or ""
        account = _normalize_mc_account(name, profile_id, access_token, refresh_token)
        account["source"] = "manual"
        account["token_source"] = "manual"
        if refresh_token:
            account["msa_client_id"] = q_ask_string(
                self,
                "Minecraft Account",
                "MSA client id (optional; Prism fills this automatically):"
            ) or ""
        upsert_mc_accounts([account], active_uuid=account.get("uuid"))
        self.refresh()

    def import_tokens(self):
        """Import access/refresh tokens pasted as text (JWT eyJ... or M.C... Artifacts)."""
        dialog = QDialog(self)
        dialog.setWindowTitle("Import Tokens")
        dialog.resize(560, 400)
        dialog.setModal(True)
        layout = QVBoxLayout(dialog)
        layout.addWidget(QLabel(
            "Paste tokens, one per line.\n"
            "  eyJ...            -> Minecraft access token\n"
            "  name:M.C...       -> MSA refresh token (Artifacts)\n"
            "  M.C...            -> MSA refresh token (no name)"
        ))
        text = QPlainTextEdit(dialog)
        layout.addWidget(text, 1)
        row = QHBoxLayout()
        layout.addLayout(row)

        def do_import():
            imported = import_tokens_from_text(text.toPlainText())
            if not imported:
                q_info(dialog, "Import Tokens", "No valid tokens found.")
                return
            upsert_mc_accounts(imported)
            dialog.accept()
            self.refresh()
            self.set_status(f"Imported {len(imported)} token(s). Probe them to fetch names/UUIDs.")

        btn_import = QPushButton("Import")
        btn_import.clicked.connect(do_import)
        row.addWidget(btn_import)
        btn_cancel = QPushButton("Cancel")
        btn_cancel.clicked.connect(dialog.reject)
        row.addWidget(btn_cancel)
        row.addStretch(1)
        dialog.exec()

    def probe_accounts(self):
        """Test/enrich all stored accounts (refresh M.C... tokens, verify JWT tokens)."""
        data = _load_mc_accounts()
        pairs = [(a, _account_key(a)) for a in data.get("accounts", []) if a.get("access_token") or a.get("refresh_token")]
        if not pairs:
            q_info(self, "Accounts", "No accounts to probe.")
            return
        self.set_status(f"Probing {len(pairs)} account(s)...")
        idx = [0]

        def on_update(acc, ok, msg):
            key = pairs[idx[0]][1] if idx[0] < len(pairs) else _account_key(acc)
            idx[0] += 1
            self.after(0, lambda a=acc, o=ok, m=msg, k=key: self._finish_probe(k, a, o, m))

        def on_progress(done, total):
            if done >= total:
                self.after(0, lambda: self.set_status(f"Probe complete: {total} account(s) tested."))

        probe_accounts_async([a for a, _ in pairs], on_update, progress_cb=on_progress)

    def _finish_probe(self, key, acc, ok, msg):
        self._probe_results[key] = (ok, msg)
        if acc.get("uuid"):
            self._probe_results[acc["uuid"]] = (ok, msg)
        if acc.get("name") and acc["name"] != key:
            self._probe_results[acc["name"]] = (ok, msg)
        self.refresh()
        self.set_status(f"Test {acc.get('name') or key}: {'OK' if ok else 'FAILED'} ({msg})")

    def test_selected(self):
        keys = self._selected_keys()
        if not keys:
            q_info(self, "Accounts", "Select one or more accounts first.")
            return
        data = _load_mc_accounts()
        by_key = {_account_key(a): a for a in data.get("accounts", [])}
        accounts = [a for k in keys if k in by_key for a in [by_key[k]]]
        accounts = [a for a in accounts if a.get("access_token") or a.get("refresh_token")]
        if not accounts:
            q_info(self, "Accounts", "No selected account has a token to test.")
            return
        self.set_status(f"Testing {len(accounts)} account(s)...")
        def worker():
            for a in accounts:
                acc, ok, msg = probe_account(a)
                k = _account_key(a)
                self.after(0, lambda a=acc, o=ok, m=msg, kk=k: self._finish_probe(kk, a, o, m))
        threading.Thread(target=worker, daemon=True).start()

    def set_active(self):
        key = self._selected_key()
        if not key:
            q_info(self, "Accounts", "Select an account first.")
            return
        data = _load_mc_accounts()
        account = next((a for a in data.get("accounts", []) if _account_key(a) == key), None)
        if not account or not account.get("uuid"):
            q_info(self, "Accounts", "This account has no UUID yet. Probe it first to fetch its UUID.")
            return
        data["active_uuid"] = account["uuid"]
        _save_mc_accounts(data)
        self.refresh()

    def remove_selected(self):
        keys = self._selected_keys()
        if not keys:
            q_info(self, "Accounts", "Select one or more accounts first.")
            return
        data = _load_mc_accounts()
        kept = [a for a in data.get("accounts", []) if _account_key(a) not in keys]
        removed = len(data.get("accounts", [])) - len(kept)
        data["accounts"] = kept
        active = data.get("active_uuid")
        if active and not any(a.get("uuid") == active for a in kept):
            data["active_uuid"] = next((a.get("uuid", "") for a in kept if a.get("uuid")), "")
        if not data.get("active_uuid") and kept:
            data["active_uuid"] = next((a.get("uuid", "") for a in kept if a.get("uuid")), "")
        _save_mc_accounts(data)
        for k in keys:
            self._probe_results.pop(k, None)
        self.refresh()
        self.set_status(f"Removed {removed} account(s).")

    def remove_failed(self):
        """Remove every account whose last probe FAILED (bad/expired token)."""
        data = _load_mc_accounts()
        kept = []
        removed = []
        for a in data.get("accounts", []):
            key = _account_key(a)
            if self._status_for(a, key).startswith("FAILED"):
                removed.append(a.get("name") or key)
            else:
                kept.append(a)
        if not removed:
            q_info(self, "Accounts", "No failed accounts to remove.")
            return
        data["accounts"] = kept
        active = data.get("active_uuid")
        if active and not any(a.get("uuid") == active for a in kept):
            data["active_uuid"] = next((a.get("uuid", "") for a in kept if a.get("uuid")), "")
        if not data.get("active_uuid") and kept:
            data["active_uuid"] = next((a.get("uuid", "") for a in kept if a.get("uuid")), "")
        _save_mc_accounts(data)
        self._probe_results = {}
        self.refresh()
        self.set_status(f"Removed {len(removed)} failed account(s).")




# ===== Qt port section: qt_network (PySide6, 1:1 behavior) =====
"""PySide6 port of NetworkScanTab (scanner.py lines 4740-5317).

1:1 logic port — only the widget framework changes (tkinter/ttk -> Qt).
Method names, button labels, columns, and background-thread logic preserved.
"""

import threading
from concurrent.futures import ThreadPoolExecutor

from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

class _TextVarAdapter:
    """Compat shim exposing Tk-style .get()/.set() over a QLineEdit."""

    def __init__(self, widget):
        self._w = widget

    def get(self):
        try:
            return self._w.text()
        except Exception:
            return ""

    def set(self, value):
        try:
            self._w.setText(str(value))
        except Exception:
            pass


class _ComboVarAdapter:
    """Compat shim exposing Tk-style .get()/.set() over a QComboBox."""

    def __init__(self, widget):
        self._w = widget

    def get(self):
        try:
            return self._w.currentText()
        except Exception:
            return ""

    def set(self, value):
        try:
            self._w.setCurrentText(str(value))
        except Exception:
            pass


class _BoolVarAdapter:
    """Compat shim exposing Tk-style .get()/.set() over a QCheckBox."""

    def __init__(self, widget):
        self._w = widget

    def get(self):
        try:
            return bool(self._w.isChecked())
        except Exception:
            return False

    def set(self, value):
        try:
            self._w.setChecked(bool(value))
        except Exception:
            pass


class _PlainTextVarAdapter:
    """Compat shim exposing Tk-style .get() over a QPlainTextEdit."""

    def __init__(self, widget):
        self._w = widget

    def get(self, *args, **kwargs):
        try:
            return self._w.toPlainText()
        except Exception:
            return ""


class NetworkScanTab(QtBaseMixin, QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.scan_rows = []
        self._scan_row_map = {}
        self._current_scan_ip = None
        self._cracked_job_id = 0
        self._whitelist_job_id = 0
        self._build_ui()

    # ---- Tk-compat var properties (read through to the Qt widgets) ----
    @property
    def ports_var(self):
        return _TextVarAdapter(self.ports_edit)

    @property
    def max_hosts_var(self):
        return _TextVarAdapter(self.max_hosts_edit)

    @property
    def backend_var(self):
        return _ComboVarAdapter(self.backend_combo)

    @property
    def masscan_rate_var(self):
        return _TextVarAdapter(self.masscan_rate_edit)

    @property
    def masscan_wait_var(self):
        return _TextVarAdapter(self.masscan_wait_edit)

    @property
    def masscan_status_var(self):
        return _TextVarAdapter(self.masscan_status_label)

    @property
    def version_filter_var(self):
        return _ComboVarAdapter(self.version_filter_combo)

    @property
    def pre_version_var(self):
        return _TextVarAdapter(self.pre_version_edit)

    @property
    def only_players_var(self):
        return _BoolVarAdapter(self.only_players_check)

    @property
    def check_cracked_var(self):
        return _BoolVarAdapter(self.check_cracked_check)

    @property
    def check_whitelist_var(self):
        return _BoolVarAdapter(self.check_whitelist_check)

    def _build_ui(self):
        main = QVBoxLayout(self)

        # Top: targets text + ports / max hosts grid.
        top = QWidget(self)
        top_grid = QGridLayout(top)
        top_grid.setContentsMargins(8, 8, 8, 8)
        lbl_targets = QLabel(
            "Targets (IPs/CIDRs/ranges/ASNs \u2014 comma, space or newline separated):", top
        )
        top_grid.addWidget(lbl_targets, 0, 0)
        self.targets_text = QPlainTextEdit(top)
        self.targets_text.setMinimumHeight(4 * 18)
        top_grid.addWidget(self.targets_text, 1, 0, 4, 1)
        top_grid.setColumnStretch(0, 1)

        top_grid.addWidget(QLabel("Ports:", top), 0, 1)
        self.ports_edit = QLineEdit(top)
        try:
            self.ports_edit.setText(NETWORK_SCAN_DEFAULT_PORTS)
        except Exception:
            self.ports_edit.setText("")
        self.ports_edit.setMaximumWidth(220)
        top_grid.addWidget(self.ports_edit, 1, 1)

        lbl_max = QLabel("Max hosts:", top)
        top_grid.addWidget(lbl_max, 2, 1)
        self.max_hosts_edit = QLineEdit(top)
        try:
            self.max_hosts_edit.setText(str(NETWORK_SCAN_MAX_HOSTS))
        except Exception:
            self.max_hosts_edit.setText("")
        self.max_hosts_edit.setMaximumWidth(220)
        top_grid.addWidget(self.max_hosts_edit, 3, 1)
        main.addWidget(top)

        # Backend bar.
        backend_bar = QWidget(self)
        bb = QHBoxLayout(backend_bar)
        bb.setContentsMargins(8, 0, 8, 8)
        bb.addWidget(QLabel("Backend:", backend_bar))
        self.backend_combo = QComboBox(backend_bar)
        self.backend_combo.setEditable(False)
        self.backend_combo.addItems(
            [
                "Auto (masscan \u2192 Python)",
                "masscan (fast SYN + handshake)",
                "Python (handshake only)",
            ]
        )
        self.backend_combo.setCurrentText("Auto (masscan \u2192 Python)")
        self.backend_combo.setMinimumWidth(240)
        bb.addWidget(self.backend_combo)
        bb.addWidget(QLabel("Rate (pps):", backend_bar))
        self.masscan_rate_edit = QLineEdit(backend_bar)
        try:
            self.masscan_rate_edit.setText(str(MASSCAN_DEFAULT_RATE))
        except Exception:
            self.masscan_rate_edit.setText("")
        self.masscan_rate_edit.setMaximumWidth(80)
        bb.addWidget(self.masscan_rate_edit)
        bb.addWidget(QLabel("Wait (s):", backend_bar))
        self.masscan_wait_edit = QLineEdit(backend_bar)
        try:
            self.masscan_wait_edit.setText(str(MASSCAN_DEFAULT_WAIT))
        except Exception:
            self.masscan_wait_edit.setText("")
        self.masscan_wait_edit.setMaximumWidth(60)
        bb.addWidget(self.masscan_wait_edit)
        self.masscan_status_label = QLabel(backend_bar)
        try:
            self.masscan_status_label.setText(masscan_status_line())
        except Exception:
            self.masscan_status_label.setText("")
        bb.addWidget(self.masscan_status_label)
        recheck_btn = QPushButton("Recheck", backend_bar)
        recheck_btn.clicked.connect(
            lambda: self.masscan_status_label.setText(masscan_status_line())
        )
        bb.addWidget(recheck_btn)
        bb.addStretch(1)
        main.addWidget(backend_bar)

        # Controls row.
        controls = QWidget(self)
        cl = QHBoxLayout(controls)
        cl.setContentsMargins(8, 0, 8, 8)
        scan_btn = QPushButton("Scan Targets", controls)
        scan_btn.clicked.connect(self.scan_targets)
        cl.addWidget(scan_btn)
        copy_btn = QPushButton("Copy IP(s)", controls)
        copy_btn.clicked.connect(self.copy_selected)
        cl.addWidget(copy_btn)
        ignore_btn = QPushButton("Add to Ignore", controls)
        ignore_btn.clicked.connect(self.ignore_selected)
        cl.addWidget(ignore_btn)
        save_btn = QPushButton("Add to Saved", controls)
        save_btn.clicked.connect(self.save_selected)
        cl.addWidget(save_btn)
        mon_btn = QPushButton("Add to Monitor", controls)
        mon_btn.clicked.connect(self.add_selected_to_monitor)
        cl.addWidget(mon_btn)
        cl.addWidget(QLabel("Pre version:", controls))
        self.pre_version_edit = QLineEdit(controls)
        self.pre_version_edit.setText("")
        self.pre_version_edit.setMaximumWidth(140)
        cl.addWidget(self.pre_version_edit)
        cl.addWidget(QLabel("Found version:", controls))
        self.version_filter_combo = QComboBox(controls)
        self.version_filter_combo.setEditable(True)
        self.version_filter_combo.addItems(["All versions"])
        self.version_filter_combo.setCurrentText("All versions")
        self.version_filter_combo.setMinimumWidth(150)
        self.version_filter_combo.currentTextChanged.connect(
            lambda _t: self.refresh_scan_tree()
        )
        self.version_filter_combo.lineEdit().textChanged.connect(
            lambda _t: self.refresh_scan_tree()
        )
        cl.addWidget(self.version_filter_combo)
        self.only_players_check = QCheckBox("Only players > 0", controls)
        self.only_players_check.setChecked(False)
        cl.addWidget(self.only_players_check)
        self.check_cracked_check = QCheckBox("Check cracked", controls)
        self.check_cracked_check.setChecked(False)
        cl.addWidget(self.check_cracked_check)
        self.check_whitelist_check = QCheckBox("Check whitelist", controls)
        self.check_whitelist_check.setChecked(False)
        cl.addWidget(self.check_whitelist_check)
        cl.addStretch(1)
        main.addWidget(controls)

        # Results table.
        cols = ("ip", "motd", "players", "version", "cracked", "whitelist", "active_players")
        self.scan_tree = ResultTable(self)
        self.scan_tree.set_columns(cols)
        try:
            widths = {
                "motd": 260,
                "active_players": 260,
                "whitelist": 220,
                "players": 120,
                "version": 120,
                "cracked": 90,
                "ip": 170,
            }
            for idx, col in enumerate(cols):
                try:
                    self.scan_tree.setColumnWidth(idx, widths.get(col, 170))
                except Exception:
                    pass
        except Exception:
            pass
        main.addWidget(self.scan_tree, 1)

        # Bottom row.
        bottom = QWidget(self)
        bl = QHBoxLayout(bottom)
        bl.setContentsMargins(8, 0, 8, 8)
        cracked_btn = QPushButton("Check Cracked", bottom)
        cracked_btn.clicked.connect(
            lambda: check_selected_cracked(self, self.scan_tree)
        )
        bl.addWidget(cracked_btn)
        wl_btn = QPushButton("Check Whitelist", bottom)
        wl_btn.clicked.connect(
            lambda: check_selected_whitelist(self, self.scan_tree)
        )
        bl.addWidget(wl_btn)
        bl.addStretch(1)
        main.addWidget(bottom)

        try:
            self.scan_tree.set_sort_keys(
                {
                    "ip": _ip_key,
                    "motd": lambda v: str(v).lower(),
                    "players": _players_key,
                    "version": _version_key,
                    "cracked": lambda v: (0 if str(v).lower() in ("false", "no", "0") else 1)
                    if v is not None
                    else -1,
                    "whitelist": lambda v: str(v).lower(),
                    "active_players": lambda v: str(v).lower(),
                }
            )
        except Exception:
            try:

                make_tree_sortable(
                    self.scan_tree,
                    {
                        "ip": _ip_key,
                        "motd": lambda v: str(v).lower(),
                        "players": _players_key,
                        "version": _version_key,
                        "cracked": lambda v: (0 if str(v).lower() in ("false", "no", "0") else 1)
                        if v is not None
                        else -1,
                        "whitelist": lambda v: str(v).lower(),
                        "active_players": lambda v: str(v).lower(),
                    },
                )
            except Exception:
                pass
        try:

            _get_icon_manager().attach_to_tree(self.scan_tree)
        except Exception:
            pass

        self.status_label = QLabel("Ready.", self)
        main.addWidget(self.status_label)

    def set_status(self, msg):
        try:
            super().set_status(msg)  # type: ignore[misc]
        except Exception:
            pass
        try:
            self.status_label.setText(str(msg))
        except Exception:
            pass

    def _selected_rows(self):
        rows = []
        for iid in self.scan_tree.selection():
            vals = self.scan_tree.item(iid, "values")
            if vals:
                rows.append(vals)
        return rows

    def _update_version_filter_choices(self, rows):
        choices = collect_version_options([(r[0], r[1], r[2], r[3]) for r in rows])
        try:
            current = self.version_filter_combo.currentText() or "All versions"
        except Exception:
            current = "All versions"
        try:
            self.version_filter_combo.blockSignals(True)
            self.version_filter_combo.clear()
            self.version_filter_combo.addItems(list(choices))
            if current not in choices:
                current = "All versions"
            self.version_filter_combo.setCurrentText(current)
        finally:
            try:
                self.version_filter_combo.blockSignals(False)
            except Exception:
                pass

    def refresh_scan_tree(self):
        self.scan_tree.delete(*self.scan_tree.get_children(""))
        self._scan_row_map = {}
        try:
            filt = self.version_filter_combo.currentText()
        except Exception:
            filt = "All versions"
        for row in self.scan_rows:
            if version_filter_allows(row[3], filt):
                iid = self.scan_tree.insert("", "end", values=row)
                self._scan_row_map[row[0]] = iid

    def _set_tree_row_values(self, iid, vals):
        # Prefer native item setter; fall back to per-column set().
        try:
            self.scan_tree.item(iid, values=vals)
            return
        except Exception:
            pass
        try:
            cols = list(self.scan_tree.columns)
        except Exception:
            cols = []
        for idx, val in enumerate(vals):
            try:
                col = cols[idx] if idx < len(cols) else idx
                self.scan_tree.set(iid, col, val)
            except Exception:
                pass

    def _update_scan_row_cracked(self, ip, text):
        iid = self._scan_row_map.get(ip)
        if not iid:
            return
        vals = list(self.scan_tree.item(iid, "values"))
        if len(vals) >= 5:
            vals[4] = text
            self._set_tree_row_values(iid, vals)
        for idx, row in enumerate(self.scan_rows):
            if row and row[0] == ip:
                row = list(row)
                row[4] = text
                self.scan_rows[idx] = tuple(row)
                break

    def _update_scan_row_whitelist(self, ip, text):
        iid = self._scan_row_map.get(ip)
        if not iid:
            return
        vals = list(self.scan_tree.item(iid, "values"))
        if len(vals) >= 6:
            vals[5] = text
            self._set_tree_row_values(iid, vals)
        for idx, row in enumerate(self.scan_rows):
            if row and row[0] == ip:
                row = list(row)
                row[5] = text
                self.scan_rows[idx] = tuple(row)
                break

    def _prompt_sudo_password(self):
        """Ask for the sudo password on the main thread. Called from a worker
        thread; blocks it until the user answers. Returns
        (password_or_None, error_or_None): error is set when the prompt
        itself broke (vs the user pressing Cancel / closing the window).
        The password is kept in memory for this scan only and never stored."""
        holder = {}
        done = threading.Event()

        def ask():
            try:
                try:
                    self.activateWindow()
                    self.raise_()
                except Exception:
                    pass
                pw, err = SudoPasswordDialog.ask(self)
                holder["pw"] = pw
                holder["err"] = err
            except Exception as exc:
                holder["pw"] = None
                holder["err"] = f"prompt crashed: {exc}"
            finally:
                done.set()

        try:
            self.after(0, ask)
        except Exception as exc:
            return None, f"cannot schedule prompt: {exc}"
        if not done.wait(timeout=300):
            return None, "prompt timed out after 5 minutes (no answer)"
        return holder.get("pw"), holder.get("err")

    def scan_targets(self):
        try:
            max_hosts_raw = int(self.max_hosts_edit.text().strip() or NETWORK_SCAN_MAX_HOSTS)
        except ValueError:
            max_hosts_raw = NETWORK_SCAN_MAX_HOSTS
        backend = ""
        try:
            backend = self.backend_combo.currentText()
        except Exception:
            backend = "Auto (masscan \u2192 Python)"
        use_masscan = backend != "Python (handshake only)"
        if use_masscan:
            max_hosts = max(1, min(max_hosts_raw, MASSCAN_MAX_HOSTS))
        else:
            max_hosts = max(1, min(max_hosts_raw, 65536))
        ports = parse_ports(self.ports_edit.text())
        try:
            masscan_rate = int((self.masscan_rate_edit.text() or "").strip() or MASSCAN_DEFAULT_RATE)
        except ValueError:
            masscan_rate = MASSCAN_DEFAULT_RATE
        try:
            masscan_wait = int((self.masscan_wait_edit.text() or "").strip() or MASSCAN_DEFAULT_WAIT)
        except ValueError:
            masscan_wait = MASSCAN_DEFAULT_WAIT
        targets_raw = self.targets_text.toPlainText()
        # Snapshot widget state here (main thread); work() runs in the background.
        only_players = self.only_players_check.isChecked()
        pre_version = self.pre_version_edit.text().strip()
        check_cracked_flag = self.check_cracked_check.isChecked()
        check_whitelist_flag = self.check_whitelist_check.isChecked()
        self.set_status("Expanding targets...")

        def work():
            try:
                if use_masscan and backend.startswith("masscan") and not is_masscan_available():
                    self.after(0, lambda: self.set_status("masscan not found; install masscan or use Auto/Python backend."))
                    return
                # Shared setup runs first so streamed masscan hits appear in
                # the table the moment their handshake completes.
                self.scan_rows = []
                self._scan_row_map = {}
                self.after(0, lambda: self.scan_tree.delete(*self.scan_tree.get_children("")))
                check_whitelist = check_whitelist_flag
                check_cracked = check_cracked_flag
                # Cracked servers need no account (offline probe, no Mojang auth);
                # account may be None and only online-mode hits will report it.
                account = get_active_mc_account() if check_whitelist else None
                if check_cracked:
                    self._cracked_job_id += 1
                cracked_job = self._cracked_job_id
                cracked_entries = []
                cracked_seen = set()
                if check_whitelist:
                    self._whitelist_job_id += 1
                whitelist_job = self._whitelist_job_id
                whitelist_entries = []
                whitelist_seen = set()
                lock = threading.Lock()
                results = []
                stream_updated = {}

                def on_start(ip):
                    self._current_scan_ip = ip

                def on_result(r, line):
                    if not r:
                        return
                    if only_players and r.get("players", 0) <= 0:
                        return
                    if pre_version and not version_filter_allows(r.get("version", ""), pre_version):
                        return
                    if check_cracked:
                        cached = get_cached_cracked_entry(r["ip"])
                        if cached:
                            cracked_text = "Yes (cached)"
                        elif r.get("cracked"):
                            cracked_text = "Yes?"
                        else:
                            cracked_text = "Queued"
                    else:
                        cracked_text = "Yes" if r.get("cracked") else "No"
                    row = (
                        r["ip"],
                        r["motd"],
                        f"{r['players']}/{r['max_players']}",
                        r["version"],
                        cracked_text,
                        "Queued" if check_whitelist else "-",
                        format_player_list(r.get("players_sample"))
                    )
                    self.scan_rows.append(row)

                    def add_row(row=row):
                        try:
                            filt = self.version_filter_combo.currentText()
                        except Exception:
                            filt = "All versions"
                        if not version_filter_allows(row[3], filt):
                            return
                        iid = self.scan_tree.insert("", "end", values=row)
                        self._scan_row_map[row[0]] = iid

                    self.after(0, add_row)
                    if check_cracked and cracked_text == "Queued":
                        with lock:
                            if r["ip"] not in cracked_seen:
                                cracked_seen.add(r["ip"])
                                cracked_entries.append(r)
                    if check_whitelist:
                        with lock:
                            if r["ip"] not in whitelist_seen:
                                whitelist_seen.add(r["ip"])
                                whitelist_entries.append(r)

                targets = None
                skip_python = False
                masscan_note = ""
                if use_masscan and is_masscan_available():
                    # ---- streaming masscan path: each open port is handed to
                    # the handshake pool (and the GUI) as soon as masscan
                    # reports it, instead of waiting for the whole sweep. ----
                    try:
                        ranges, direct = build_masscan_inputs(targets_raw, ports)
                    except Exception as exc:
                        ranges, direct = [], []
                        if backend.startswith("masscan"):
                            message = str(exc)
                            self.after(0, lambda m=message: self.set_status(f"masscan target error: {m}"))
                            return
                    if not ranges and not direct:
                        targets = []
                    if targets is None:
                        submitted = set()
                        opened_n = {"n": 0}
                        probed_n = {"n": 0}
                        scan_prog = {"pct": None, "rate": None}
                        hs_executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)

                        def update_stream_status():
                            self.after(0, lambda o=opened_n["n"], p=probed_n["n"], f=len(results),
                                       pct=scan_prog["pct"], rate=scan_prog["rate"]:
                                self.set_status(format_stream_status(o, p, f, pct, rate)))

                        def handle_scan_progress(pct, rate):
                            scan_prog["pct"] = pct
                            scan_prog["rate"] = rate
                            update_stream_status()

                        def handle_ping_done(server, fut):
                            try:
                                r = fut.result()
                            except Exception:
                                r = None
                            with lock:
                                probed_n["n"] += 1
                            if r:
                                line = (f"{r['ip']} | MOTD: {r['motd']} | Players: "
                                        f"{r['players']}/{r['max_players']} | Version: {r['version']}")
                                with lock:
                                    results.append(r)
                                    stream_updated[r["ip"]] = line
                                try:
                                    USER_LOG_MANAGER.update_from_result(r)
                                except Exception:
                                    pass
                                try:
                                    on_result(r, line)
                                except Exception:
                                    pass
                            update_stream_status()

                        def handle_open(ip_port):
                            with lock:
                                if ip_port in submitted:
                                    return
                                submitted.add(ip_port)
                                opened_n["n"] += 1
                            on_start(ip_port)
                            try:
                                fut = hs_executor.submit(ping_server, ip_port)
                            except Exception:
                                return
                            fut.add_done_callback(lambda f, s=ip_port: handle_ping_done(s, f))
                            update_stream_status()

                        def finish_stream_error(msg):
                            """Common failure exit. Returns 'fallback' or 'abort'."""
                            try:
                                hs_executor.shutdown(wait=True)
                            except Exception:
                                pass
                            if backend.startswith("masscan"):
                                merge_global_ip_log(stream_updated)
                                self.after(0, lambda rows=list(self.scan_rows): self._update_version_filter_choices(rows))
                                self.after(0, lambda m=msg: self.set_status(m))
                                return "abort"
                            self.after(0, lambda m=msg: self.set_status(m + " Falling back to Python scan..."))
                            return "fallback"

                        for d in direct:
                            handle_open(d)
                        eta = _format_masscan_eta(_masscan_estimate_seconds(
                            ranges, ports, masscan_rate, masscan_wait))
                        self.after(0, lambda e=eta: self.set_status(
                            f"masscan: discovering open ports (live){e}..."))
                        outcome = "ok"
                        try:
                            _, masscan_note = run_masscan_streaming(
                                ranges, ports, rate=masscan_rate,
                                wait=masscan_wait, on_open=handle_open,
                                on_scan_progress=handle_scan_progress)
                        except PermissionError:
                            if sudo_available() and ranges:
                                self.after(0, lambda: self.set_status("masscan needs root; trying sudo..."))
                                passwordless = sudo_noninteractive_ok()
                                sudo_pw = None
                                sudo_err = None
                                if passwordless:
                                    self.after(0, lambda: self.set_status("masscan: retrying with sudo..."))
                                else:
                                    self.after(0, lambda: self.set_status(
                                        "sudo password required \u2014 waiting for the popup..."))
                                    sudo_pw, sudo_err = self._prompt_sudo_password()
                                if passwordless or sudo_pw:
                                    try:
                                        self.after(0, lambda e=eta: self.set_status(
                                            f"masscan: discovering open ports with sudo (live){e}..."))
                                        _, masscan_note = run_masscan_streaming(
                                            ranges, ports, rate=masscan_rate,
                                            wait=masscan_wait, on_open=handle_open,
                                            on_scan_progress=handle_scan_progress,
                                            use_sudo=True, sudo_password=sudo_pw)
                                        sudo_pw = None
                                    except PermissionError as exc2:
                                        outcome = finish_stream_error(f"sudo failed: {exc2}")
                                    except Exception as exc2:
                                        outcome = finish_stream_error(f"masscan with sudo failed: {exc2}")
                                else:
                                    if sudo_err:
                                        outcome = finish_stream_error(
                                            f"sudo prompt failed ({sudo_err}). "
                                            "Tip: run 'sudo -v' in Terminal, then scan again")
                                    else:
                                        outcome = finish_stream_error("sudo canceled")
                            else:
                                outcome = finish_stream_error("masscan needs privileges")
                        except Exception as exc:
                            outcome = finish_stream_error(f"masscan failed: {exc}")
                        if outcome == "abort":
                            return
                        if outcome == "fallback":
                            try:
                                hs_executor.shutdown(wait=True)
                            except Exception:
                                pass
                            targets = [t for t in expand_scan_targets(targets_raw, ports, max_hosts=max_hosts)
                                       if t not in submitted]
                        else:
                            try:
                                hs_executor.shutdown(wait=True)
                            except Exception:
                                pass
                            skip_python = True
                if not skip_python:
                    if targets is None:
                        targets = expand_scan_targets(targets_raw, ports, max_hosts=max_hosts)
                    if not targets and not results:
                        self.after(0, lambda: self.set_status("No valid targets to scan."))
                        merge_global_ip_log(stream_updated)
                        return
                    if targets:
                        def on_progress(done, total):
                            self.after(0, lambda d=done, t=total:
                                       self.set_status(f"Network scan: {d}/{t}"))

                        more, _ = scan_servers_gui(
                            targets,
                            on_start=on_start,
                            on_result=on_result,
                            on_progress=on_progress
                        )
                        results.extend(more)
                merge_global_ip_log(stream_updated)
                self.after(0, lambda rows=list(self.scan_rows): self._update_version_filter_choices(rows))
                if _masscan_note_is_partial(masscan_note):
                    self.after(0, lambda n=len(results): self.set_status(
                        "Scan complete \u2014 masscan stopped early (timeout), results partial. "
                        f"Minecraft servers: {n}."))
                else:
                    self.after(0, lambda n=len(results): self.set_status(f"Scan complete. Minecraft servers: {n}."))

                if check_cracked:
                    with lock:
                        entries = list(cracked_entries)

                    def handle_cracked_update(entry, result, message, was_cached):
                        if cracked_job != self._cracked_job_id:
                            return
                        if was_cached or result is True:
                            label = "Yes (cached)" if was_cached else "Yes"
                        elif result is False:
                            label = "No"
                        else:
                            label = "Unknown"
                        self.after(0, lambda ip=entry.get("ip"), label=label:
                                   self._update_scan_row_cracked(ip, label))

                    def handle_cracked_progress(done, total):
                        if cracked_job != self._cracked_job_id:
                            return
                        self.after(0, lambda d=done, t=total:
                                   self.set_status(f"Checking cracked: {d}/{t}"))
                    run_cracked_verifier_async(entries, handle_cracked_update, progress_cb=handle_cracked_progress)

                if check_whitelist:
                    with lock:
                        entries = list(whitelist_entries)

                    def handle_update(entry, result, message):
                        if whitelist_job != self._whitelist_job_id:
                            return
                        label = whitelist_result_label(result, message)
                        self.after(0, lambda ip=entry.get("ip"), label=label:
                                   self._update_scan_row_whitelist(ip, label))

                    def handle_progress(done, total):
                        if whitelist_job != self._whitelist_job_id:
                            return
                        self.after(0, lambda d=done, t=total:
                                   self.set_status(f"Checking whitelist: {d}/{t}"))
                    run_whitelist_verifier_async(entries, account, handle_update, progress_cb=handle_progress)
            except Exception as exc:
                message = str(exc)
                self.after(0, lambda m=message: self.set_status(f"Scan failed: {m}"))

        threading.Thread(target=work, daemon=True).start()

    def copy_selected(self):
        rows = self._selected_rows()
        if not rows:
            q_info(self, "Network Scan", "Select one or more rows.")
            return
        try:
            QApplication.clipboard().setText("\n".join(row[0] for row in rows))
        except Exception:
            pass
        self.set_status(f"Copied {len(rows)} IP(s).")

    def ignore_selected(self):
        rows = self._selected_rows()
        if not rows:
            q_info(self, "Network Scan", "Select one or more rows.")
            return
        reason = ask_reason_with_whitelist(self, "Reason", "Why ignore? (optional)")
        if reason is None:
            return
        for row in rows:
            add_to_ignore(row[0], reason or "")
        self.set_status(f"Added {len(rows)} to ignore.txt.")

    def save_selected(self):
        rows = self._selected_rows()
        if not rows:
            q_info(self, "Network Scan", "Select one or more rows.")
            return
        reason = q_ask_string(self, "Reason", "Why save? (optional)")
        for row in rows:
            add_to_saved(row[0], reason or "")
        self.set_status(f"Added {len(rows)} to saved.txt.")

    def add_selected_to_monitor(self):
        rows = self._selected_rows()
        if not rows:
            q_info(self, "Network Scan", "Select one or more rows.")
            return
        added, invalid, duplicates = add_ips_to_monitor_list([row[0] for row in rows])
        self.set_status(format_monitor_feedback(added, invalid, duplicates))


# ===== Qt port section: qt_proxy (PySide6, 1:1 behavior) =====
"""PySide6 port of ProxyTab (scanner.py:5317-5696). 1:1 logic, widget calls translated."""

import os
import threading

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QLineEdit, QPlainTextEdit, QCheckBox, QRadioButton, QComboBox,
    QGroupBox, QButtonGroup,
)




class ProxyTab(QWidget, QtBaseMixin):
    """
    Proxy manager + bulk whitelist scanner.
      - Paste proxies as 'ip:port' (HTTP) or 'ip:port:user:pass' (SOCKS5).
      - Test each proxy, save the list to proxies.json.
      - Run a bulk whitelist scan that cycles accounts AND proxies in parallel.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.proxies = []
        self.servers = []          # list[str] ip:port
        self._bulk_job = 0
        self._current_bulk = None
        self._build_ui()
        self.refresh()

    def _build_ui(self):
        root = QVBoxLayout(self)

        bar = QHBoxLayout()
        root.addLayout(bar)
        btn_import_text = QPushButton("Import from Text")
        btn_import_text.clicked.connect(self.import_text)
        bar.addWidget(btn_import_text)
        btn_import_file = QPushButton("Import from File")
        btn_import_file.clicked.connect(self.import_file)
        bar.addWidget(btn_import_file)
        btn_save = QPushButton("Save")
        btn_save.clicked.connect(self.save)
        bar.addWidget(btn_save)
        btn_test_all = QPushButton("Test All")
        btn_test_all.clicked.connect(self.test_all)
        bar.addWidget(btn_test_all)
        btn_test_selected = QPushButton("Test Selected")
        btn_test_selected.clicked.connect(self.test_selected)
        bar.addWidget(btn_test_selected)
        btn_clear = QPushButton("Clear")
        btn_clear.clicked.connect(self.clear)
        bar.addWidget(btn_clear)
        btn_reload = QPushButton("Reload")
        btn_reload.clicked.connect(self.refresh)
        bar.addWidget(btn_reload)
        self.use_proxy_mode = QCheckBox("Use proxies for all whitelist scans")
        self.use_proxy_mode.setChecked(whitelist_proxy_mode())
        self.use_proxy_mode.toggled.connect(self._toggle_proxy_mode)
        bar.addWidget(self.use_proxy_mode)
        bar.addStretch(1)

        paste_label = QLabel("Paste proxies, one per line. 'ip:port' = HTTP, 'ip:port:user:pass' = SOCKS5:")
        root.addWidget(paste_label)
        self.paste_text = QPlainTextEdit()
        self.paste_text.setFixedHeight(90)
        root.addWidget(self.paste_text)

        cols = ("host", "port", "type", "user", "status", "message")
        self.tree = ResultTable(self, columns=list(cols), headers=[c.upper() for c in cols])
        root.addWidget(self.tree)

        # --- Bulk whitelist scan ---
        scan = QGroupBox("Bulk Whitelist Scan  (cycles accounts + proxies in parallel)")
        root.addWidget(scan)
        scan_layout = QVBoxLayout(scan)

        row = QHBoxLayout()
        scan_layout.addLayout(row)
        row.addWidget(QLabel("Server list (.txt):"))
        self.server_file = QLineEdit()
        self.server_file.setMinimumWidth(300)
        row.addWidget(self.server_file)
        btn_browse = QPushButton("Browse")
        btn_browse.clicked.connect(self._pick_server_file)
        row.addWidget(btn_browse)
        btn_load = QPushButton("Load")
        btn_load.clicked.connect(self._load_server_list)
        row.addWidget(btn_load)
        row.addWidget(QLabel("  Loaded: "))
        self.server_count_label = QLabel("0")
        self.server_count_label.setMinimumWidth(40)
        row.addWidget(self.server_count_label)
        row.addStretch(1)

        row2 = QHBoxLayout()
        scan_layout.addLayout(row2)
        row2.addWidget(QLabel("Workers (0 = auto / per working proxy):"))
        self.workers_edit = QLineEdit("0")
        self.workers_edit.setMaximumWidth(60)
        row2.addWidget(self.workers_edit)
        self.use_all_accounts = QCheckBox("Use all accounts")
        self.use_all_accounts.setChecked(True)
        row2.addWidget(self.use_all_accounts)
        btn_start = QPushButton("Start Scan")
        btn_start.clicked.connect(self.start_bulk_scan)
        row2.addWidget(btn_start)
        btn_stop = QPushButton("Stop")
        btn_stop.clicked.connect(self.stop_bulk_scan)
        row2.addWidget(btn_stop)
        btn_export = QPushButton("Export Results")
        btn_export.clicked.connect(self.export_bulk_results)
        row2.addWidget(btn_export)
        row2.addStretch(1)

        row3 = QHBoxLayout()
        scan_layout.addLayout(row3)
        row3.addWidget(QLabel("Initial scan via:"))
        self.realip_radio = QRadioButton("My IP")
        self.realip_radio.setChecked(True)
        row3.addWidget(self.realip_radio)
        self.single_radio = QRadioButton("Single proxy")
        row3.addWidget(self.single_radio)
        self._initial_proxy_group = QButtonGroup(self)
        self._initial_proxy_group.addButton(self.realip_radio)
        self._initial_proxy_group.addButton(self.single_radio)
        self.initial_proxy_choice = QComboBox()
        self.initial_proxy_choice.setEditable(False)
        self.initial_proxy_choice.setMinimumWidth(200)
        row3.addWidget(self.initial_proxy_choice)
        row3.addWidget(QLabel("  (status scan finds live servers, then whitelist scan uses the proxies)"))
        row3.addStretch(1)

        self.scan_status_label = QLabel("Load a server list to begin.")
        self.scan_status_label.setWordWrap(True)
        scan_layout.addWidget(self.scan_status_label)

        res_cols = ("ip", "result", "detail", "account", "proxy")
        self.res_tree = ResultTable(self, columns=list(res_cols), headers=[c.upper() for c in res_cols])
        scan_layout.addWidget(self.res_tree)

        self.status_label = QLabel("Ready.")
        root.addWidget(self.status_label)

    # QtBaseMixin is assumed to provide after() / set_status(); keep local
    # status label in sync for the translated StringVar calls.
    def set_status(self, msg):
        try:
            super().set_status(msg)  # type: ignore[attr-defined]
        except Exception:
            pass
        try:
            self.status_label.setText(msg)
        except Exception:
            pass

    def _initial_mode(self):
        return "single" if self.single_radio.isChecked() else "realip"

    # ---- proxy list management ----
    def refresh(self):
        self.proxies = load_proxies()
        self.tree.delete(*self.tree.get_children())
        for p in self.proxies:
            status = "Working" if p.get("working") is True else ("Failed" if p.get("working") is False else "-")
            self.tree.insert(
                "",
                "end",
                values=(
                    p.get("host", ""),
                    p.get("port", ""),
                    p.get("type", ""),
                    p.get("user", ""),
                    status,
                    p.get("message", "")
                )
            )
        working = sum(1 for p in self.proxies if p.get("working") is True)
        self.set_status(f"{len(self.proxies)} proxy(ies) loaded. {working} working.")
        choices = [proxy_display(p) for p in self.proxies]
        current = self.initial_proxy_choice.currentText()
        self.initial_proxy_choice.clear()
        if choices:
            self.initial_proxy_choice.addItems(choices)
            if not current:
                self.initial_proxy_choice.setCurrentIndex(0)
            else:
                idx = self.initial_proxy_choice.findText(current)
                self.initial_proxy_choice.setCurrentIndex(idx if idx >= 0 else 0)

    def _toggle_proxy_mode(self):
        enabled = self.use_proxy_mode.isChecked()
        set_whitelist_proxy_mode(enabled)
        if enabled:
            self.set_status("Proxy mode ON: all whitelist scans cycle proxies + all accounts.")
        else:
            self.set_status("Proxy mode OFF: whitelist scans use a single account directly.")

    def import_text(self):
        text = self.paste_text.toPlainText()
        added = 0
        seen = {(p.get("host"), p.get("port")) for p in self.proxies}
        for line in text.splitlines():
            p = parse_proxy_line(line)
            if p and (p["host"], p["port"]) not in seen:
                seen.add((p["host"], p["port"]))
                self.proxies.append(p)
                added += 1
        save_proxies(self.proxies)
        self.refresh()
        self.set_status(f"Imported {added} new proxy(ies).")
        self.paste_text.clear()

    def import_file(self):
        path = q_ask_open("Import proxies", "Text (*.txt);;All files (*.*)")
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read()
        except Exception as exc:
            q_error("Proxies", f"Could not read file: {exc}")
            return
        added = 0
        seen = {(p.get("host"), p.get("port")) for p in self.proxies}
        for line in text.splitlines():
            p = parse_proxy_line(line)
            if p and (p["host"], p["port"]) not in seen:
                seen.add((p["host"], p["port"]))
                self.proxies.append(p)
                added += 1
        save_proxies(self.proxies)
        self.refresh()
        self.set_status(f"Imported {added} new proxy(ies) from file.")

    def save(self):
        save_proxies(self.proxies)
        self.set_status("Proxies saved to proxies.json.")

    def clear(self):
        self.proxies = []
        save_proxies(self.proxies)
        self.refresh()

    def test_all(self):
        if not self.proxies:
            q_info("Proxies", "No proxies loaded.")
            return
        self.set_status(f"Testing {len(self.proxies)} proxy(ies) in parallel...")

        def on_progress(done, total):
            if done >= total:
                self.after(150, self.refresh)
                self.after(0, lambda d=done: self.set_status(f"Proxy test complete: {d}/{total} tested."))
            else:
                self.after(0, lambda d=done, t=total: self.set_status(f"Testing proxies: {d}/{t}"))
        probe_proxies_async(self.proxies, lambda p, ok, msg: None, progress_cb=on_progress)

    def test_selected(self):
        selected = set(self.tree.selection())
        if not selected:
            q_info("Proxies", "Select one or more proxies first.")
            return
        targets = [p for iid, p in zip(self.tree.get_children(), self.proxies) if iid in selected]
        if not targets:
            return
        self.set_status(f"Testing {len(targets)} selected proxy(ies) in parallel...")

        def on_progress(done, total):
            if done >= total:
                self.after(150, self.refresh)
                self.after(0, lambda d=done: self.set_status(f"Selected proxy test complete: {d}/{total} tested."))
            else:
                self.after(0, lambda d=done, t=total: self.set_status(f"Testing selected proxies: {d}/{t}"))
        probe_proxies_async(targets, lambda p, ok, msg: None, progress_cb=on_progress)

    # ---- bulk whitelist scan ----
    def _pick_server_file(self):
        path = q_ask_open("Pick server list", "Text (*.txt);;All files (*.*)")
        if path:
            self.server_file.setText(path)
            self._load_server_list()

    def _load_server_list(self):
        path = self.server_file.text().strip()
        if not path:
            q_info("Bulk Whitelist", "Pick a server list file first.")
            return
        try:
            self.servers = read_servers(path)
        except Exception as exc:
            q_error("Bulk Whitelist", f"Could not read server list: {exc}")
            return
        self.server_count_label.setText(str(len(self.servers)))
        self.scan_status_label.setText(f"Loaded {len(self.servers)} server(s) from {os.path.basename(path)}.")

    def start_bulk_scan(self):
        if not self.servers:
            q_info("Bulk Whitelist", "Load a server list first.")
            return
        # Use all proxies that aren't known-dead. No need to pre-test the list —
        # dead proxies simply fail per-probe and are skipped as workers.
        proxies = [p for p in self.proxies if p.get("working") is not False]
        if not proxies:
            q_info("Bulk Whitelist", "No proxies loaded. Add some in the Proxies tab first.")
            return
        accounts = get_all_mc_accounts() if self.use_all_accounts.isChecked() else [a for a in [get_active_mc_account()] if a]
        # Cracked servers need no account (offline probe, no Mojang auth), so
        # allow the scan with zero accounts; online-mode hits will report it.
        try:
            workers = int(self.workers_edit.text().strip() or "0")
        except ValueError:
            workers = 0
        job = self._bulk_job + 1
        self._bulk_job = job
        self.res_tree.delete(*self.res_tree.get_children())
        self._current_bulk = {"job": job, "accounts": accounts, "proxies": proxies, "workers": workers}

        # Stage 1: initial status scan (real IP, or optionally a single proxy) to
        # find live hosts before spending proxies + account auth on whitelist probes.
        initial_proxy = None
        if self._initial_mode() == "single":
            chosen = self.initial_proxy_choice.currentText()
            for p in proxies:
                if proxy_display(p) == chosen:
                    initial_proxy = p
                    break
        via = proxy_display(initial_proxy) if initial_proxy else "your IP"
        self.scan_status_label.setText(f"Initial scan of {len(self.servers)} server(s) via {via}...")

        live = []
        live_lock = threading.Lock()

        def on_init_result(server, result):
            if job != self._bulk_job:
                return
            if result:
                with live_lock:
                    live.append({"ip": result["ip"], "protocol": result.get("protocol"), "version": result.get("version", "")})

        def on_init_progress(done, total):
            if job != self._bulk_job:
                return
            if done >= total:
                self.after(0, lambda: self._start_whitelist_stage(job, list(live)))
            else:
                self.after(0, lambda d=done, t=total, n=len(live): self.scan_status_label.setText(
                    f"Initial scan: {d}/{t} (found {n} live)..."))

        run_status_scan_async(self.servers, on_init_result, progress_cb=on_init_progress, proxy=initial_proxy)

    def _start_whitelist_stage(self, job, entries):
        """Stage 2: run the parallel whitelist scan only on live servers."""
        if job != self._bulk_job:
            return
        if not entries:
            self.scan_status_label.setText("Initial scan found no live servers.")
            return
        bulk = self._current_bulk
        accounts = bulk["accounts"]
        proxies = bulk["proxies"]
        workers = bulk["workers"]
        self.scan_status_label.setText(
            f"Initial scan done: {len(entries)} live. Whitelist scan through {len(proxies)} proxy(ies)..."
        )

        def on_update(entry, result, message, account, proxy):
            if job != self._bulk_job:
                return
            ip = entry.get("ip", "")
            label = whitelist_result_label(result, message)
            acc_name = (account or {}).get("name", "")
            proxy_str = proxy_display(proxy) if proxy else "-"
            self.after(0, lambda: self.res_tree.insert(
                "", "end",
                values=(ip, label, sanitize_motd(message or "")[:160], acc_name, proxy_str)
            ))

        def on_progress(done, total):
            if job != self._bulk_job:
                return
            if done >= total:
                self.after(0, lambda: self.scan_status_label.setText(
                    f"Bulk whitelist scan complete: {done}/{total} live servers. Export below."
                ))
            else:
                self.after(0, lambda d=done, t=total: self.scan_status_label.setText(
                    f"Whitelist scan: {d}/{t} of {len(entries)} live servers"))

        run_bulk_whitelist_verifier_async(entries, accounts, proxies, on_update, progress_cb=on_progress, workers=workers)

    def stop_bulk_scan(self):
        self._bulk_job += 1
        self.scan_status_label.setText("Bulk scan stopped.")

    def export_bulk_results(self):
        whitelisted = []
        not_whitelisted = []
        for item in self.res_tree.get_children():
            vals = self.res_tree.item(item, "values")
            if len(vals) < 2:
                continue
            ip, label = vals[0], vals[1]
            if label.lower().startswith("whitelisted"):
                whitelisted.append(ip)
            elif label.lower().startswith("not whitelisted"):
                not_whitelisted.append(ip)
        if not (whitelisted or not_whitelisted):
            q_info("Bulk Whitelist", "No results to export yet.")
            return
        path = q_ask_save("Export bulk whitelist results", "bulk_whitelist_results.txt", "Text (*.txt)")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write("# Whitelisted\n")
                f.write("\n".join(whitelisted) + "\n")
                f.write("# Not Whitelisted\n")
                f.write("\n".join(not_whitelisted) + "\n")
            self.scan_status_label.setText(f"Exported {len(whitelisted)} whitelisted / {len(not_whitelisted)} not-whitelisted.")
        except Exception as exc:
            q_error("Bulk Whitelist", f"Export failed: {exc}")


# ===== Qt port section: qt_servers (PySide6, 1:1 behavior) =====
"""PySide6 port of ServersTab (scanner.py lines 5737-6349).

1:1 translation of the Tk ``ServersTab`` (``FullAppGUI`` is ported by a
separate worker and is intentionally NOT included here).

Widget translation map (logic unchanged):
  - ttk.Frame + grid/pack          -> QWidget + QVBoxLayout/QHBoxLayout
  - tk.PanedWindow (vertical)      -> QSplitter(Qt.Vertical)
  - ttk.Treeview                   -> ResultTable (qt_helpers, Treeview-API
                                     compatible: insert/delete/get_children/
                                     selection/item/selection_set/
                                     selection_remove/focus/see)
  - BooleanVar/Checkbutton         -> QCheckBox (+ isChecked/setChecked)
  - StringVar/Combobox (editable)  -> QComboBox editable (+ currentText)
  - StringVar/Entry                -> QLineEdit (+ text)
  - StringVar/Label                -> QLabel (+ setText)
  - messagebox/simpledialog/filedialog -> q_info/q_error/q_ask_string/
                                     q_ask_open/q_ask_save (qt_helpers)
  - ask_reason_with_whitelist      -> qt_helpers.ask_reason_with_whitelist
  - clipboard_clear/append         -> QApplication.clipboard().setText
  - self.after                     -> QtBaseMixin.after (unchanged call sites)

Backend references (scan helpers, ignore/saved lists, monitor list,
whitelist/cracked verifiers, formatting/parsing utils) are imported
as-is from ``scanner``.
"""

import os
import threading

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSplitter,
    QVBoxLayout,
    QWidget,
)




class ServersTab(QWidget, QtBaseMixin):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.current_source = None
        self.servers = []  # list[str] of IP:PORT
        self.source_rows = []  # list[tuple(ip,motd,players,version)]
        self._in_ignore = False  # re-entrancy guard
        self._build_ui()
        self._current_scan_ip = None
        self._scan_row_map = {}
        self._cracked_job_id = 0
        self._whitelist_job_id = 0

    def add_ignore(self):
        sel = self._selected_ips_any()
        if not sel:
            q_info(self, "Info", "Select one or more.")
            return
        # use the new dialog that offers a "White List" shortcut button
        reason = ask_reason_with_whitelist(self, "Reason", "Why ignore? (optional)")
        # If user cancelled (None), do nothing
        if reason is None:
            self.set_status("Ignore cancelled.")
            return
        for ip in sel:
            add_to_ignore(ip, reason or "")
        # remove from self.servers
        self.servers = [s for s in self.servers if s not in sel]
        self.refresh_list()
        self.set_status(f"Added {len(sel)} to ignore.txt")

    def add_saved(self):
        sel = self._selected_ips_any()
        if not sel:
            q_info(self, "Info", "Select one or more.")
            return
        reason = q_ask_string(self, "Reason", "Why save? (optional)")
        for ip in sel:
            add_to_saved(ip, reason or "")
        self.set_status(f"Added {len(sel)} to saved.txt")

    def _build_ui(self):
        root = QVBoxLayout(self)

        # Splitter: top (source) / middle (results) — replaces PanedWindow
        splitter = QSplitter(Qt.Vertical, self)
        root.addWidget(splitter, 1)

        # --- Source area (TOP) ---
        pane_top = QWidget(splitter)
        top_layout = QVBoxLayout(pane_top)
        top_layout.setContentsMargins(8, 8, 8, 8)

        self.src_label = QLabel("Source: (none)", pane_top)
        top_layout.addWidget(self.src_label)

        middle = QWidget(pane_top)
        middle_layout = QHBoxLayout(middle)
        middle_layout.setContentsMargins(0, 0, 0, 0)
        top_layout.addWidget(middle, 1)

        # Source Table
        source_cols = ["ip", "motd", "players", "version", "cracked"]
        self.source_tree = ResultTable(middle, columns=source_cols)
        self.source_tree.setHorizontalHeaderLabels([c.upper() for c in source_cols])
        _source_widths = {"motd": 240, "players": 120, "version": 120,
                          "cracked": 90}
        for i, c in enumerate(source_cols):
            self.source_tree.setColumnWidth(i, _source_widths.get(c, 170))
        self.source_tree.setSortingEnabled(True)
        middle_layout.addWidget(self.source_tree, 1)

        # Right-side button column
        right = QWidget(middle)
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(8, 0, 0, 0)
        middle_layout.addWidget(right, 0)

        def _right_btn(label, slot):
            btn = QPushButton(label, right)
            btn.clicked.connect(slot)
            right_layout.addWidget(btn)
            return btn

        _right_btn("Import .txt", self.load_txt)
        _right_btn("Copy IP", self.copy_ip)
        _right_btn("Add to Ignore", self.add_ignore)
        _right_btn("Add to Saved", self.add_saved)
        _right_btn("Add to Monitor", self.add_search_selected_to_monitor)
        sep = QFrame(right)
        sep.setFrameShape(QFrame.HLine)
        right_layout.addWidget(sep)
        _right_btn("Scan Selected", self.scan_selected)
        _right_btn("Scan All", self.scan_all)

        self.only_players = QCheckBox("Only players > 0", right)
        self.only_players.setChecked(True)
        right_layout.addWidget(self.only_players)
        self.only_cracked = QCheckBox("Only cracked servers", right)
        self.only_cracked.setChecked(False)
        right_layout.addWidget(self.only_cracked)
        self.check_whitelist = QCheckBox("Check whitelist", right)
        self.check_whitelist.setChecked(False)
        right_layout.addWidget(self.check_whitelist)

        right_layout.addWidget(QLabel("Version filter:", right))
        self.version_filter = QComboBox(right)
        self.version_filter.setEditable(True)
        self.version_filter.addItems(["All versions"])
        self.version_filter.setCurrentText("All versions")
        right_layout.addWidget(self.version_filter)
        self.version_filter.currentTextChanged.connect(lambda _t: self.refresh_list())
        if self.version_filter.lineEdit() is not None:
            self.version_filter.lineEdit().textEdited.connect(lambda _t: self.refresh_list())
        right_layout.addStretch(1)

        splitter.addWidget(pane_top)

        # --- Results area (MIDDLE) ---
        pane_mid = QWidget(splitter)
        mid_layout = QVBoxLayout(pane_mid)
        mid_layout.setContentsMargins(8, 8, 8, 8)
        mid_layout.addWidget(QLabel("Results (select to copy/save/ignore):", pane_mid))

        results_cols = ["ip", "motd", "players", "version", "cracked",
                        "whitelist", "active_players"]
        self.results_tree = ResultTable(pane_mid, columns=results_cols)
        self.results_tree.setHorizontalHeaderLabels([c.upper() for c in results_cols])
        _results_widths = {"motd": 240, "active_players": 240, "players": 130,
                           "version": 130, "whitelist": 220, "cracked": 90}
        for i, c in enumerate(results_cols):
            self.results_tree.setColumnWidth(i, _results_widths.get(c, 170))
        self.results_tree.setSortingEnabled(True)
        mid_layout.addWidget(self.results_tree, 1)
        try:
            _get_icon_manager().attach_to_tree(self.results_tree)
        except Exception:
            pass


        splitter.addWidget(pane_mid)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 1)

        # ------- Footer (pinned) -------
        footer = QWidget(self)
        footer_layout = QHBoxLayout(footer)
        footer_layout.setContentsMargins(8, 6, 8, 8)
        root.addWidget(footer)

        def _foot_btn(label, slot):
            btn = QPushButton(label, footer)
            btn.clicked.connect(slot)
            footer_layout.addWidget(btn)
            return btn

        _foot_btn("Copy IP(s)", self.copy_scan_selected)
        _foot_btn("Add to Ignore", self.ignore_scan_selected)
        _foot_btn("Add to Saved", self.save_scan_selected)
        _foot_btn("Add to Monitor", self.add_scan_selected_to_monitor)
        _foot_btn("Export Scan…", self.export_scan_results)
        _foot_btn("Check Whitelist",
                 lambda: check_selected_whitelist(self, self.results_tree))
        self.player_search = QLineEdit(footer)
        self.player_search.setMaximumWidth(180)
        self.player_search.returnPressed.connect(self.search_players)
        footer_layout.addWidget(self.player_search)
        _foot_btn("Find Player", self.search_players)

        self.status_label = QLabel("Ready.", footer)
        footer_layout.addWidget(self.status_label, 1)

    def set_status(self, msg):
        self.status_label.setText(msg)

    def _update_version_filter_choices(self, rows):
        choices = collect_version_options(rows)
        current = self.version_filter.currentText() or "All versions"
        self.version_filter.blockSignals(True)
        try:
            self.version_filter.clear()
            self.version_filter.addItems(choices)
            if current not in choices:
                current = "All versions"
            self.version_filter.setCurrentText(current)
        finally:
            self.version_filter.blockSignals(False)

    def refresh_list(self, items=None):
        # populate source_tree using parsed rows when available
        for iid in self.source_tree.get_children():
            self.source_tree.delete(iid)
        if items is not None:
            rows = [(ip, "", "", "") for ip in items]  # explicit override
        elif self.source_rows:
            rows = self.source_rows
        else:
            rows = [(ip, "", "", "") for ip in self.servers]
        if items is None and rows and len(rows[0]) >= 4:
            rows = [row for row in rows
                    if version_filter_allows(row[3], self.version_filter.currentText())]
        for row in rows:
            self.source_tree.insert("", "end", values=row)

    def load_txt(self):
        path = q_ask_open(self, "Open .txt", "Text files (*.txt);;All files (*.*)")
        if not path:
            return
        try:
            rows = []  # (ip,motd,players,version)
            seen = set()  # prevent duplicates
            total_lines = 0
            skipped_ignored = 0
            skipped_invalid = 0
            skipped_duplicates = 0
            with open(path, "r", encoding="utf-8") as f:
                for ln in f:
                    total_lines += 1
                    ln = ln.strip()
                    if not ln:
                        continue
                    # Try to parse full formatted line first
                    ip, motd, players, version = parse_formatted_line(ln)
                    ip = get_ip_only(ip)
                    if not is_valid_ip_port(ip):
                        skipped_invalid += 1
                        continue
                    if is_ignored(ip):
                        skipped_ignored += 1
                        continue
                    if ip in seen:
                        skipped_duplicates += 1
                        continue
                    seen.add(ip)
                    rows.append((ip, motd, players, version))
            # update state
            self.current_source = path
            self.source_rows = rows
            self.servers = [ip for (ip, _, _, _) in rows]  # keep scan list intact
            self._update_version_filter_choices(rows)
            self.src_label.setText(
                f"Source: {os.path.basename(path)} ({len(rows)} entries)")
            self.refresh_list()
            # Build status message with helpful stats
            parts = [f"Loaded {len(rows)} entries."]
            if skipped_duplicates:
                parts.append(f"{skipped_duplicates} duplicate(s) skipped.")
            if skipped_invalid:
                parts.append(f"{skipped_invalid} invalid line(s) skipped.")
            if skipped_ignored:
                parts.append(f"{skipped_ignored} ignored (in ignore.txt) skipped.")
            self.set_status(" ".join(parts))
        except Exception as e:
            q_error(self, "Load error", str(e))

    def _selected_ips_from_tree(self, tree):
        sel = []
        for iid in tree.selection():
            vals = tree.item(iid, "values")
            if vals:
                sel.append(vals[0])
        return sel

    def _selected_ips_any(self):
        ips = []
        ips.extend(self._selected_ips_from_tree(self.source_tree))
        for vals in self._scan_selected_rows():
            if vals:
                ips.append(vals[0])
        seen = []
        for ip in ips:
            if ip not in seen:
                seen.append(ip)
        return seen

    def copy_ip(self):
        sel = self._selected_ips_any()
        if not sel:
            q_info(self, "Info", "Select one or more.")
            return
        QApplication.clipboard().setText("\n".join(sel))
        self.set_status(f"Copied {len(sel)} IP(s).")

    # Helpers to read selected rows from results tree
    def _scan_selected_rows(self):
        out = []
        for iid in self.results_tree.selection():
            vals = self.results_tree.item(iid, "values")
            if vals:
                out.append(vals)
        return out

    def copy_scan_selected(self):
        rows = self._scan_selected_rows()
        if not rows:
            q_info(self, "Info", "Select results first.")
            return
        ips = [row[0] for row in rows]
        QApplication.clipboard().setText("\n".join(ips))
        self.set_status(f"Copied {len(ips)} IP(s) from results.")

    def ignore_scan_selected(self):
        rows = self._scan_selected_rows()
        if not rows:
            q_info(self, "Info", "Select results first.")
            return
        reason = ask_reason_with_whitelist(self, "Reason", "Why ignore? (optional)")
        if reason is None:
            self.set_status("Ignore cancelled.")
            return
        for ip, *_ in rows:
            add_to_ignore(ip, reason or "")
        for iid in list(self.results_tree.selection()):
            self.results_tree.delete(iid)
        self.set_status(f"Added {len(rows)} to ignore.txt from results.")

    def save_scan_selected(self):
        rows = self._scan_selected_rows()
        if not rows:
            q_info(self, "Info", "Select results first.")
            return
        reason = q_ask_string(self, "Reason", "Why save? (optional)")
        for ip, *_ in rows:
            add_to_saved(ip, reason or "")
        self.set_status(f"Added {len(rows)} to saved.txt from results.")

    def add_scan_selected_to_monitor(self):
        rows = self._scan_selected_rows()
        if not rows:
            q_info(self, "Info", "Select results first.")
            return
        ips = [row[0] for row in rows]
        added, invalid, duplicates = add_ips_to_monitor_list(ips)
        self.set_status(format_monitor_feedback(added, invalid, duplicates))

    def export_scan_results(self):
        rows = []
        for iid in self.results_tree.get_children():
            vals = self.results_tree.item(iid, "values")
            if vals:
                rows.append(vals)
        if not rows:
            q_info(self, "Info", "No scan results to export.")
            return
        # default name uses source file name (if any)
        if self.current_source:
            base_name = os.path.splitext(os.path.basename(self.current_source))[0]
            base = sanitize_query_for_filename(base_name + "_scan")
        else:
            base = "servers_scan"
        path = q_ask_save(self, "Export Servers Scan Results",
                          "Text files (*.txt)", f"{base}.txt")
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            for row in rows:
                if not row:
                    continue
                ip = row[0]
                motd = row[1] if len(row) > 1 else ""
                players = row[2] if len(row) > 2 else "N/A"
                version = row[3] if len(row) > 3 else "N/A"
                if "/" in str(players):
                    online, maximum = str(players).split("/", 1)
                else:
                    online, maximum = "N", "A"
                f.write(format_result_line(ip, motd, online, maximum, version) + "\n")
        self.set_status(f"Exported {len(rows)} scan rows to {os.path.basename(path)}")

    def search_players(self):
        query_raw = self.player_search.text() or ""
        query = query_raw.strip().lower()
        if not query:
            self.set_status("Enter a player name to search.")
            return
        matches = []
        for iid in self.results_tree.get_children():
            vals = self.results_tree.item(iid, "values")
            if not vals:
                continue
            players_text = vals[-1] if vals else ""
            if isinstance(players_text, str) and query in players_text.lower():
                matches.append(iid)
        current_sel = self.results_tree.selection()
        if current_sel:
            self.results_tree.selection_remove(current_sel)
        if matches:
            self.results_tree.selection_set(matches)
            self.results_tree.focus(matches[0])
            self.results_tree.see(matches[0])
            self.set_status(f"Found {len(matches)} match(es) for '{query_raw.strip()}'.")
        else:
            self.set_status(f"No matches for '{query_raw.strip()}'.")

    def _reset_scan_row_map(self):
        self._scan_row_map = {}

    def _register_scan_row(self, ip, iid):
        self._scan_row_map[ip] = iid

    def _update_scan_row_cracked(self, ip, text):
        iid = self._scan_row_map.get(ip)
        if not iid:
            return
        vals = list(self.results_tree.item(iid, "values"))
        if len(vals) >= 5:
            vals[4] = text
            self.results_tree.item(iid, values=vals)

    def _update_scan_row_whitelist(self, ip, text):
        iid = self._scan_row_map.get(ip)
        if not iid:
            return
        vals = list(self.results_tree.item(iid, "values"))
        if len(vals) >= 6:
            vals[5] = text
            self.results_tree.item(iid, values=vals)

    def _remove_scan_row(self, ip):
        iid = self._scan_row_map.pop(ip, None)
        if iid:
            self.results_tree.delete(iid)

    def _scan(self, items):
        for iid in self.results_tree.get_children():
            self.results_tree.delete(iid)
        self.set_status("Preparing scan...")
        only_cracked = self.only_cracked.isChecked()
        check_whitelist = self.check_whitelist.isChecked()
        # Cracked servers need no account (offline probe, no Mojang auth).
        account = get_active_mc_account() if check_whitelist else None
        if only_cracked or check_whitelist:
            self._reset_scan_row_map()
            self._cracked_job_id += 1
            self._whitelist_job_id += 1
        else:
            self._scan_row_map.clear()
        current_job = self._cracked_job_id
        whitelist_job = self._whitelist_job_id
        pending_entries = []
        pending_seen = set()
        whitelist_entries = []
        whitelist_seen = set()
        pending_lock = threading.Lock()
        discovered_rows = []

        def work():
            try:
                total = len(items)

                def on_start(ip):
                    self._current_scan_ip = ip
                    self.after(0, lambda ip=ip: self.set_status(
                        f"Currently scanning: {ip} [0/{total}]"))

                def on_result(r, line):
                    if not r:
                        return
                    discovered_rows.append((r['ip'], r['motd'],
                                           f"{r['players']}/{r['max_players']}",
                                           r['version']))

                    if self.only_players.isChecked() and r.get('players', 0) <= 0:
                        return

                    if only_cracked and should_skip_cracked_probe(r):
                        return
                    if not version_filter_allows(r.get("version", ""),
                                                self.version_filter.currentText()):
                        return

                    cracked_text = "Yes" if r.get('cracked') else "No"
                    whitelist_text = "Queued" if check_whitelist else "-"
                    queue_candidate = None
                    if only_cracked:
                        cached = get_cached_cracked_entry(r['ip'])
                        if cached:
                            cracked_text = "Yes (cached)"
                        else:
                            cracked_text = "Queued"
                            queue_candidate = r

                    active_players = format_player_list(r.get('players_sample'))
                    vals = (
                        r['ip'],
                        r['motd'],
                        f"{r['players']}/{r['max_players']}",
                        r['version'],
                        cracked_text,
                        whitelist_text,
                        active_players
                    )

                    def add_row(ip=r['ip'], v=vals):
                        iid = self.results_tree.insert("", "end", values=v)
                        if only_cracked or check_whitelist:
                            self._register_scan_row(ip, iid)
                    self.after(0, add_row)

                    if only_cracked and queue_candidate:
                        with pending_lock:
                            ip = queue_candidate['ip']
                            if ip not in pending_seen:
                                pending_seen.add(ip)
                                pending_entries.append(queue_candidate)
                    if check_whitelist:
                        with pending_lock:
                            ip = r['ip']
                            if ip not in whitelist_seen:
                                whitelist_seen.add(ip)
                                whitelist_entries.append(r)

                def on_progress(done, total):
                    ip = self._current_scan_ip or "…"
                    self.after(0, lambda d=done, t=total, ip=ip:
                               self.set_status(f"Currently scanning: {ip} [{d}/{t}]"))

                results, online_lines = scan_servers_gui(
                    items,
                    on_start=on_start,
                    on_result=on_result,
                    on_progress=on_progress
                )
                self.after(0, lambda: self.set_status(
                    f"Scan complete. Responded: {len(results)}; "
                    f"With 1+: {len(online_lines)}"))

                if only_cracked:
                    with pending_lock:
                        verify_entries = list(pending_entries)

                    def handle_update(entry, result, message, was_cached):
                        if current_job != self._cracked_job_id:
                            return
                        ip = entry.get("ip")

                        def ui():
                            if was_cached or result is True:
                                label = "Yes (cached)" if was_cached else "Yes"
                                self._update_scan_row_cracked(ip, label)
                            else:
                                self._remove_scan_row(ip)
                        self.after(0, ui)

                    def handle_progress(done, total):
                        if current_job != self._cracked_job_id:
                            return
                        if done < total:
                            self.after(0, lambda d=done, t=total:
                                       self.set_status(
                                           f"Verifying cracked servers: {d}/{t}"))
                        else:
                            def finish():
                                remaining = len(self.results_tree.get_children())
                                self.set_status(
                                    "Cracked verification complete. "
                                    f"Showing {remaining} server(s).")
                            self.after(0, finish)
                    run_cracked_verifier_async(verify_entries, handle_update,
                                              progress_cb=handle_progress)
                if check_whitelist:
                    with pending_lock:
                        verify_whitelist = list(whitelist_entries)

                    def handle_whitelist_update(entry, result, message):
                        if whitelist_job != self._whitelist_job_id:
                            return
                        ip = entry.get("ip")

                        def ui():
                            label = whitelist_result_label(result, message)
                            self._update_scan_row_whitelist(ip, label)
                        self.after(0, ui)

                    def handle_whitelist_progress(done, total):
                        if whitelist_job != self._whitelist_job_id:
                            return
                        if done < total:
                            self.after(0, lambda d=done, t=total:
                                       self.set_status(
                                           f"Checking whitelist: {d}/{t}"))
                        else:
                            self.after(0, lambda:
                                       self.set_status(
                                           "Whitelist check complete for "
                                           f"{total} server(s)."))
                    run_whitelist_verifier_async(verify_whitelist, account,
                                                handle_whitelist_update,
                                                progress_cb=handle_whitelist_progress)
                if discovered_rows:
                    self.after(0, lambda rows=discovered_rows:
                               self._update_version_filter_choices(rows))
            except Exception as e:
                self.after(0, lambda: self.set_status(f"Scan failed: {e}"))

        threading.Thread(target=work, daemon=True).start()

    def scan_selected(self):
        sel = self._selected_ips_any()
        if not sel:
            q_info(self, "Info", "Select one or more.")
            return
        self._scan(sel)

    def scan_all(self):
        if not self.servers:
            q_info(self, "Info", "Load a .txt first.")
            return
        self._scan(self.servers)

    def add_search_selected_to_monitor(self):
        sel = self._selected_ips_any()
        if not sel:
            q_info(self, "Info", "Select items first.")
            return
        added, invalid, duplicates = add_ips_to_monitor_list(sel)
        self.set_status(format_monitor_feedback(added, invalid, duplicates))


# ===== Qt port section: qt_monitor (PySide6, 1:1 behavior) =====
"""PySide6 port of ServerMonitorTab (scanner.py lines 6350-6737)."""
import threading
import time

from PySide6.QtCore import QTimer, Qt
from PySide6.QtGui import QColor, QBrush
from PySide6.QtWidgets import (
    QApplication,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

SERVER_COLUMNS = ("ip", "status", "players", "version", "cracked", "motd", "last_ping")
PLAYER_COLUMNS = ("uuid", "name", "last_seen")

_SERVER_WIDTHS = {
    "ip": 150,
    "status": 100,
    "players": 110,
    "version": 120,
    "cracked": 90,
    "motd": 260,
    "last_ping": 170,
}
_PLAYER_WIDTHS = {"uuid": 260, "name": 200, "last_seen": 170}


class ServerMonitorTab(QtBaseMixin, QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.monitor_state = load_server_monitor_state()
        self._monitor_thread = None
        self._monitoring = False
        self._monitor_interval = DEFAULT_MONITOR_INTERVAL
        self._stop_event = threading.Event()
        self._last_selected_ip = None
        self._build_ui()
        register_monitor_tab(self)
        self._refresh_server_tree()
        self._refresh_players_tree()

    def _build_ui(self):
        layout = QVBoxLayout(self)

        # --- Input group ---
        layout.addWidget(QLabel("Add servers (one IP:PORT per line):"))
        self.server_input = QPlainTextEdit()
        self.server_input.setMaximumBlockCount(0)
        self.server_input.setFixedHeight(64)
        layout.addWidget(self.server_input)

        btn_row = QHBoxLayout()
        self.add_btn = QPushButton("Add to Monitor")
        self.add_btn.clicked.connect(self.add_servers_from_input)
        btn_row.addWidget(self.add_btn)
        self.clear_btn = QPushButton("Clear Input")
        self.clear_btn.clicked.connect(self.clear_input)
        btn_row.addWidget(self.clear_btn)
        self.remove_btn = QPushButton("Remove Selected")
        self.remove_btn.clicked.connect(self.remove_selected_servers)
        btn_row.addWidget(self.remove_btn)
        self.copy_btn = QPushButton("Copy Selected")
        self.copy_btn.clicked.connect(self.copy_monitored_ips)
        btn_row.addWidget(self.copy_btn)
        self.copy_ips_btn = QPushButton("Copy IPs")
        self.copy_ips_btn.clicked.connect(self.copy_monitored_ips)
        btn_row.addWidget(self.copy_ips_btn)
        btn_row.addStretch(1)
        layout.addLayout(btn_row)

        # --- Control row ---
        ctrl_row = QHBoxLayout()
        ctrl_row.addWidget(QLabel("Ping interval (secs):"))
        self.interval_spin = QSpinBox()
        self.interval_spin.setMinimum(5)
        self.interval_spin.setMaximum(86400)
        self.interval_spin.setValue(DEFAULT_MONITOR_INTERVAL)
        ctrl_row.addWidget(self.interval_spin)
        self.start_btn = QPushButton("Start Monitoring")
        self.start_btn.clicked.connect(self.start_monitoring)
        ctrl_row.addWidget(self.start_btn)
        self.stop_btn = QPushButton("Stop")
        self.stop_btn.clicked.connect(self.stop_monitoring)
        self.stop_btn.setEnabled(False)
        ctrl_row.addWidget(self.stop_btn)
        self.export_btn = QPushButton("Export Player Log")
        self.export_btn.clicked.connect(self.export_players)
        ctrl_row.addWidget(self.export_btn)
        ctrl_row.addStretch(1)
        layout.addLayout(ctrl_row)

        # --- Tables (vertical splitter) ---
        splitter = QSplitter(Qt.Vertical)

        server_wrap = QWidget()
        server_layout = QVBoxLayout(server_wrap)
        server_layout.setContentsMargins(0, 0, 0, 0)
        self.server_tree = ResultTable(SERVER_COLUMNS)
        self.server_tree.setSortingEnabled(True)
        for idx, col in enumerate(SERVER_COLUMNS):
            self.server_tree.setColumnWidth(idx, _SERVER_WIDTHS[col])
        self.server_tree.itemSelectionChanged.connect(self._on_server_selected)
        server_layout.addWidget(self.server_tree)
        splitter.addWidget(server_wrap)

        players_wrap = QWidget()
        players_layout = QVBoxLayout(players_wrap)
        players_layout.setContentsMargins(0, 0, 0, 0)
        players_layout.addWidget(QLabel("Recorded players for selected server:"))
        self.players_tree = ResultTable(PLAYER_COLUMNS)
        self.players_tree.setSortingEnabled(True)
        for idx, col in enumerate(PLAYER_COLUMNS):
            self.players_tree.setColumnWidth(idx, _PLAYER_WIDTHS[col])
        players_layout.addWidget(self.players_tree)
        prow = QHBoxLayout()
        self.copy_names_btn = QPushButton("Copy Username(s)")
        self.copy_names_btn.clicked.connect(self.copy_selected_player_names)
        prow.addWidget(self.copy_names_btn)
        prow.addStretch(1)
        players_layout.addLayout(prow)
        splitter.addWidget(players_wrap)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)
        layout.addWidget(splitter, 1)

        # --- Footer status ---
        self.status_label = QLabel("Monitor idle.")
        layout.addWidget(self.status_label)

    # ---- helpers ----
    def _set_status(self, msg):
        self.status_label.setText(msg)

    def _server_selected_rows(self):
        rows = sorted({i.row() for i in self.server_tree.selectedIndexes()})
        return rows

    def _server_row_values(self, row):
        vals = []
        for col in range(self.server_tree.columnCount()):
            item = self.server_tree.item(row, col)
            vals.append(item.text() if item else "")
        return tuple(vals)

    def _players_selected_rows(self):
        return sorted({i.row() for i in self.players_tree.selectedIndexes()})

    def _players_row_values(self, row):
        vals = []
        for col in range(self.players_tree.columnCount()):
            item = self.players_tree.item(row, col)
            vals.append(item.text() if item else "")
        return tuple(vals)

    def _add_table_row(self, table, values, fg=None, bg=None):
        table.setSortingEnabled(False)
        row = table.rowCount()
        table.insertRow(row)
        for col, val in enumerate(values):
            item = QTableWidgetItem(str(val))
            item.setFlags(item.flags() & ~Qt.ItemIsEditable)
            if fg is not None:
                item.setForeground(QBrush(QColor(fg)))
            if bg is not None:
                item.setBackground(QBrush(QColor(bg)))
            table.setItem(row, col, item)
        table.setSortingEnabled(True)
        return row

    # ---- input actions ----
    def add_servers_from_input(self):
        raw = self.server_input.toPlainText().strip()
        if not raw:
            self._set_status("Paste one or more servers first.")
            return
        added = 0
        invalid = 0
        for line in raw.splitlines():
            ip = get_ip_only(line.strip())
            if not ip:
                continue
            if not is_valid_ip_port(ip):
                invalid += 1
                continue
            if ip in self.monitor_state.get("servers", {}):
                continue
            _ensure_monitor_server_entry(self.monitor_state, ip)
            added += 1
        if added:
            save_server_monitor_state(self.monitor_state)
            self._refresh_server_tree()
            self._set_status(f"Added {added} server(s) to monitor list.")
        elif invalid:
            self._set_status("Skipped invalid entries.")
        else:
            self._set_status("No new servers added.")
        self.server_input.clear()

    def clear_input(self):
        self.server_input.clear()
        self._set_status("Input cleared.")

    def remove_selected_servers(self):
        selected = self._server_selected_rows()
        if not selected:
            q_info(self, "Info", "Select rows to remove.")
            return
        removed = 0
        for row in selected:
            vals = self._server_row_values(row)
            if not vals:
                continue
            ip = vals[0]
            if ip in self.monitor_state.get("servers", {}):
                self.monitor_state["servers"].pop(ip, None)
                removed += 1
        if removed:
            save_server_monitor_state(self.monitor_state)
            self._last_selected_ip = None
            self._refresh_server_tree()
            self._refresh_players_tree(None)
            self._set_status(f"Removed {removed} server(s) from monitor list.")
        else:
            self._set_status("No servers removed.")

    # alias (contract name)
    def remove_selected(self):
        return self.remove_selected_servers()

    def copy_monitored_ips(self):
        selected = self._server_selected_rows()
        if not selected:
            q_info(self, "Info", "Select rows first.")
            return
        ips = []
        for row in selected:
            vals = self._server_row_values(row)
            if vals:
                ips.append(vals[0])
        if not ips:
            q_info(self, "Info", "No valid IPs selected.")
            return
        QApplication.clipboard().setText("\n".join(ips))
        self._set_status(f"Copied {len(ips)} monitored server(s).")

    # alias (contract name)
    def copy_ips(self):
        return self.copy_monitored_ips()

    def copy_selected_player_names(self):
        selected = self._players_selected_rows()
        if not selected:
            q_info(self, "Info", "Select player rows first.")
            return
        names = []
        for row in selected:
            vals = self._players_row_values(row)
            if vals and len(vals) >= 2:
                name = vals[1]
                if isinstance(name, str) and name.strip():
                    names.append(name.strip())
        if not names:
            q_info(self, "Info", "No player names selected.")
            return
        QApplication.clipboard().setText("\n".join(names))
        self._set_status(f"Copied {len(names)} player name(s).")

    def start_monitoring(self):
        if self._monitoring:
            return
        interval = self._read_interval()
        if not interval:
            q_info(self, "Info", "Enter a valid interval (in seconds).")
            return
        ips = self._get_monitored_ips()
        if not ips:
            q_info(self, "Info", "Add at least one server to monitor.")
            return
        self._monitor_interval = interval
        self._stop_event.clear()
        self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._monitor_thread.start()
        self._monitoring = True
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self._set_status(f"Monitoring {len(ips)} server(s) every {interval}s.")

    # alias (contract name)
    def start_monitor(self):
        return self.start_monitoring()

    def stop_monitoring(self):
        if not self._monitoring:
            return
        self._stop_event.set()
        self._monitoring = False
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self._set_status("Monitoring paused.")

    # alias (contract name)
    def stop_monitor(self):
        return self.stop_monitoring()

    def _monitor_loop(self):
        while not self._stop_event.is_set():
            start = time.time()
            try:
                self._run_monitor_pass()
            except Exception as exc:
                self.after(0, lambda: self._set_status(f"Monitor error: {exc}"))
            elapsed = time.time() - start
            wait = max(0, self._monitor_interval - elapsed)
            if self._stop_event.wait(wait):
                break

    def _run_monitor_pass(self):
        ips = self._get_monitored_ips()
        if not ips:
            self.after(0, lambda: self._set_status("No servers configured to monitor."))
            return
        self.after(0, lambda: self._set_status(f"Pinging {len(ips)} server(s)..."))
        cycle_ts = time.time()
        results, _ = scan_servers_gui(ips)
        processed = set()

        if results:
            self.after(0, lambda: self._set_status(f"Re-checking cracked status for {len(results)} online server(s)..."))

            def on_cracked_progress(done, total):
                self.after(0, lambda d=done, t=total: self._set_status(f"Re-checking cracked status: {d}/{t}"))

            results = verify_monitor_cracked_results(results, progress_cb=on_cracked_progress)

        for result in results:
            ip = result.get("ip")
            if not ip:
                continue
            update_server_monitor_entry(self.monitor_state, ip, result, cycle_ts)
            processed.add(ip)
        for ip in ips:
            if ip not in processed:
                mark_server_offline_in_state(self.monitor_state, ip, cycle_ts)
        save_server_monitor_state(self.monitor_state)
        self.after(0, self._refresh_server_tree)
        self.after(0, self._refresh_players_tree)
        self.after(0, lambda: self._set_status(f"Monitor cycle complete ({len(ips)} servers)."))

    def export_players(self):
        ip = self._last_selected_ip
        if not ip:
            q_info(self, "Info", "Select a server first.")
            return
        entry = self.monitor_state.get("servers", {}).get(ip)
        if not entry:
            q_info(self, "Info", "Server data unavailable.")
            return
        log = entry.get("player_log", {})
        if not log:
            q_info(self, "Info", "No player data for this server yet.")
            return
        safe_name = ip.replace(":", "_")
        path = q_ask_save(
            self,
            "Export Player Log",
            f"{safe_name}_players.txt",
            "Text files (*.txt)",
        )
        if not path:
            return
        rows = sorted(log.items(), key=lambda kv: kv[1].get("last_seen", 0), reverse=True)
        with open(path, "w", encoding="utf-8") as f:
            for uid, data in rows:
                name = data.get("name", "")
                seen = format_timestamp(data.get("last_seen"))
                f.write(f"{uid} | {name} | Last seen: {seen}\n")
        self._set_status(f"Exported {len(rows)} player entries for {ip}.")

    # alias (contract name)
    def export(self):
        return self.export_players()

    def _get_monitored_ips(self):
        return list(self.monitor_state.get("servers", {}).keys())

    def _read_interval(self):
        try:
            val = int(self.interval_spin.value())
            return max(5, val)
        except Exception:
            return None

    def _refresh_server_tree(self):
        current = self._last_selected_ip
        target_row = None
        self.server_tree.setSortingEnabled(False)
        self.server_tree.setRowCount(0)
        for ip in sorted(self.monitor_state.get("servers", {})):
            entry = self.monitor_state["servers"][ip]
            players = entry.get("players_online", 0)
            max_players = entry.get("max_players", 0)
            status = entry.get("last_status", "unknown")
            last_ping = format_timestamp(entry.get("last_ping"))
            version = entry.get("version", "N/A")
            cracked = "Yes" if entry.get("cracked") else "No"
            motd = sanitize_motd(entry.get("motd", ""))
            offline = status.strip().lower() != "online" and status.strip()
            row = self._add_table_row(
                self.server_tree,
                (ip, status.title(), f"{players}/{max_players}", version, cracked, motd, last_ping),
                bg="#ffe6e6" if offline else None,
            )
            if ip == current:
                target_row = row
        self.server_tree.setSortingEnabled(True)
        if target_row is not None:
            self.server_tree.selectRow(target_row)
            item = self.server_tree.item(target_row, 0)
            if item is not None:
                self.server_tree.scrollToItem(item)

    def _refresh_players_tree(self, ip=None):
        if ip is None:
            ip = self._last_selected_ip
        self.players_tree.setSortingEnabled(False)
        self.players_tree.setRowCount(0)
        if not ip:
            self.players_tree.setSortingEnabled(True)
            return
        entry = self.monitor_state.get("servers", {}).get(ip)
        if not entry:
            self.players_tree.setSortingEnabled(True)
            return
        current_online = set(entry.get("current_players") or [])
        rows = []
        for uid, pdata in entry.get("player_log", {}).items():
            rows.append((uid, pdata.get("name", ""), pdata.get("last_seen", 0)))
        rows.sort(key=lambda item: item[2], reverse=True)
        for uid, name, last_seen in rows:
            online = uid in current_online
            self._add_table_row(
                self.players_tree,
                (uid, name, format_timestamp(last_seen)),
                fg="#0b8f0b" if online else None,
            )
        self.players_tree.setSortingEnabled(True)

    def _on_server_selected(self):
        selection = self._server_selected_rows()
        if not selection:
            self._last_selected_ip = None
            self._refresh_players_tree(None)
            return
        vals = self._server_row_values(selection[0])
        if not vals:
            return
        self._last_selected_ip = vals[0]
        self._refresh_players_tree(self._last_selected_ip)

    def reload_state(self):
        self.monitor_state = load_server_monitor_state()
        if self._last_selected_ip not in self.monitor_state.get("servers", {}):
            self._last_selected_ip = None
        self._refresh_server_tree()
        self._refresh_players_tree(self._last_selected_ip)


# ===== Qt port section: qt_shodan (PySide6, 1:1 behavior) =====
"""PySide6 port of ShodanTab (scanner.py lines 6740-7369). 1:1 logic port.

Original: class ShodanTab(ttk.Frame) with ttk.Treeview tables, tk.StringVar/
BooleanVar state, messagebox/simpledialog/filedialog, self.after / threading.

Qt mapping:
  ttk.Frame -> QWidget + layouts (QSplitter vertical replaces tk.PanedWindow)
  ttk.Entry(query) -> QLineEdit
  ttk.Combobox (editable) -> QComboBox (editable)
  ttk.Checkbutton -> QCheckBox
  ttk.Button -> QPushButton (exact same labels)
  ttk.Treeview -> ResultTable (QTableWidget-based, from qt_helpers)
  tk.StringVar status -> QLabel; set_status sets text
  self.after -> QtBaseMixin.after (QTimer.singleShot)
  messagebox -> q_info / q_error; simpledialog -> q_ask_string;
    filedialog -> q_ask_save; ask_reason_with_whitelist / ensure_shodan_key_ui
    from qt_helpers (QInputDialog-based)
  clipboard_clear/append -> QApplication.clipboard().setText
Backend refs (search_shodan, parse_*, scan_servers_gui, verifiers, etc.)
imported from scanner module as-is (guarded import so module loads standalone).
No QPlainTextEdit in original ShodanTab: none added here.
Note: original ShodanTab.search_players references self.player_search_var
which is never created in ShodanTab._build_ui (only BulkTab/JSONTab create
it) and has no search entry/button wired. Port keeps the method with
identical logic, reading from an optional player_search_edit if present.
"""

import os
import threading

from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSplitter,
    QVBoxLayout,
    QWidget,
    QAbstractItemView,
)
from PySide6.QtCore import Qt


# Backend refs as-is (same names as scanner.py globals).
SEARCH_COLS = ("ip", "motd", "players", "version")
SCAN_COLS = ("ip", "motd", "players", "version", "cracked", "whitelist", "active_players")


def _table_row_values(table, row):
    """Return list of cell texts for QTableWidget-like table row."""
    cols = table.columnCount()
    out = []
    for c in range(cols):
        item = table.item(row, c)
        out.append(item.text() if item is not None else "")
    return out


def _selected_rows(table):
    """Sorted unique selected row indices (SelectRows mode)."""
    rows = set()
    for idx in table.selectionModel().selectedRows():
        rows.add(idx.row())
    # Fallback for cell selection without row selection model update
    for item in table.selectedItems():
        rows.add(item.row())
    return sorted(rows)


class ShodanTab(QWidget, QtBaseMixin):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.results = []  # list[tuple(ip,motd,players,version)]
        self.scan_rows = []
        self._in_ignore = False
        self._version_filter = "All versions"
        self._build_ui()
        self._current_scan_ip = None
        self._scan_row_map = {}
        self._cracked_job_id = 0
        self._whitelist_job_id = 0

    # ---------- UI ----------
    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(8, 8, 8, 8)

        pane = QSplitter(Qt.Vertical, self)
        root.addWidget(pane, 1)

        pane_top = QWidget(pane)
        top_layout = QVBoxLayout(pane_top)
        top_layout.setContentsMargins(0, 0, 0, 0)
        pane.addWidget(pane_top)

        pane_bottom = QWidget(pane)
        bottom_layout = QVBoxLayout(pane_bottom)
        bottom_layout.setContentsMargins(0, 0, 0, 0)
        pane.addWidget(pane_bottom)
        pane.setSizes([420, 280])

        # --- top bar ---
        bar = QWidget(pane_top)
        bar_layout = QHBoxLayout(bar)
        bar_layout.setContentsMargins(8, 8, 8, 4)
        bar_layout.addWidget(QLabel("Query (without 'minecraft'): ", bar))
        self.query_edit = QLineEdit(bar)
        self.query_edit.setMinimumWidth(340)
        bar_layout.addWidget(self.query_edit)
        self.search_btn = QPushButton("Search", bar)
        self.search_btn.clicked.connect(self.do_search)
        bar_layout.addWidget(self.search_btn)
        self.export_search_btn = QPushButton("Export Search…", bar)
        self.export_search_btn.clicked.connect(self.export_search_results)
        bar_layout.addWidget(self.export_search_btn)
        bar_layout.addWidget(QLabel("Version:", bar))
        self.version_filter_combo = QComboBox(bar)
        self.version_filter_combo.setEditable(True)
        self.version_filter_combo.addItem("All versions")
        self.version_filter_combo.setMinimumWidth(140)
        self.version_filter_combo.currentTextChanged.connect(
            lambda _t: self._refresh_search_tree()
        )
        self.version_filter_combo.lineEdit().textChanged.connect(
            lambda _t: self._refresh_search_tree()
        )
        bar_layout.addWidget(self.version_filter_combo)
        bar_layout.addStretch(1)
        top_layout.addWidget(bar)

        # --- mid: search table + right buttons ---
        mid = QWidget(pane_top)
        mid_layout = QHBoxLayout(mid)
        mid_layout.setContentsMargins(8, 4, 8, 4)
        top_layout.addWidget(mid, 1)

        self.tree = ResultTable(mid, list(SEARCH_COLS))
        self.tree.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.tree.setSelectionMode(QAbstractItemView.ExtendedSelection)
        mid_layout.addWidget(self.tree, 1)
        try:
            _get_icon_manager().attach_to_tree(self.tree)
        except Exception:
            pass


        right = QWidget(mid)
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(8, 0, 0, 0)
        mid_layout.addWidget(right)

        self.copy_btn = QPushButton("Copy IP(s)", right)
        self.copy_btn.clicked.connect(self.copy_selected)
        right_layout.addWidget(self.copy_btn)
        self.ignore_btn = QPushButton("Add to Ignore", right)
        self.ignore_btn.clicked.connect(self.ignore_selected)
        right_layout.addWidget(self.ignore_btn)
        self.save_btn = QPushButton("Add to Saved", right)
        self.save_btn.clicked.connect(self.save_selected)
        right_layout.addWidget(self.save_btn)
        self.monitor_btn = QPushButton("Add to Monitor", right)
        self.monitor_btn.clicked.connect(self.add_search_selected_to_monitor)
        right_layout.addWidget(self.monitor_btn)
        sep = QWidget(right)
        sep.setFixedHeight(8)
        right_layout.addWidget(sep)
        self.scan_sel_btn = QPushButton("Scan Selected", right)
        self.scan_sel_btn.clicked.connect(self.scan_selected)
        right_layout.addWidget(self.scan_sel_btn)
        self.scan_all_btn = QPushButton("Scan All", right)
        self.scan_all_btn.clicked.connect(self.scan_all)
        right_layout.addWidget(self.scan_all_btn)
        self.only_players_cb = QCheckBox("Only players > 0", right)
        self.only_players_cb.setChecked(True)
        right_layout.addWidget(self.only_players_cb)
        self.only_cracked_cb = QCheckBox("Only cracked servers", right)
        self.only_cracked_cb.setChecked(False)
        right_layout.addWidget(self.only_cracked_cb)
        self.check_whitelist_cb = QCheckBox("Check whitelist", right)
        self.check_whitelist_cb.setChecked(False)
        right_layout.addWidget(self.check_whitelist_cb)
        right_layout.addStretch(1)

        # --- bottom: scan output table ---
        bottom_layout.addWidget(
            QLabel("Scan Output (select to copy/save/ignore):", pane_bottom)
        )
        self.scan_tree = ResultTable(pane_bottom, list(SCAN_COLS))
        self.scan_tree.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.scan_tree.setSelectionMode(QAbstractItemView.ExtendedSelection)
        bottom_layout.addWidget(self.scan_tree, 1)
        try:
            _get_icon_manager().attach_to_tree(self.scan_tree)
        except Exception:
            pass


        # --- footer (pinned) ---
        footer = QWidget(self)
        footer_layout = QHBoxLayout(footer)
        footer_layout.setContentsMargins(0, 6, 0, 0)
        root.addWidget(footer)

        self.copy_scan_btn = QPushButton("Copy IP(s)", footer)
        self.copy_scan_btn.clicked.connect(self.copy_scan_selected)
        footer_layout.addWidget(self.copy_scan_btn)
        self.ignore_scan_btn = QPushButton("Add to Ignore", footer)
        self.ignore_scan_btn.clicked.connect(self.ignore_scan_selected_from_output)
        footer_layout.addWidget(self.ignore_scan_btn)
        self.save_scan_btn = QPushButton("Add to Saved", footer)
        self.save_scan_btn.clicked.connect(self.save_scan_selected_from_output)
        footer_layout.addWidget(self.save_scan_btn)
        self.monitor_scan_btn = QPushButton("Add to Monitor", footer)
        self.monitor_scan_btn.clicked.connect(self.add_scan_output_selected_to_monitor)
        footer_layout.addWidget(self.monitor_scan_btn)
        self.export_scan_btn = QPushButton("Export Scan…", footer)
        self.export_scan_btn.clicked.connect(self.export_scan_output)
        footer_layout.addWidget(self.export_scan_btn)
        self.check_wl_btn = QPushButton("Check Whitelist", footer)
        self.check_wl_btn.clicked.connect(
            lambda: check_selected_whitelist(self, self.scan_tree)
        )
        footer_layout.addWidget(self.check_wl_btn)

        self.status_label = QLabel("Ready.", footer)
        footer_layout.addWidget(self.status_label, 1)

    def set_status(self, msg):
        self.status_label.setText(msg)

    # ---------- version filter ----------
    def _version_filter_text(self):
        return self.version_filter_combo.currentText() or "All versions"

    def _update_version_filter_choices(self, rows):
        choices = collect_version_options(rows)
        current = self._version_filter_text() or "All versions"
        self.version_filter_combo.blockSignals(True)
        try:
            self.version_filter_combo.clear()
            self.version_filter_combo.addItems(choices)
            if current not in choices:
                current = "All versions"
            self.version_filter_combo.setCurrentText(current)
        finally:
            self.version_filter_combo.blockSignals(False)

    def _refresh_search_tree(self):
        self.tree.clear_rows()
        for row in self.results:
            if version_filter_allows(row[3], self._version_filter_text()):
                self.tree.add_row(row)

    def _refresh_scan_tree(self):
        self.scan_tree.clear_rows()
        for row in self.scan_rows:
            if version_filter_allows(row[3], self._version_filter_text()):
                self.scan_tree.add_row(row)

    # ---------- search ----------
    def do_search(self):
        q = self.query_edit.text().strip()
        full_query = f"minecraft {q}" if q else "minecraft"

        # MAIN THREAD: ensure key (may open a dialog)
        key = ensure_shodan_key_ui(self)
        if not key:
            self.set_status("Search canceled: no Shodan API key.")
            return

        self.set_status(f"Searching: {full_query}")
        self.tree.clear_rows()

        def work(k=key, fq=full_query):
            try:
                matches = search_shodan(fq, k) or []
                rows = []
                for m in matches:
                    ip = f"{m.get('ip_str')}:{m.get('port', 25565)}"
                    if is_ignored(ip):
                        continue
                    data = m.get("data", "")
                    motd = parse_description_from_raw(data)
                    players = parse_players(data)
                    version = parse_version(data)
                    rows.append((ip, motd, players, version))
                self.results = rows
                self.scan_rows = []

                def insert_all():
                    self._update_version_filter_choices(rows)
                    self._refresh_search_tree()
                    self.set_status(f"Found {len(rows)} (ignored filtered).")

                self.after(0, insert_all)

            except Exception as e:
                # Preserve original invalid-key handling (shodan.APIError branch).
                msg = str(e)
                is_api_error = False
                try:
                    is_api_error = shodan is not None and isinstance(e, shodan.APIError)
                except Exception:
                    is_api_error = False

                def report_error():
                    self.set_status(f"Search failed: {msg}")
                    if is_api_error and (
                        "invalid" in msg.lower() or "unauthorized" in msg.lower()
                    ):
                        try:
                            if os.path.exists(SHODAN_KEY_PATH):
                                os.remove(SHODAN_KEY_PATH)
                        except Exception:
                            pass
                        q_error(
                            self,
                            "Shodan",
                            "The Shodan API key appears to be invalid.\n"
                            "I removed shodan_key.txt. Search again and enter a valid key.",
                        )

                self.after(0, report_error)

        threading.Thread(target=work, daemon=True).start()
        return

    # ---------- selection helpers ----------
    def _search_selected_ips(self):
        sel = []
        for row in _selected_rows(self.tree):
            vals = _table_row_values(self.tree, row)
            if vals:
                sel.append(vals[0])
        return list(dict.fromkeys(sel))

    def _all_selected_ips(self):
        ips = self._search_selected_ips()
        for vals in self._scan_selected_rows():
            if vals:
                ips.append(vals[0])
        seen = []
        for ip in ips:
            if ip not in seen:
                seen.append(ip)
        return seen

    # ---- Scan Output helpers ----
    def _scan_selected_rows(self):
        out = []
        for row in _selected_rows(self.scan_tree):
            vals = _table_row_values(self.scan_tree, row)
            if vals:
                out.append(vals)
        return out

    def copy_scan_selected(self):
        rows = self._scan_selected_rows()
        if not rows:
            q_info(self, "Info", "Select scan output rows.")
            return
        ips = [row[0] for row in rows]
        QApplication.clipboard().setText("\n".join(ips))
        self.set_status(f"Copied {len(ips)} IP(s) from scan output.")

    def ignore_selected(self):
        sel = self._all_selected_ips()
        if not sel:
            q_info(self, "Info", "Select items first.")
            return
        reason = ask_reason_with_whitelist(self, "Reason", "Why ignore? (optional)")
        if reason is None:
            self.set_status("Ignore cancelled.")
            return
        for ip in sel:
            add_to_ignore(ip, reason or "")
        self.tree.remove_selected()
        self.set_status(f"Added {len(sel)} to ignore.txt")

    def save_selected(self):
        sel = self._all_selected_ips()
        if not sel:
            q_info(self, "Info", "Select items first.")
            return
        reason = q_ask_string(self, "Reason", "Why save? (optional)")
        for ip in sel:
            add_to_saved(ip, reason or "")
        self.set_status(f"Added {len(sel)} to saved.txt")

    def add_search_selected_to_monitor(self):
        sel = self._all_selected_ips()
        if not sel:
            q_info(self, "Info", "Select items first.")
            return
        added, invalid, duplicates = add_ips_to_monitor_list(sel)
        self.set_status(format_monitor_feedback(added, invalid, duplicates))

    def ignore_scan_selected_from_output(self):
        rows = self._scan_selected_rows()
        if not rows:
            q_info(self, "Info", "Select scan output rows.")
            return
        reason = ask_reason_with_whitelist(self, "Reason", "Why ignore? (optional)")
        if reason is None:
            self.set_status("Ignore cancelled.")
            return
        for ip, *_ in rows:
            add_to_ignore(ip, reason or "")
        self.scan_tree.remove_selected()
        self.set_status(f"Added {len(rows)} to ignore.txt from scan output.")

    def save_scan_selected_from_output(self):
        rows = self._scan_selected_rows()
        if not rows:
            q_info(self, "Info", "Select scan output rows.")
            return
        reason = q_ask_string(self, "Reason", "Why save? (optional)")
        for ip, *_ in rows:
            add_to_saved(ip, reason or "")
        self.set_status(f"Added {len(rows)} to saved.txt from scan output.")

    def add_scan_output_selected_to_monitor(self):
        rows = self._scan_selected_rows()
        if not rows:
            q_info(self, "Info", "Select scan output rows.")
            return
        ips = [row[0] for row in rows]
        added, invalid, duplicates = add_ips_to_monitor_list(ips)
        self.set_status(format_monitor_feedback(added, invalid, duplicates))

    def export_scan_output(self):
        rows = []
        for r in range(self.scan_tree.rowCount()):
            vals = _table_row_values(self.scan_tree, r)
            if vals:
                rows.append(vals)
        if not rows:
            q_info(self, "Info", "No scan output to export.")
            return
        q = self.query_edit.text().strip()
        base = sanitize_query_for_filename((q if q else "minecraft") + "_scan")
        path = q_ask_save(
            self, "Export Shodan Scan Output", f"{base}.txt", "Text files (*.txt)"
        )
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            for row in rows:
                if not row:
                    continue
                ip = row[0]
                motd = row[1] if len(row) > 1 else ""
                players = row[2] if len(row) > 2 else "N/A"
                version = row[3] if len(row) > 3 else "N/A"
                if "/" in str(players):
                    online, maximum = str(players).split("/", 1)
                else:
                    online, maximum = "N", "A"
                f.write(format_result_line(ip, motd, online, maximum, version) + "\n")
        self.set_status(f"Exported {len(rows)} scan rows to {os.path.basename(path)}")

    def search_players(self):
        # Original ShodanTab has no player-search entry; keep identical logic.
        edit = getattr(self, "player_search_edit", None)
        query_raw = (edit.text() if edit is not None else "") or ""
        query = query_raw.strip().lower()
        if not query:
            self.set_status("Enter a player name to search.")
            return
        matches = []
        for r in range(self.scan_tree.rowCount()):
            vals = _table_row_values(self.scan_tree, r)
            if not vals:
                continue
            players_text = vals[-1] if vals else ""
            if isinstance(players_text, str) and query in players_text.lower():
                matches.append(r)
        self.scan_tree.clearSelection()
        if matches:
            # Select all matches (ExtendedSelection)
            for r in matches:
                self.scan_tree.selectionModel().select(
                    self.scan_tree.model().index(r, 0),
                    self.scan_tree.selectionModel().Select
                    | self.scan_tree.selectionModel().Rows,
                )
            self.scan_tree.setCurrentCell(matches[0], 0)
            self.scan_tree.scrollToItem(
                self.scan_tree.item(matches[0], 0)
            ) if self.scan_tree.item(matches[0], 0) else None
            self.set_status(f"Found {len(matches)} match(es) for '{query_raw.strip()}'.")
        else:
            self.set_status(f"No matches for '{query_raw.strip()}'.")

    # ---------- scan row map (ip -> row; Qt rows shift so also search by ip) ----------
    def _find_scan_row(self, ip):
        for r in range(self.scan_tree.rowCount()):
            item = self.scan_tree.item(r, 0)
            if item is not None and item.text() == ip:
                return r
        return None

    def _reset_scan_row_map(self):
        self._scan_row_map = {}

    def _register_scan_row(self, ip, row):
        self._scan_row_map[ip] = row

    def _set_scan_cell(self, row, col, text):
        from PySide6.QtWidgets import QTableWidgetItem

        item = self.scan_tree.item(row, col)
        if item is None:
            item = QTableWidgetItem(str(text))
            self.scan_tree.setItem(row, col, item)
        else:
            item.setText(str(text))

    def _update_scan_row_cracked(self, ip, text):
        row = self._scan_row_map.get(ip)
        if row is None or row >= self.scan_tree.rowCount():
            row = self._find_scan_row(ip)
            if row is None:
                return
            self._scan_row_map[ip] = row
        else:
            # Verify mapping still points at the same ip (rows shift on delete).
            item = self.scan_tree.item(row, 0)
            if item is None or item.text() != ip:
                row = self._find_scan_row(ip)
                if row is None:
                    return
                self._scan_row_map[ip] = row
        vals_len = self.scan_tree.columnCount()
        if vals_len >= 5:
            self._set_scan_cell(row, 4, text)

    def _update_scan_row_whitelist(self, ip, text):
        row = self._scan_row_map.get(ip)
        if row is None or row >= self.scan_tree.rowCount():
            row = self._find_scan_row(ip)
            if row is None:
                return
            self._scan_row_map[ip] = row
        else:
            item = self.scan_tree.item(row, 0)
            if item is None or item.text() != ip:
                row = self._find_scan_row(ip)
                if row is None:
                    return
                self._scan_row_map[ip] = row
        vals_len = self.scan_tree.columnCount()
        if vals_len >= 6:
            self._set_scan_cell(row, 5, text)

    def _remove_scan_row(self, ip):
        row = self._scan_row_map.pop(ip, None)
        if row is None or row >= self.scan_tree.rowCount():
            row = self._find_scan_row(ip)
            if row is None:
                return
        else:
            item = self.scan_tree.item(row, 0)
            if item is None or item.text() != ip:
                row = self._find_scan_row(ip)
                if row is None:
                    return
        self.scan_tree.removeRow(row)
        # Rebuild map since Qt row indices shift after removal.
        rebuilt = {}
        for r in range(self.scan_tree.rowCount()):
            item = self.scan_tree.item(r, 0)
            if item is not None:
                rebuilt[item.text()] = r
        self._scan_row_map = rebuilt

    def _scan_and_show(self, items):
        self.scan_tree.clear_rows()
        self.set_status("Preparing scan...")
        only_cracked = self.only_cracked_cb.isChecked()
        check_whitelist = self.check_whitelist_cb.isChecked()
        # Cracked servers need no account (offline probe, no Mojang auth).
        account = get_active_mc_account() if check_whitelist else None
        self.scan_rows = []
        if only_cracked or check_whitelist:
            self._reset_scan_row_map()
            self._cracked_job_id += 1
            self._whitelist_job_id += 1
        else:
            self._scan_row_map.clear()
        current_job = self._cracked_job_id
        whitelist_job = self._whitelist_job_id
        pending_entries = []
        pending_seen = set()
        whitelist_entries = []
        whitelist_seen = set()
        pending_lock = threading.Lock()

        def work():
            try:
                def on_start(ip):
                    self._current_scan_ip = ip
                    self.after(
                        0,
                        lambda ip=ip: self.set_status(
                            f"Currently scanning: {ip} [0/{len(items)}]"
                        ),
                    )

                def on_result(r, line):
                    if not r:
                        return
                    self.scan_rows.append(
                        (
                            r["ip"],
                            r["motd"],
                            f"{r['players']}/{r['max_players']}",
                            r["version"],
                            "Yes" if r.get("cracked") else "No",
                            "Queued" if check_whitelist else "-",
                            format_player_list(r.get("players_sample")),
                        )
                    )

                    if self.only_players_cb.isChecked() and r.get("players", 0) <= 0:
                        return
                    if only_cracked and should_skip_cracked_probe(r):
                        return
                    if not version_filter_allows(
                        r.get("version", ""), self._version_filter_text()
                    ):
                        return

                    cracked_text = "Yes" if r.get("cracked") else "No"
                    whitelist_text = "Queued" if check_whitelist else "-"
                    queue_candidate = None
                    if only_cracked:
                        cached = get_cached_cracked_entry(r["ip"])
                        if cached:
                            cracked_text = "Yes (cached)"
                        else:
                            cracked_text = "Queued"
                            queue_candidate = r

                    active_players = format_player_list(r.get("players_sample"))
                    vals = (
                        r["ip"],
                        r["motd"],
                        f"{r['players']}/{r['max_players']}",
                        r["version"],
                        cracked_text,
                        whitelist_text,
                        active_players,
                    )

                    def add_row(ip=r["ip"], v=vals):
                        row = self.scan_tree.add_row(v)
                        if only_cracked or check_whitelist:
                            self._register_scan_row(ip, row)

                    self.after(0, add_row)

                    if only_cracked and queue_candidate:
                        with pending_lock:
                            ip = queue_candidate["ip"]
                            if ip not in pending_seen:
                                pending_seen.add(ip)
                                pending_entries.append(queue_candidate)
                    if check_whitelist:
                        with pending_lock:
                            ip = r["ip"]
                            if ip not in whitelist_seen:
                                whitelist_seen.add(ip)
                                whitelist_entries.append(r)

                def on_progress(done, total):
                    ip = self._current_scan_ip or "…"
                    self.after(
                        0,
                        lambda d=done, t=total, ip=ip: self.set_status(
                            f"Currently scanning: {ip} [{d}/{t}]"
                        ),
                    )

                results, online_lines = scan_servers_gui(
                    items,
                    on_start=on_start,
                    on_result=on_result,
                    on_progress=on_progress,
                )
                self.after(
                    0,
                    lambda: self.set_status(
                        f"Scan complete. Responded: {len(results)}; With 1+: {len(online_lines)}"
                    ),
                )

                if only_cracked:
                    with pending_lock:
                        verify_entries = list(pending_entries)

                    def handle_update(entry, result, message, was_cached):
                        if current_job != self._cracked_job_id:
                            return
                        ip = entry.get("ip")

                        def ui():
                            if was_cached or result is True:
                                label = "Yes (cached)" if was_cached else "Yes"
                                self._update_scan_row_cracked(ip, label)
                            else:
                                self._remove_scan_row(ip)

                        self.after(0, ui)

                    def handle_progress(done, total):
                        if current_job != self._cracked_job_id:
                            return
                        if done < total:
                            self.after(
                                0,
                                lambda d=done, t=total: self.set_status(
                                    f"Verifying cracked servers: {d}/{t}"
                                ),
                            )
                        else:
                            def finish():
                                remaining = self.scan_tree.rowCount()
                                self.set_status(
                                    f"Cracked verification complete. Showing {remaining} server(s)."
                                )

                            self.after(0, finish)

                    run_cracked_verifier_async(
                        verify_entries, handle_update, progress_cb=handle_progress
                    )
                if check_whitelist:
                    with pending_lock:
                        verify_whitelist = list(whitelist_entries)

                    def handle_whitelist_update(entry, result, message):
                        if whitelist_job != self._whitelist_job_id:
                            return
                        ip = entry.get("ip")

                        def ui():
                            label = whitelist_result_label(result, message)
                            self._update_scan_row_whitelist(ip, label)

                        self.after(0, ui)

                    def handle_whitelist_progress(done, total):
                        if whitelist_job != self._whitelist_job_id:
                            return
                        if done < total:
                            self.after(
                                0,
                                lambda d=done, t=total: self.set_status(
                                    f"Checking whitelist: {d}/{t}"
                                ),
                            )
                        else:
                            self.after(
                                0,
                                lambda: self.set_status(
                                    f"Whitelist check complete for {total} server(s)."
                                ),
                            )

                    run_whitelist_verifier_async(
                        verify_whitelist,
                        account,
                        handle_whitelist_update,
                        progress_cb=handle_whitelist_progress,
                    )
                if self.scan_rows:
                    self.after(
                        0,
                        lambda rows=list(self.scan_rows): self._update_version_filter_choices(
                            rows
                        ),
                    )
            except Exception as e:
                self.after(0, lambda: self.set_status(f"Scan failed: {e}"))

        threading.Thread(target=work, daemon=True).start()

    def scan_selected(self):
        sel = self._all_selected_ips()
        if not sel:
            q_info(self, "Info", "Select items in the table.")
            return
        self._scan_and_show(sel)

    def scan_all(self):
        if not self.results:
            q_info(self, "Info", "Run a search first.")
            return
        all_ips = [row[0] for row in self.results]
        self._scan_and_show(all_ips)

    def copy_selected(self):
        sel = self._all_selected_ips()
        if not sel:
            q_info(self, "Info", "Select items first.")
            return
        QApplication.clipboard().setText("\n".join(sel))
        self.set_status(f"Copied {len(sel)} IP(s).")

    def export_search_results(self):
        if not self.results:
            q_info(self, "Info", "No search results to export.")
            return
        q = self.query_edit.text().strip()
        base = sanitize_query_for_filename(q if q else "minecraft")
        path = q_ask_save(
            self, "Export Shodan Search Results", f"{base}.txt", "Text files (*.txt)"
        )
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            for (ip, motd, players, version) in self.results:
                if "/" in players:
                    online, maximum = players.split("/", 1)
                else:
                    online, maximum = "N", "A"
                f.write(format_result_line(ip, motd, online, maximum, version) + "\n")
        self.set_status(f"Exported {len(self.results)} rows to {os.path.basename(path)}")


# ===== Qt port section: qt_json (PySide6, 1:1 behavior) =====
"""PySide6 port of JSONTab (scanner.py lines 7371-8041). 1:1 logic port."""
import os
import threading

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)



class JSONTab(QWidget, QtBaseMixin):
    def __init__(self, master=None):
        super().__init__(master)
        self._in_ignore = False
        self.json_entries = []
        self.all_rows = []
        self._loaded_json_path = None
        self.scan_rows = []
        self._version_filter_value = "All versions"
        self._build_ui()
        self._current_scan_ip = None
        self._scan_row_map = {}
        self._cracked_job_id = 0
        self._whitelist_job_id = 0
        self.search_rows = []  # list[tuple(ip,motd,players,version)]
        default_path = self.file_entry.text().strip()
        if default_path and os.path.exists(default_path):
            self.load_json_file(default_path)

    # -- after unchanged (from QtBaseMixin via QTimer.singleShot) --

    def _build_ui(self):
        root = QVBoxLayout(self)

        bar = QHBoxLayout()
        root.addLayout(bar)

        self.file_entry = QLineEdit()
        self.file_entry.setText(DEFAULT_JSONL_FILE)
        self.file_entry.setMinimumWidth(300)
        bar.addWidget(self.file_entry)
        self.import_btn = QPushButton("Import .json")
        self.import_btn.clicked.connect(self.pick_json)
        bar.addWidget(self.import_btn)

        self.query_entry = QLineEdit()
        self.query_entry.setMinimumWidth(300)
        self.query_entry.returnPressed.connect(self.search)
        bar.addWidget(self.query_entry)
        self.search_btn = QPushButton("Search")
        self.search_btn.clicked.connect(self.search)
        bar.addWidget(self.search_btn)
        self.export_search_btn = QPushButton("Export Search…")
        self.export_search_btn.clicked.connect(self.export_search_results)
        bar.addWidget(self.export_search_btn)
        bar.addWidget(QLabel("Version:"))
        self.version_filter_combo = QComboBox()
        self.version_filter_combo.setEditable(True)
        self.version_filter_combo.addItem("All versions")
        self.version_filter_combo.setCurrentText("All versions")
        self.version_filter_combo.currentTextChanged.connect(self._on_version_filter_changed)
        self.version_filter_combo.editTextChanged.connect(self._on_version_filter_changed)
        bar.addWidget(self.version_filter_combo)

        pane = QSplitter()
        pane.setOrientation(Qt.Vertical)
        root.addWidget(pane, 1)

        mid = QWidget()
        mid_layout = QHBoxLayout(mid)
        mid_layout.setContentsMargins(0, 0, 0, 0)

        self.search_tree = ResultTable(("ip", "motd", "players", "version"), mid)
        mid_layout.addWidget(self.search_tree, 1)
        try:
            _get_icon_manager().attach_to_tree(self.search_tree)
        except Exception:
            pass


        right = QWidget()
        right_layout = QVBoxLayout(right)
        self.copy_ip_btn = QPushButton("Copy IP(s)")
        self.copy_ip_btn.clicked.connect(self.copy_ip)
        right_layout.addWidget(self.copy_ip_btn)
        self.add_ignore_btn = QPushButton("Add to Ignore")
        self.add_ignore_btn.clicked.connect(self.add_ignore)
        right_layout.addWidget(self.add_ignore_btn)
        self.add_saved_btn = QPushButton("Add to Saved")
        self.add_saved_btn.clicked.connect(self.add_saved)
        right_layout.addWidget(self.add_saved_btn)
        self.add_monitor_btn = QPushButton("Add to Monitor")
        self.add_monitor_btn.clicked.connect(self.add_search_selected_to_monitor)
        right_layout.addWidget(self.add_monitor_btn)
        self.scan_selected_btn = QPushButton("Scan Selected")
        self.scan_selected_btn.clicked.connect(self.scan_selected)
        right_layout.addWidget(self.scan_selected_btn)
        self.scan_all_btn = QPushButton("Scan All")
        self.scan_all_btn.clicked.connect(self.scan_all)
        right_layout.addWidget(self.scan_all_btn)
        self.only_players_check = QCheckBox("Only players > 0")
        self.only_players_check.setChecked(True)
        right_layout.addWidget(self.only_players_check)
        self.only_cracked_check = QCheckBox("Only cracked servers")
        self.only_cracked_check.setChecked(False)
        right_layout.addWidget(self.only_cracked_check)
        self.check_whitelist_check = QCheckBox("Check whitelist")
        self.check_whitelist_check.setChecked(False)
        right_layout.addWidget(self.check_whitelist_check)
        right_layout.addStretch(1)
        mid_layout.addWidget(right)
        pane.addWidget(mid)

        out = QWidget()
        out_layout = QVBoxLayout(out)
        out_layout.setContentsMargins(0, 0, 0, 0)
        out_layout.addWidget(QLabel("Scan Output (select to copy/save/ignore):"))
        self.scan_tree = ResultTable(
            ("ip", "motd", "players", "version", "cracked", "whitelist", "active_players"), out
        )
        out_layout.addWidget(self.scan_tree, 1)
        try:
            _get_icon_manager().attach_to_tree(self.scan_tree)
        except Exception:
            pass

        pane.addWidget(out)
        pane.setSizes([400, 300])

        footer = QHBoxLayout()
        root.addLayout(footer)
        self.copy_scan_btn = QPushButton("Copy IP(s)")
        self.copy_scan_btn.clicked.connect(self.copy_scan_selected)
        footer.addWidget(self.copy_scan_btn)
        self.ignore_scan_btn = QPushButton("Add to Ignore")
        self.ignore_scan_btn.clicked.connect(self.ignore_scan_selected)
        footer.addWidget(self.ignore_scan_btn)
        self.save_scan_btn = QPushButton("Add to Saved")
        self.save_scan_btn.clicked.connect(self.save_scan_selected)
        footer.addWidget(self.save_scan_btn)
        self.monitor_scan_btn = QPushButton("Add to Monitor")
        self.monitor_scan_btn.clicked.connect(self.add_scan_output_selected_to_monitor)
        footer.addWidget(self.monitor_scan_btn)
        self.export_scan_btn = QPushButton("Export Scan…")
        self.export_scan_btn.clicked.connect(self.export_scan_output)
        footer.addWidget(self.export_scan_btn)
        self.check_whitelist_btn = QPushButton("Check Whitelist")
        self.check_whitelist_btn.clicked.connect(lambda: check_selected_whitelist(self, self.scan_tree))
        footer.addWidget(self.check_whitelist_btn)
        self.player_search_entry = QLineEdit()
        self.player_search_entry.setMaximumWidth(150)
        self.player_search_entry.returnPressed.connect(self.search_players)
        footer.addWidget(self.player_search_entry)
        self.find_player_btn = QPushButton("Find Player")
        self.find_player_btn.clicked.connect(self.search_players)
        footer.addWidget(self.find_player_btn)

        self.status_label = QLabel("Ready.")
        root.addWidget(self.status_label)

    def set_status(self, msg):
        self.status_label.setText(msg)

    def _on_version_filter_changed(self, *args):
        self._populate_search_tree(self.search_rows)

    def _version_filter_text(self):
        return self.version_filter_combo.currentText() or "All versions"

    def _update_version_filter_choices(self, rows):
        choices = collect_version_options(rows)
        current = self._version_filter_text() or "All versions"
        self.version_filter_combo.blockSignals(True)
        try:
            self.version_filter_combo.clear()
            self.version_filter_combo.addItems(choices)
            if current not in choices:
                current = "All versions"
            self.version_filter_combo.setCurrentText(current)
        finally:
            self.version_filter_combo.blockSignals(False)

    def _populate_search_tree(self, rows):
        self.search_tree.clear_rows()
        for ip, motd, players, version in rows:
            if version_filter_allows(version, self._version_filter_text()):
                self.search_tree.add_row((ip, motd, players, version))

    def _load_json_data(self, path):
        entries = load_json_entries(path)
        rows = json_entries_to_rows(entries)
        return entries, rows

    def load_json_file(self, path):
        if not path:
            return
        self._populate_search_tree([])
        self.set_status("Loading JSON…")

        def work():
            try:
                entries, rows = self._load_json_data(path)

                def update():
                    self.json_entries = entries
                    self.all_rows = rows
                    self.search_rows = list(rows)
                    self.scan_rows = []
                    self._loaded_json_path = path
                    self._update_version_filter_choices(rows)
                    self._populate_search_tree(rows)
                    self.set_status(f"Loaded {len(rows)} entries from {os.path.basename(path)}.")
                self.after(0, update)
            except Exception as e:
                self.after(0, lambda: self.set_status(f"Load failed: {e}"))
        threading.Thread(target=work, daemon=True).start()

    def pick_json(self):
        path, _ = QFileDialog.getOpenFileName(self, "Pick JSON Lines", "", "JSON/JSONL (*.json *.jsonl *.*)")
        if path:
            self.file_entry.setText(path)
            self.load_json_file(path)

    def search(self):
        file_path = self.file_entry.text().strip()
        query = self.query_entry.text().strip()
        status_msg = "Searching..." if query else "Loading data..."
        self.set_status(status_msg)
        self._populate_search_tree([])

        def work():
            try:
                if not self.json_entries or self._loaded_json_path != file_path:
                    entries, rows = self._load_json_data(file_path)
                    self.json_entries = entries
                    self.all_rows = rows
                    self._loaded_json_path = file_path
                if not query:
                    rows = json_entries_to_rows(self.json_entries)
                    self.all_rows = rows
                    result_message = f"Showing all {len(rows)} entrie(s)."
                else:
                    filtered = filter_entries_JSON(self.json_entries, query)
                    rows = []
                    seen = set()
                    for line in filtered:
                        ip, motd, players, version = parse_formatted_line(line)
                        ip = get_ip_only(ip)
                        if not is_valid_ip_port(ip) or is_ignored(ip) or ip in seen:
                            continue
                        rows.append((ip, motd, players, version))
                        seen.add(ip)
                    result_message = f"{len(rows)} result(s)."

                def update():
                    self.search_rows = list(rows)
                    self.scan_rows = []
                    if not query:
                        self.all_rows = list(rows)
                    self._update_version_filter_choices(rows)
                    self._populate_search_tree(rows)
                    self.set_status(result_message)
                self.after(0, update)
            except FileNotFoundError:
                self.after(0, lambda: self.set_status(f"File not found: {file_path}"))
            except Exception as e:
                self.after(0, lambda: self.set_status(f"Search failed: {e}"))
        threading.Thread(target=work, daemon=True).start()

    def _search_selected_rows(self):
        return [tuple(r) for r in self.search_tree.selected_rows()]

    def _search_selected_ips(self):
        return [row[0] for row in self._search_selected_rows() if row]

    def _all_selected_ips(self):
        ips = self._search_selected_ips()
        for row in self._scan_selected_rows():
            if row:
                ips.append(row[0])
        seen = []
        for ip in ips:
            if ip not in seen:
                seen.append(ip)
        return seen

    def copy_ip(self):
        ips = self._all_selected_ips()
        if not ips:
            QMessageBox.information(self, "Info", "Select items first.")
            return
        QApplication.clipboard().setText("\n".join(ips))
        self.set_status(f"Copied {len(ips)} IP(s).")

    def add_ignore(self):
        if self._in_ignore:
            return
        rows = self._search_selected_rows()
        if not rows:
            QMessageBox.information(self, "Info", "Select items first.")
            return
        reason = ask_reason_with_whitelist(self, "Reason", "Why ignore? (optional)")
        if reason is None:
            self.set_status("Ignore cancelled.")
            return
        self._in_ignore = True
        try:
            for (ip, *_rest) in rows:
                add_to_ignore(ip, reason or "")
            self.search_tree.remove_selected()
            self.set_status(f"Added {len(rows)} to ignore.txt")
        finally:
            self._in_ignore = False

    def add_saved(self):
        rows = self._search_selected_rows()
        if not rows:
            QMessageBox.information(self, "Info", "Select items first.")
            return
        reason, ok = QInputDialog.getText(self, "Reason", "Why save? (optional)")
        if not ok:
            reason = ""
        for (ip, *_rest) in rows:
            add_to_saved(ip, reason or "")
        self.set_status(f"Added {len(rows)} to saved.txt")

    def add_search_selected_to_monitor(self):
        ips = self._all_selected_ips()
        if not ips:
            QMessageBox.information(self, "Info", "Select items first.")
            return
        added, invalid, duplicates = add_ips_to_monitor_list(ips)
        self.set_status(format_monitor_feedback(added, invalid, duplicates))

    def add_search_selected_to_monitor(self):
        rows = self._search_selected_rows()
        if not rows:
            QMessageBox.information(self, "Info", "Select items first.")
            return
        ips = [row[0] for row in rows]
        added, invalid, duplicates = add_ips_to_monitor_list(ips)
        self.set_status(format_monitor_feedback(added, invalid, duplicates))

    # ---- JSON scan-output helpers ----
    def _scan_selected_rows(self):
        return [tuple(r) for r in self.scan_tree.selected_rows()]

    def search_players(self):
        query_raw = self.player_search_entry.text() or ""
        query = query_raw.strip().lower()
        if not query:
            self.set_status("Enter a player name to search.")
            return
        matches = self.scan_tree.find_rows_containing(len(self.scan_tree._columns) - 1, query)
        self.scan_tree.clearSelection()
        if matches:
            self.scan_tree.select_rows(matches)
            self.scan_tree.setCurrentCell(matches[0], 0)
            self.scan_tree.scrollToItem(self.scan_tree.item(matches[0], 0))
            self.set_status(f"Found {len(matches)} match(es) for '{query_raw.strip()}'.")
        else:
            self.set_status(f"No matches for '{query_raw.strip()}'.")
    def _reset_scan_row_map(self):
        self._scan_row_map = {}

    def _register_scan_row(self, ip, iid):
        self._scan_row_map[ip] = iid

    def _update_scan_row_cracked(self, ip, text):
        iid = self._scan_row_map.get(ip)
        if iid is None:
            return
        vals = list(self.scan_tree.row_values(iid))
        if len(vals) >= 5:
            self.scan_tree.set_cell(iid, 4, text)

    def _update_scan_row_whitelist(self, ip, text):
        iid = self._scan_row_map.get(ip)
        if iid is None:
            return
        vals = list(self.scan_tree.row_values(iid))
        if len(vals) >= 6:
            self.scan_tree.set_cell(iid, 5, text)

    def _remove_scan_row(self, ip):
        iid = self._scan_row_map.pop(ip, None)
        if iid is not None:
            try:
                self.scan_tree.remove_rows([iid])
            except Exception:
                pass
            # Rebuild map since row indices shifted
            self._rebuild_scan_row_map()

    def _rebuild_scan_row_map(self):
        new_map = {}
        for r in range(self.scan_tree.rowCount()):
            vals = self.scan_tree.row_values(r)
            if vals:
                new_map[vals[0]] = r
        # Keep only previously tracked IPs
        self._scan_row_map = {ip: new_map[ip] for ip in list(self._scan_row_map) if ip in new_map}
        # Also include any rows (harmless superset for updates)
        for ip, r in new_map.items():
            if ip not in self._scan_row_map:
                self._scan_row_map[ip] = r

    def _scan_and_show(self, items):
        self.scan_tree.clear_rows()
        self.set_status("Preparing scan...")
        only_cracked = self.only_cracked_check.isChecked()
        check_whitelist = self.check_whitelist_check.isChecked()
        # Cracked servers need no account (offline probe, no Mojang auth).
        account = get_active_mc_account() if check_whitelist else None
        self.scan_rows = []
        if only_cracked or check_whitelist:
            self._reset_scan_row_map()
            self._cracked_job_id += 1
            self._whitelist_job_id += 1
        else:
            self._scan_row_map.clear()
        current_job = self._cracked_job_id
        whitelist_job = self._whitelist_job_id
        pending_entries = []
        pending_seen = set()
        whitelist_entries = []
        whitelist_seen = set()
        pending_lock = threading.Lock()

        def work():
            try:
                total = len(items)

                def on_start(ip):
                    self._current_scan_ip = ip
                    self.after(0, lambda ip=ip: self.set_status(f"Currently scanning: {ip} [0/{total}]"))

                def on_result(r, line):
                    if not r:
                        return
                    self.scan_rows.append((
                        r['ip'],
                        r['motd'],
                        f"{r['players']}/{r['max_players']}",
                        r['version'],
                        "Yes" if r.get('cracked') else "No",
                        "Queued" if check_whitelist else "-",
                        format_player_list(r.get('players_sample'))
                    ))

                    if self.only_players_check.isChecked() and r.get('players', 0) <= 0:
                        return
                    if only_cracked and should_skip_cracked_probe(r):
                        return
                    if not version_filter_allows(r.get("version", ""), self._version_filter_text()):
                        return

                    cracked_text = "Yes" if r.get('cracked') else "No"
                    whitelist_text = "Queued" if check_whitelist else "-"
                    queue_candidate = None
                    if only_cracked:
                        cached = get_cached_cracked_entry(r['ip'])
                        if cached:
                            cracked_text = "Yes (cached)"
                        else:
                            cracked_text = "Queued"
                            queue_candidate = r

                    active_players = format_player_list(r.get('players_sample'))
                    vals = (
                        r['ip'],
                        r['motd'],
                        f"{r['players']}/{r['max_players']}",
                        r['version'],
                        cracked_text,
                        whitelist_text,
                        active_players
                    )

                    def add_row(ip=r['ip'], v=vals):
                        iid = self.scan_tree.add_row(v)
                        if only_cracked or check_whitelist:
                            self._register_scan_row(ip, iid)
                    self.after(0, add_row)

                    if only_cracked and queue_candidate:
                        with pending_lock:
                            ip = queue_candidate['ip']
                            if ip not in pending_seen:
                                pending_seen.add(ip)
                                pending_entries.append(queue_candidate)
                    if check_whitelist:
                        with pending_lock:
                            ip = r['ip']
                            if ip not in whitelist_seen:
                                whitelist_seen.add(ip)
                                whitelist_entries.append(r)

                def on_progress(done, total):
                    ip = self._current_scan_ip or "…"
                    self.after(0, lambda d=done, t=total, ip=ip:
                               self.set_status(f"Currently scanning: {ip} [{d}/{t}]"))

                results, online_lines = scan_servers_gui(
                    items,
                    on_start=on_start,
                    on_result=on_result,
                    on_progress=on_progress
                )
                self.after(0, lambda: self.set_status(f"Scan complete. Responded: {len(results)}; With 1+: {len(online_lines)}"))
                if only_cracked:
                    with pending_lock:
                        verify_entries = list(pending_entries)

                    def handle_update(entry, result, message, was_cached):
                        if current_job != self._cracked_job_id:
                            return
                        ip = entry.get("ip")

                        def ui():
                            if was_cached or result is True:
                                label = "Yes (cached)" if was_cached else "Yes"
                                self._update_scan_row_cracked(ip, label)
                            else:
                                self._remove_scan_row(ip)
                        self.after(0, ui)

                    def handle_progress(done, total):
                        if current_job != self._cracked_job_id:
                            return
                        if done < total:
                            self.after(0, lambda d=done, t=total:
                                       self.set_status(f"Verifying cracked servers: {d}/{t}"))
                        else:
                            def finish():
                                remaining = self.scan_tree.rowCount()
                                self.set_status(f"Cracked verification complete. Showing {remaining} server(s).")
                            self.after(0, finish)
                    run_cracked_verifier_async(verify_entries, handle_update, progress_cb=handle_progress)
                if check_whitelist:
                    with pending_lock:
                        verify_whitelist = list(whitelist_entries)

                    def handle_whitelist_update(entry, result, message):
                        if whitelist_job != self._whitelist_job_id:
                            return
                        ip = entry.get("ip")

                        def ui():
                            label = whitelist_result_label(result, message)
                            self._update_scan_row_whitelist(ip, label)
                        self.after(0, ui)

                    def handle_whitelist_progress(done, total):
                        if whitelist_job != self._whitelist_job_id:
                            return
                        if done < total:
                            self.after(0, lambda d=done, t=total:
                                       self.set_status(f"Checking whitelist: {d}/{t}"))
                        else:
                            self.after(0, lambda:
                                       self.set_status(f"Whitelist check complete for {total} server(s)."))
                    run_whitelist_verifier_async(verify_whitelist, account, handle_whitelist_update, progress_cb=handle_whitelist_progress)
                if self.scan_rows:
                    self.after(0, lambda rows=list(self.scan_rows): self._update_version_filter_choices(rows))
            except Exception as e:
                self.after(0, lambda: self.set_status(f"Scan failed: {e}"))

        threading.Thread(target=work, daemon=True).start()

    def scan_selected(self):
        ips = self._all_selected_ips()
        if not ips:
            QMessageBox.information(self, "Info", "Select items first.")
            return
        self._scan_and_show(ips)

    def scan_all(self):
        if not self.search_rows:
            QMessageBox.information(self, "Info", "Run a search first.")
            return
        ips = [row[0] for row in self.search_rows]
        self._scan_and_show(ips)

    def copy_scan_selected(self):
        rows = self._scan_selected_rows()
        if not rows:
            QMessageBox.information(self, "Info", "Select scan output rows.")
            return
        ips = [row[0] for row in rows]
        QApplication.clipboard().setText("\n".join(ips))
        self.set_status(f"Copied {len(ips)} IP(s) from scan output.")

    def ignore_scan_selected(self):
        rows = self._scan_selected_rows()
        if not rows:
            QMessageBox.information(self, "Info", "Select scan output rows.")
            return
        reason = ask_reason_with_whitelist(self, "Reason", "Why ignore? (optional)")
        if reason is None:
            self.set_status("Ignore cancelled.")
            return
        for (ip, *_rest) in rows:
            add_to_ignore(ip, reason or "")
        self.scan_tree.remove_selected()
        self.set_status(f"Added {len(rows)} to ignore.txt from scan output.")

    def save_scan_selected(self):
        rows = self._scan_selected_rows()
        if not rows:
            QMessageBox.information(self, "Info", "Select scan output rows.")
            return
        reason, ok = QInputDialog.getText(self, "Reason", "Why save? (optional)")
        if not ok:
            reason = ""
        for (ip, *_rest) in rows:
            add_to_saved(ip, reason or "")
        self.set_status(f"Added {len(rows)} to saved.txt from scan output.")

    def add_scan_output_selected_to_monitor(self):
        rows = self._scan_selected_rows()
        if not rows:
            QMessageBox.information(self, "Info", "Select scan output rows.")
            return
        ips = [row[0] for row in rows]
        added, invalid, duplicates = add_ips_to_monitor_list(ips)
        self.set_status(format_monitor_feedback(added, invalid, duplicates))

    def export_search_results(self):
        if not self.search_rows:
            QMessageBox.information(self, "Info", "No search results to export.")
            return
        q = self.query_entry.text().strip()
        base = sanitize_query_for_filename(q if q else "json_search")
        path, _ = QFileDialog.getSaveFileName(
            self, "Export JSON Search Results", f"{base}.txt", "Text files (*.txt)"
        )
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            for (ip, motd, players, version) in self.search_rows:
                online, maximum = ("N", "A")
                if "/" in players:
                    parts = players.split("/", 1)
                    online, maximum = parts[0], parts[1]
                f.write(format_result_line(ip, motd, online, maximum, version) + "\n")
        self.set_status(f"Exported {len(self.search_rows)} rows to {os.path.basename(path)}")

    def export_scan_output(self):
        rows = self.scan_tree.get_all_rows()
        if not rows:
            QMessageBox.information(self, "Info", "No scan output to export.")
            return
        q = self.query_entry.text().strip()
        base = sanitize_query_for_filename((q if q else "json_search") + "_scan")
        path, _ = QFileDialog.getSaveFileName(
            self, "Export JSON Scan Output", f"{base}.txt", "Text files (*.txt)"
        )
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            for row in rows:
                if not row:
                    continue
                ip = row[0]
                motd = row[1] if len(row) > 1 else ""
                players = row[2] if len(row) > 2 else "N/A"
                version = row[3] if len(row) > 3 else "N/A"
                if "/" in str(players):
                    online, maximum = str(players).split("/", 1)
                else:
                    online, maximum = "N", "A"
                f.write(format_result_line(ip, motd, online, maximum, version) + "\n")
        self.set_status(f"Exported {len(rows)} scan rows to {os.path.basename(path)}")


# ===== Qt port section: qt_rest (PySide6, 1:1 behavior) =====
"""PySide6 port of ExportTab (scanner.py:8041-8094),
_ReasonFileTab/SavedTab/IgnoreTab (8095-8228), IpLogTab (8229-8321),
UserLogTab (8322-8482) and FullAppGUI (5696-5734). 1:1 logic, Qt widgets only.

Backend symbols (reference as-is, provided by scanner.py):
    import_file_to_servers_dat, BACKUP_PATH, SERVERS_DAT_PATH,
    load_reason_file, save_reason_file, SAVED_FILE, IGNORE_FILE,
    refresh_ignore_set, is_valid_ip_port, get_ip_only,
    get_active_mc_account, whitelist_result_label,
    run_whitelist_verifier_async, load_ips_rows, save_ips_rows,
    GLOBAL_IP_LOG, sanitize_motd, make_tree_sortable,
    _ip_key, _players_key, _version_key, USER_LOG_MANAGER
"""

import os
import shutil
import threading
import time

from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QPushButton,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)




class ExportTab(QWidget, QtBaseMixin):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._build_ui()

    def _build_ui(self):
        root = QVBoxLayout(self)

        box = QHBoxLayout()
        root.addLayout(box)
        self.file_edit = QLineEdit()
        box.addWidget(self.file_edit, 1)
        btn_pick = QPushButton("Pick .txt")
        btn_pick.clicked.connect(self.pick_txt)
        box.addWidget(btn_pick)

        self.backup_check = QCheckBox("Backup servers.dat if no backup exists")
        self.backup_check.setChecked(True)
        root.addWidget(self.backup_check)

        btns = QHBoxLayout()
        root.addLayout(btns)
        btn_export = QPushButton("Export to servers.dat")
        btn_export.clicked.connect(self.do_import)
        btns.addWidget(btn_export)
        btn_restore = QPushButton("Restore Backup")
        btn_restore.clicked.connect(self.restore_backup)
        btns.addWidget(btn_restore)
        btns.addStretch(1)

        self.status_label = QLabel("Ready.")
        root.addWidget(self.status_label)
        root.addStretch(1)

    def pick_txt(self):
        path = q_ask_open(
            self,
            "Pick .txt source",
            "Text files (*.txt);;All files (*.*)",
        )
        if path:
            self.file_edit.setText(path)

    def do_import(self):
        path = self.file_edit.text().strip()
        if not path:
            q_info(self, "Info", "Pick a .txt first.")
            return

        def work():
            ok, msg = import_file_to_servers_dat(path, do_backup=self.backup_check.isChecked())
            self.set_status(msg if ok else f"Failed: {msg}")

        threading.Thread(target=work, daemon=True).start()
        self.set_status("Importing...")

    def restore_backup(self):
        try:
            if not os.path.exists(BACKUP_PATH):
                q_info(self, "Info", "No backup found.")
                return
            shutil.copyfile(BACKUP_PATH, SERVERS_DAT_PATH)
            self.set_status("Backup restored.")
        except Exception as e:
            self.set_status(f"Restore failed: {e}")


# ---- Saved / Ignore (Reason file) Tab ----
class ReasonFileTab(QWidget, QtBaseMixin):
    def __init__(self, parent=None, file_path="", tab_name=""):
        super().__init__(parent)
        self.file_path = file_path
        self.tab_name = tab_name
        self.rows = []  # list[(ip, reason)]
        self._scan_status_label = None
        self._build_ui()
        self._load()

    def _build_ui(self):
        root = QVBoxLayout(self)

        bar = QHBoxLayout()
        root.addLayout(bar)
        btn_add = QPushButton("Add")
        btn_add.clicked.connect(self._add)
        bar.addWidget(btn_add)
        btn_edit = QPushButton("Edit")
        btn_edit.clicked.connect(self._edit)
        bar.addWidget(btn_edit)
        btn_remove = QPushButton("Remove")
        btn_remove.clicked.connect(self._remove)
        bar.addWidget(btn_remove)
        btn_copy = QPushButton("Copy IP(s)")
        btn_copy.clicked.connect(self._copy)
        bar.addWidget(btn_copy)
        btn_reload = QPushButton("Reload")
        btn_reload.clicked.connect(self._load)
        bar.addWidget(btn_reload)
        btn_save = QPushButton("Save")
        btn_save.clicked.connect(self._save)
        bar.addWidget(btn_save)
        if self.tab_name == "Ignore":
            btn_scan = QPushButton("Scan Entire List for Whitelist")
            btn_scan.clicked.connect(self._scan_whitelist)
            bar.addWidget(btn_scan)
        bar.addStretch(1)

        cols = ("ip", "reason", "whitelist") if self.tab_name == "Ignore" else ("ip", "reason")
        self._columns = cols
        self.tree = ResultTable()
        self.tree.set_columns(cols)
        root.addWidget(self.tree, 1)

        # enable sorting
        make_tree_sortable(self.tree, {
            "ip": _ip_key,
            "reason": lambda v: str(v).lower(),
        })

    def _load(self):
        self.rows = load_reason_file(self.file_path)
        self.tree.delete(*self.tree.get_children())
        for ip, reason in self.rows:
            values = (ip, reason, "-") if self.tab_name == "Ignore" else (ip, reason)
            self.tree.insert("", "end", values=values)

    def _save(self):
        # collect from UI to rows
        rows = []
        for iid in self.tree.get_children():
            values = self.tree.item(iid, "values")
            ip, reason = values[:2]
            if is_valid_ip_port(ip):
                rows.append((ip, reason))
        save_reason_file(self.file_path, rows)
        # refresh in-memory ignore set if needed
        if self.file_path == IGNORE_FILE:
            refresh_ignore_set()
        q_info(self, self.tab_name, "Saved.")

    def _scan_whitelist(self):
        # Cracked servers need no account; online-mode hits report missing auth.
        account = get_active_mc_account()
        entries = []
        for iid in self.tree.get_children(""):
            values = self.tree.item(iid, "values")
            if values and is_valid_ip_port(values[0]):
                entries.append({"ip": values[0]})
                self.tree.set(iid, "whitelist", "Queued")
        if not entries:
            return

        def update(entry, result, message):
            ip = entry.get("ip")
            label = whitelist_result_label(result, message)
            for iid in self.tree.get_children(""):
                values = self.tree.item(iid, "values")
                if values and values[0] == ip:
                    self.after(0, lambda i=iid, v=label: self.tree.set(i, "whitelist", v))
                    break

        def progress(done, total):
            self.after(0, lambda d=done, t=total: self._set_scan_status(f"Whitelist scan: {d}/{t}"))

        self._set_scan_status(f"Whitelist scan queued: {len(entries)} server(s)")
        run_whitelist_verifier_async(entries, account, update, progress_cb=progress)

    def _set_scan_status(self, text):
        if self._scan_status_label is not None:
            self._scan_status_label.setText(text)
        else:
            self._scan_status_label = QLabel(text)
            self.layout().addWidget(self._scan_status_label)

    def _selected_iids(self):
        return list(self.tree.selection())

    def _add(self):
        ip = q_ask_string(self, self.tab_name, "IP:PORT")
        if not ip or not is_valid_ip_port(ip):
            return
        reason = q_ask_string(self, self.tab_name, "Reason (optional)") or ""
        if self.tab_name == "Ignore":
            self.tree.insert("", "end", values=(get_ip_only(ip), reason, "-"))
        else:
            self.tree.insert("", "end", values=(get_ip_only(ip), reason))

    def _edit(self):
        iids = self._selected_iids()
        if not iids:
            return
        values = self.tree.item(iids[0], "values")
        ip, reason = values[:2]
        new_ip = q_ask_string(self, self.tab_name, "IP:PORT", initial=ip) or ip
        if not is_valid_ip_port(get_ip_only(new_ip)):
            return
        new_reason = q_ask_string(self, self.tab_name, "Reason", initial=reason) or ""
        values = (get_ip_only(new_ip), new_reason, values[2]) if self.tab_name == "Ignore" else (get_ip_only(new_ip), new_reason)
        self.tree.item(iids[0], values=values)

    def _remove(self):
        for iid in self._selected_iids():
            self.tree.delete(iid)

    def _copy(self):
        ips = []
        for iid in self._selected_iids():
            v = self.tree.item(iid, "values")
            if v:
                ips.append(v[0])
        if not ips:
            return
        QApplication.clipboard().setText("\n".join(ips))


_ReasonFileTab = ReasonFileTab


class SavedTab(ReasonFileTab):
    def __init__(self, parent=None):
        super().__init__(parent, SAVED_FILE, "Saved")


class IgnoreTab(ReasonFileTab):
    def __init__(self, parent=None):
        super().__init__(parent, IGNORE_FILE, "Ignore")


# ---- IP Log (ips.txt) Tab ----
class IpLogTab(QWidget, QtBaseMixin):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.rows = []  # list[(ip,motd,players,version)]
        self._build_ui()
        self._load()

    def _build_ui(self):
        root = QVBoxLayout(self)

        bar = QHBoxLayout()
        root.addLayout(bar)
        btn_add = QPushButton("Add")
        btn_add.clicked.connect(self._add)
        bar.addWidget(btn_add)
        btn_edit = QPushButton("Edit")
        btn_edit.clicked.connect(self._edit)
        bar.addWidget(btn_edit)
        btn_remove = QPushButton("Remove")
        btn_remove.clicked.connect(self._remove)
        bar.addWidget(btn_remove)
        btn_copy = QPushButton("Copy IP(s)")
        btn_copy.clicked.connect(self._copy)
        bar.addWidget(btn_copy)
        btn_reload = QPushButton("Reload")
        btn_reload.clicked.connect(self._load)
        bar.addWidget(btn_reload)
        btn_save = QPushButton("Save")
        btn_save.clicked.connect(self._save)
        bar.addWidget(btn_save)
        bar.addStretch(1)

        cols = ("ip", "motd", "players", "version")
        self.tree = ResultTable()
        self.tree.set_columns(cols)
        root.addWidget(self.tree, 1)

        # enable sorting
        make_tree_sortable(self.tree, {
            "ip": _ip_key,
            "motd": lambda v: str(v).lower(),
            "players": _players_key,
            "version": _version_key,
        })

    def _load(self):
        self.rows = load_ips_rows(GLOBAL_IP_LOG)
        self.tree.delete(*self.tree.get_children())
        for row in self.rows:
            self.tree.insert("", "end", values=row)

    def _save(self):
        rows = []
        for iid in self.tree.get_children():
            vals = self.tree.item(iid, "values")
            if vals and is_valid_ip_port(vals[0]):
                rows.append(vals)
        save_ips_rows(rows, GLOBAL_IP_LOG)
        q_info(self, "IP Log", "Saved.")

    def _selected_iids(self):
        return list(self.tree.selection())

    def _add(self):
        ip = q_ask_string(self, "IP Log", "IP:PORT")
        if not ip or not is_valid_ip_port(ip):
            return
        motd = q_ask_string(self, "IP Log", "MOTD (optional)") or ""
        players = q_ask_string(self, "IP Log", "Players (e.g. 0/20 or N/A)", initial="N/A") or "N/A"
        version = q_ask_string(self, "IP Log", "Version (optional)") or "N/A"
        self.tree.insert("", "end", values=(get_ip_only(ip), motd, players, version))

    def _edit(self):
        iids = self._selected_iids()
        if not iids:
            return
        ip, motd, players, version = self.tree.item(iids[0], "values")
        new_ip = q_ask_string(self, "IP Log", "IP:PORT", initial=ip) or ip
        if not is_valid_ip_port(get_ip_only(new_ip)):
            return
        motd = q_ask_string(self, "IP Log", "MOTD", initial=motd) or ""
        players = q_ask_string(self, "IP Log", "Players", initial=players) or players
        version = q_ask_string(self, "IP Log", "Version", initial=version) or version
        self.tree.item(iids[0], values=(get_ip_only(new_ip), motd, players, version))

    def _remove(self):
        for iid in self._selected_iids():
            self.tree.delete(iid)

    def _copy(self):
        ips = []
        for iid in self._selected_iids():
            v = self.tree.item(iid, "values")
            if v:
                ips.append(v[0])
        if not ips:
            return
        QApplication.clipboard().setText("\n".join(ips))


class UserLogTab(QWidget, QtBaseMixin):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._manager = None
        self._refresh_pending = False
        self._cached_entries = []
        self._build_ui()

    def _build_ui(self):
        root = QVBoxLayout(self)

        bar = QHBoxLayout()
        root.addLayout(bar)
        btn_copy_players = QPushButton("Copy Player(s)")
        btn_copy_players.clicked.connect(self.copy_players)
        bar.addWidget(btn_copy_players)
        btn_copy_ips = QPushButton("Copy IP(s)")
        btn_copy_ips.clicked.connect(self.copy_ips)
        bar.addWidget(btn_copy_ips)
        btn_export = QPushButton("Export Log…")
        btn_export.clicked.connect(self.export_log)
        bar.addWidget(btn_export)
        self.user_search_edit = QLineEdit()
        self.user_search_edit.setFixedWidth(160)
        bar.addWidget(self.user_search_edit)
        btn_search = QPushButton("Search Player")
        btn_search.clicked.connect(self.search_player_log)
        bar.addWidget(btn_search)
        btn_clear = QPushButton("Clear Search")
        btn_clear.clicked.connect(self.clear_player_log_search)
        bar.addWidget(btn_clear)
        bar.addStretch(1)

        cols = ("player", "ip", "motd", "last_seen")
        self.tree = ResultTable()
        self.tree.set_columns(cols)
        root.addWidget(self.tree, 1)

        make_tree_sortable(self.tree, {
            "player": lambda v: str(v).lower(),
            "ip": _ip_key,
            "motd": lambda v: str(v).lower(),
            "last_seen": lambda v: str(v),
        })

        self.status_label = QLabel("Ready.")
        root.addWidget(self.status_label)

    def bind_manager(self, manager):
        self._manager = manager

    def request_refresh(self, initial=False):
        if not self._manager:
            return
        if self._refresh_pending and not initial:
            return
        self._refresh_pending = True
        try:
            self.after(0, self._refresh_from_manager)
        except Exception:
            self._refresh_pending = False

    def _refresh_from_manager(self):
        if not self._manager:
            self._refresh_pending = False
            return
        entries = self._manager.snapshot()
        entries.sort(key=lambda e: e["last_seen"], reverse=True)
        self._cached_entries = list(entries)
        self._populate_user_tree(entries)
        self.set_status(f"Tracking {len(entries)} player(s).")
        self._refresh_pending = False

    def _populate_user_tree(self, entries):
        self.tree.delete(*self.tree.get_children())
        for entry in entries:
            self.tree.insert(
                "",
                "end",
                values=(
                    entry["player"],
                    entry["ip"],
                    entry["motd"],
                    self._format_last_seen(entry["last_seen"]),
                ),
            )

    def search_player_log(self):
        query = (self.user_search_edit.text() or "").strip().lower()
        if not query:
            self.set_status("Enter a player name to search.")
            return
        matches = [
            entry for entry in self._cached_entries
            if query in (entry.get("player") or "").lower()
        ]
        self._populate_user_tree(matches)
        self.set_status(f"{len(matches)} match(es) for '{self.user_search_edit.text().strip()}'.")

    def clear_player_log_search(self):
        self.user_search_edit.setText("")
        self._populate_user_tree(self._cached_entries)
        self.set_status(f"Tracking {len(self._cached_entries)} player(s).")

    def _format_last_seen(self, ts):
        try:
            return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
        except Exception:
            return "-"

    def _selected_rows(self):
        rows = []
        for iid in self.tree.selection():
            vals = self.tree.item(iid, "values")
            if vals:
                rows.append(vals)
        return rows

    def copy_players(self):
        rows = self._selected_rows()
        if not rows:
            q_info(self, "User Log", "Select one or more rows.")
            return
        players = [row[0] for row in rows]
        QApplication.clipboard().setText("\n".join(players))
        self.set_status(f"Copied {len(players)} player(s).")

    def copy_ips(self):
        rows = self._selected_rows()
        if not rows:
            q_info(self, "User Log", "Select one or more rows.")
            return
        ips = [row[1] for row in rows]
        QApplication.clipboard().setText("\n".join(ips))
        self.set_status(f"Copied {len(ips)} IP(s).")

    def export_log(self):
        if not self._cached_entries:
            q_info(self, "User Log", "Nothing to export yet.")
            return
        path = q_ask_save(
            self,
            "Export User Log",
            "Text files (*.txt);;All files (*.*)",
            default_suffix=".txt",
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                for entry in self._cached_entries:
                    ts = self._format_last_seen(entry["last_seen"])
                    motd = sanitize_motd(entry["motd"])
                    f.write(f"{entry['player']} | {entry['ip']} | Last Seen: {ts} | MOTD: {motd}\n")
            self.set_status(f"Exported {len(self._cached_entries)} player(s) to {os.path.basename(path)}.")
        except Exception as e:
            self.set_status(f"Export failed: {e}")
            q_error(self, "User Log", f"Export failed: {e}")


class FullAppGUI(QMainWindow):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Minecraft Server Scanner — GUI")
        self.resize(1100, 760)
        self.create_widgets()

    def create_widgets(self):
        nb = QTabWidget(self)
        self.setCentralWidget(nb)
        self.nb = nb

        # Tabs
        self.shodan_tab = ShodanTab(nb)
        self.network_tab = NetworkScanTab(nb)
        self.json_tab = JSONTab(nb)
        self.servers_tab = ServersTab(nb)
        self.import_tab = ExportTab(nb)
        self.saved_tab = SavedTab(nb)
        self.ignore_tab = IgnoreTab(nb)
        self.iplog_tab = IpLogTab(nb)
        self.user_log_tab = UserLogTab(nb)
        self.account_tab = AccountTab(nb)
        self.monitor_tab = ServerMonitorTab(nb)
        self.proxy_tab = ProxyTab(nb)

        nb.addTab(self.shodan_tab, "Shodan")
        nb.addTab(self.network_tab, "Network Scan")
        nb.addTab(self.json_tab, "JSON Search")
        nb.addTab(self.servers_tab, "Servers")
        nb.addTab(self.import_tab, "Export To MC")
        nb.addTab(self.saved_tab, "Saved List")
        nb.addTab(self.ignore_tab, "Ignore List")
        nb.addTab(self.iplog_tab, "IP Log")
        nb.addTab(self.user_log_tab, "User Log")
        nb.addTab(self.account_tab, "Accounts")
        nb.addTab(self.proxy_tab, "Proxies")
        nb.addTab(self.monitor_tab, "Server Monitor")

        USER_LOG_MANAGER.attach_tab(self.user_log_tab)

# ==================== GUI entry ====================
def main():  #gone but not forgotten
    import sys
    app = QApplication.instance() or QApplication(sys.argv)
    win = FullAppGUI()
    win.show()
    try:
        app.exec()
    except Exception:
        pass


if __name__ == "__main__":  #
    main()
