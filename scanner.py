# === Minecraft Scanner by Cev-API ===

import shodan
import socket
import struct
import json
import re
import os
import random
import time
import shutil
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

# Tkinter + threading
import tkinter as tk  
from tkinter import ttk, filedialog, messagebox, simpledialog  
import threading  

import base64  
import io      
try:
    from PIL import Image, ImageTk  
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
CRACKED_VERIFY_WORKERS = 10
MC_ACCOUNTS_FILE = "mc_accounts.json"
PRISM_ACCOUNTS_PATH = os.path.expandvars(r"%APPDATA%\PrismLauncher\accounts.json")
PROXIES_FILE = "proxies.json"
PROXY_TEST_HOST = "api.minecraftservices.com"
PROXY_TEST_PORT = 443
WHITELIST_VERIFY_WORKERS = 1
WHITELIST_PROBE_DELAY = 2.5
MOJANG_RATE_LIMIT_COOLDOWN = 45
MOJANG_JOIN_RETRIES = 2
NETWORK_SCAN_WORKERS = 500
NETWORK_SCAN_DEFAULT_PORTS = "25565"
NETWORK_SCAN_MAX_HOSTS = 4096

# Never trust a server-provided length.  Apart from protecting against broken
# servers, this prevents a single scan target from reserving gigabytes of RAM.
MAX_STATUS_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_FAVICON_RESPONSE_BYTES = 512 * 1024
MAX_ICON_CACHE_ENTRIES = 512

_CRACKED_CACHE_LOCK = threading.Lock()
_WHITELIST_LOG_LOCK = threading.Lock()
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
    """
    key = _load_key_from_cwd()
    if key:
        return key
    key = simpledialog.askstring(
        "Shodan API Key",
        "Enter your Shodan API key:",
        parent=parent,
        show="*"  # hides the text while typing
    )
    if key:
        _save_key_to_cwd(key)
        return key.strip()
    return None

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
        if attempt < 2:
            time.sleep(0.25)
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

def ensure_minecraft_session_join(account, server_hash):
    last_rate_limit = False
    for attempt in range(MOJANG_JOIN_RETRIES + 1):
        try:
            minecraft_join_server(account, server_hash, verify=False)
            return account
        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                last_rate_limit = True
                if attempt < MOJANG_JOIN_RETRIES:
                    time.sleep(MOJANG_RATE_LIMIT_COOLDOWN)
                    continue
                raise MinecraftSessionError(
                    f"Mojang sessionserver rate limited join after {MOJANG_JOIN_RETRIES + 1} attempt(s)"
                )
            if exc.code not in (401, 403):
                raise
            try:
                refreshed = refresh_minecraft_account(account)
            except Exception:
                refreshed = None
            if not refreshed:
                raise MinecraftSessionError(f"Session token rejected by Mojang HTTP {exc.code}")
            account = refreshed
            continue
        except MinecraftSessionError:
            raise
    if last_rate_limit:
        raise MinecraftSessionError("Mojang sessionserver rate limited join")
    raise MinecraftSessionError("Session join failed")

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
    sort_state = {}  # col -> bool

    def sort_by(col):
        reverse = sort_state.get(col, False)
        rows = [(column_key_funcs.get(col, str)(tree.set(iid, col)), iid) for iid in tree.get_children("")]
        rows.sort(reverse=reverse)
        for idx, (_, iid) in enumerate(rows):
            tree.move(iid, "", idx)
        sort_state[col] = not reverse

    for col in tree["columns"]:
        tree.heading(col, command=lambda c=col: sort_by(c))

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

            return {
                'ip': f"{host}:{port}",
                'players': players,
                'max_players': max_players,
                'motd': motd,
                'version': response.get('version', {}).get('name', 'N/A'),
                'protocol': response.get('version', {}).get('protocol', PROTOCOL_VERSION),
                'players_sample': players_sample,
                'cracked': cracked
            }
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

def get_server_status_info(host, port=25565, proxy=None):
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

        return proto, sample_names, sample_hint
    except Exception:
        return DEFAULT_STATUS_PROTOCOL, [], None
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass

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

def whitelist_login_probe(host, port=25565, account=None, protocol=None, proxy=None):
    if not account:
        return None, "No Minecraft account selected"
    # USERNAME:TOKEN imports may not include a profile UUID. Resolve the
    # profile before constructing Login Start; an empty selectedProfile is
    # rejected by the session server as HTTP 400.
    if not account.get("uuid") and account.get("access_token"):
        resolved, ok, detail = probe_account(account)
        if ok and resolved.get("uuid"):
            account.clear()
            account.update(resolved)
            upsert_mc_accounts([account], active_uuid=account.get("uuid"))
        else:
            return None, f"Token profile lookup failed: {detail}"
    if not account.get("uuid"):
        return None, "Minecraft profile UUID is missing; test the token first"
    if not _CRYPTO_AVAILABLE:
        return None, "cryptography package is not available"
    if protocol is None:
        protocol, _, _ = get_server_status_info(host, port, proxy=proxy)
    sock = None
    compression_threshold = -1
    encrypted = False
    try:
        sock = open_connection(host, port, proxy=proxy, timeout=6)
        sock.settimeout(2.5)
        handshake = (
            varint_encode(0) +
            varint_encode(protocol) +
            write_string(host) +
            struct.pack(">H", port) +
            varint_encode(2)
        )
        send_mc_packet(sock, handshake)
        send_mc_packet(sock, build_authenticated_login_start(account, protocol))

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
                server_id, pos = read_mc_string_from_bytes(buf, pos)
                public_key_bytes, pos = read_mc_byte_array_from_bytes(buf, pos)
                verify_token, pos = read_mc_byte_array_from_bytes(buf, pos)
                public_key = load_der_public_key(public_key_bytes, backend=default_backend())
                shared_secret = os.urandom(16)
                server_hash = minecraft_sha1_hexdigest(
                    server_id.encode("ascii", errors="ignore"),
                    shared_secret,
                    public_key_bytes
                )
                try:
                    account = ensure_minecraft_session_join(account, server_hash)
                except urllib.error.HTTPError as exc:
                    try:
                        detail = exc.read().decode("utf-8", errors="replace")[:180]
                    except Exception:
                        detail = ""
                    return None, f"Mojang join failed: HTTP {exc.code}" + (f": {detail}" if detail else "")
                except MinecraftSessionError as exc:
                    return None, f"Auth/session failed before server login ({exc})"
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
                    return True, f"WHITELISTED ({reason})"
                if "outdated client" in low or "outdated server" in low:
                    return None, f"Version mismatch ({reason})"
                if (
                    "multiplayer is disabled" in low or
                    "authentication" in low or
                    "invalid session" in low or
                    "verify username" in low or
                    "unverified_username" in low
                ):
                    return None, f"Auth/session rejected ({reason})"
                return False, f"Not Whitelisted ({reason})"

            if packet_id == 0x02:
                return False, "Not Whitelisted (login accepted)"

            if packet_id == 0x04:
                return False, "Not Whitelisted (login plugin request; no immediate whitelist kick)"

            if packet_id == 0x05:
                return False, "Not Whitelisted (entered configuration; no immediate whitelist kick)"

    except socket.timeout:
        return None, "Timed out during whitelist probe"
    except Exception as exc:
        return None, f"Whitelist probe error: {str(exc)[:80]}"
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass

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
    return whitelist_login_probe(host, port, account=account, protocol=protocol, proxy=proxy)

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
    if base == "Not Whitelisted" and detail.lower().startswith("not whitelisted"):
        detail = detail[len("Not Whitelisted"):].strip()
        if detail.startswith(":"):
            detail = detail[1:].strip()
        if detail.startswith("(") and detail.endswith(")"):
            detail = detail[1:-1].strip()
    if len(detail) > 90:
        detail = detail[:87] + "..."
    return f"{base}: {detail}"

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
            messagebox.showinfo("Whitelist Log", os.path.abspath(WHITELIST_LOG_FILE), parent=parent)
    except Exception as exc:
        if parent is not None:
            messagebox.showerror("Whitelist Log", f"Could not open log: {exc}", parent=parent)

def check_selected_whitelist(parent, tree):
    """Manually probe the currently selected result rows using the active token."""
    account = get_active_mc_account()
    if not account:
        messagebox.showinfo("Check Whitelist", "Select/probe an active Minecraft account first.", parent=parent)
        return
    selected = tree.selection()
    if not selected:
        messagebox.showinfo("Check Whitelist", "Select one or more server rows first.", parent=parent)
        return
    columns = list(tree["columns"])
    if "whitelist" not in columns:
        messagebox.showinfo("Check Whitelist", "This result view has no whitelist column.", parent=parent)
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

def run_whitelist_verifier_async(entries, account, callback, progress_cb=None):
    # Proxy mode: route through working proxies and rotate accounts in parallel.
    if _WHITELIST_USE_PROXIES:
        proxies = get_working_proxies()
        accounts = get_all_mc_accounts() or [a for a in [account] if a]
        if proxies and accounts:
            def adapted(entry, result, message, acc=None, proxy=None):
                callback(entry, result, message)
            run_bulk_whitelist_verifier_async(entries, accounts, proxies, adapted, progress_cb=progress_cb)
            return
    def worker():
        total = len(entries)
        completed = 0
        for entry in entries:
            try:
                result, message = _probe_whitelist_entry(entry, account)
            except Exception as exc:
                result, message = None, str(exc)
            log_whitelist_probe(entry, result, message, account=account)
            callback(entry, result, message)
            completed += 1
            if progress_cb:
                progress_cb(completed, total)
            if completed < total and WHITELIST_PROBE_DELAY > 0:
                time.sleep(WHITELIST_PROBE_DELAY)
    if entries:
        threading.Thread(target=worker, daemon=True).start()

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
    if not accounts or not entries:
        return
    total = len(entries)
    if workers is None or workers < 1:
        workers = max(1, len(working_proxies))
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

    tokens = []
    for line in target_text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        tokens.extend([part.strip() for part in re.split(r"[,;\s]+", line) if part.strip()])

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

def ask_reason_with_whitelist(parent, title="Reason", prompt="Why ignore? (optional)"):

    dlg = tk.Toplevel(parent)
    dlg.transient(parent)
    dlg.grab_set()
    dlg.title(title)

    # Make small, non-resizable and center over parent (best-effort)
    try:
        dlg.resizable(False, False)
    except Exception:
        pass

    frm = ttk.Frame(dlg, padding=(12, 10))
    frm.pack(fill="both", expand=True)

    ttk.Label(frm, text=prompt).pack(anchor="w", pady=(0,6))

    var = tk.StringVar()
    entry = ttk.Entry(frm, textvariable=var, width=60)
    entry.pack(fill="x", expand=True)
    entry.focus_set()

    btns = ttk.Frame(frm)
    btns.pack(fill="x", pady=(10,0))

    def _close_with(val):
        dlg.result = None if val is None else str(val)
        try:
            dlg.grab_release()
        except Exception:
            pass
        dlg.destroy()

    def _on_ok():
        _close_with(var.get().strip() if var.get().strip() else "")

    def _on_whitelist():
        # immediate accept with "White List"
        _close_with("White List")

    def _on_cancel():
        _close_with(None)

    # Buttons: OK, White List, Cancel
    ttk.Button(btns, text="OK", command=_on_ok).pack(side="left", padx=(0,6))
    ttk.Button(btns, text="White List", command=_on_whitelist).pack(side="left", padx=(0,6))
    ttk.Button(btns, text="Cancel", command=_on_cancel).pack(side="left")

    # Bind Enter / Escape keys
    dlg.bind("<Return>", lambda e: _on_ok())
    dlg.bind("<Escape>", lambda e: _on_cancel())

    # center over parent (best-effort)
    try:
        parent.update_idletasks()
        px = parent.winfo_rootx()
        py = parent.winfo_rooty()
        pw = parent.winfo_width()
        ph = parent.winfo_height()
        dlg.update_idletasks()
        w = dlg.winfo_reqwidth()
        h = dlg.winfo_reqheight()
        x = px + max(0, (pw - w) // 2)
        y = py + max(0, (ph - h) // 2)
        dlg.geometry(f"+{x}+{y}")
    except Exception:
        pass

    parent.wait_window(dlg)
    return getattr(dlg, "result", None)

# ========================================  

class _IconManager:
    def __init__(self):
        self._cache_bytes = {}        # ip -> png bytes or None
        self._cache_images = {}       # ip -> PhotoImage (or placeholder)
        self._executor = ThreadPoolExecutor(max_workers=max(1, ICON_THREADS))
        self._attached = set()
        self._placeholder_image = None

    def _ensure_tree_ready(self, tree: ttk.Treeview):
        # turn on the tree column to host images, center it, set width
        try:
            tree["show"] = "tree headings"
        except Exception:
            pass
        tree.heading("#0", text="ICON")
        tree.column("#0", width=ICON_SIZE + ICON_COL_EXTRA_PAD, stretch=False, anchor="center")

        # increase row height just for this tree
        sty = ttk.Style(tree)
        style_name = f"IconTreeview{str(id(tree))}"
        try:
            sty.configure(style_name, rowheight=max(ICON_SIZE + 8, 24))
            tree.configure(style=style_name)
        except Exception:
            pass

        # storage for PhotoImage refs so they don't get GC'd
        if not hasattr(tree, "_icon_images"):
            tree._icon_images = {}

    def attach_to_tree(self, tree: ttk.Treeview):
        if not ICON_ENABLED:
            return
        if tree in self._attached:
            return
        self._ensure_tree_ready(tree)

        # monkeypatch insert to auto-register rows
        if not hasattr(tree, "_orig_insert"):
            tree._orig_insert = tree.insert

            def _insert_wrapper(parent, index, iid=None, **kw):
                values = kw.get("values")
                new_iid = tree._orig_insert(parent, index, iid=iid, **kw)
                if values and len(values) > 0:
                    ip = values[0]
                    if is_valid_ip_port(ip):
                        self._fetch_and_set_icon(tree, new_iid, ip)
                return new_iid

            tree.insert = _insert_wrapper  # type: ignore

        self._attached.add(tree)

    def _fetch_and_set_icon(self, tree: ttk.Treeview, iid: str, ip: str):
        # if already cached, set immediately on UI thread
        if ip in self._cache_bytes:
            data = self._cache_bytes[ip]
            self._apply_icon_to_item(tree, iid, ip, data)
            return

        # fetch in background
        def work():
            data = fetch_server_favicon_bytes(ip)
            # cache whether None or bytes to avoid repeat lookups
            if len(self._cache_bytes) >= MAX_ICON_CACHE_ENTRIES and ip not in self._cache_bytes:
                self._cache_bytes.pop(next(iter(self._cache_bytes)), None)
            self._cache_bytes[ip] = data
            try:
                tree.after(0, lambda: self._apply_icon_to_item(tree, iid, ip, data))
            except Exception:
                pass

        self._executor.submit(work)

    def _apply_icon_to_item(self, tree: ttk.Treeview, iid: str, ip: str, png_bytes: bytes | None):
        try:
            photo = self._photo_for_ip(ip, png_bytes)
            # keep ref
            if len(tree._icon_images) >= MAX_ICON_CACHE_ENTRIES and iid not in tree._icon_images:
                tree._icon_images.pop(next(iter(tree._icon_images)), None)
            tree._icon_images[iid] = photo
            tree.item(iid, image=photo, text="")
        except Exception:
            # ignore per-row failures silently
            pass

    def _photo_for_ip(self, ip: str, png_bytes: bytes | None):
        if ip in self._cache_images:
            return self._cache_images[ip]
        photo = self._make_photo(png_bytes)
        if photo is None:
            photo = self._placeholder_photo()
        if len(self._cache_images) >= MAX_ICON_CACHE_ENTRIES and ip not in self._cache_images:
            self._cache_images.pop(next(iter(self._cache_images)), None)
        self._cache_images[ip] = photo
        return photo

    def _make_photo(self, png_bytes):
        if not png_bytes:
            return None
        if _PIL_AVAILABLE:
            try:
                im = Image.open(io.BytesIO(png_bytes)).convert("RGBA")
                im = im.resize((ICON_SIZE, ICON_SIZE), Image.LANCZOS)
                return ImageTk.PhotoImage(im)
            except Exception:
                return None
        # fallback: try raw PhotoImage (cannot upscale; can downscale via subsample)
        try:
            b64 = base64.b64encode(png_bytes)
            img = tk.PhotoImage(data=b64)
            w = img.width()
            if w > 0 and ICON_SIZE < w:
                factor = max(1, round(w / ICON_SIZE))
                img = img.subsample(factor)
            return img
        except Exception:
            return None

    def _placeholder_photo(self):
        if self._placeholder_image is not None:
            return self._placeholder_image
        # simple solid square to reserve space
        img = tk.PhotoImage(width=ICON_SIZE, height=ICON_SIZE)
        img.put(ICON_PLACEHOLDER, to=(0, 0, ICON_SIZE, ICON_SIZE))
        self._placeholder_image = img
        return img


# singleton accessor
_ICON_MANAGER_SINGLETON = None
def _get_icon_manager():
    global _ICON_MANAGER_SINGLETON
    if _ICON_MANAGER_SINGLETON is None:
        _ICON_MANAGER_SINGLETON = _IconManager()
    return _ICON_MANAGER_SINGLETON


# ==================== GUI ====================

class AccountTab(ttk.Frame):
    def __init__(self, master):
        super().__init__(master)
        self._probe_results = {}   # account key -> (ok, message)
        self._row_keys = {}        # tree iid -> account key
        self._build_ui()
        self.refresh()

    def _build_ui(self):
        bar = ttk.Frame(self)
        bar.pack(fill="x", padx=8, pady=8)
        ttk.Button(bar, text="Import Prism Accounts", command=self.import_prism).pack(side="left", padx=4)
        ttk.Button(bar, text="Import Tokens", command=self.import_tokens).pack(side="left", padx=4)
        ttk.Button(bar, text="Add Manual Token", command=self.add_manual).pack(side="left", padx=4)
        ttk.Button(bar, text="Set Active", command=self.set_active).pack(side="left", padx=4)
        ttk.Button(bar, text="Test Selected", command=self.test_selected).pack(side="left", padx=4)
        ttk.Button(bar, text="Probe All", command=self.probe_accounts).pack(side="left", padx=4)
        ttk.Button(bar, text="Remove", command=self.remove_selected).pack(side="left", padx=4)
        ttk.Button(bar, text="Remove Failed", command=self.remove_failed).pack(side="left", padx=4)
        ttk.Button(bar, text="Open Whitelist Log", command=lambda: open_whitelist_log_file(self)).pack(side="left", padx=12)

        frame = ttk.Frame(self)
        frame.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        cols = ("active", "name", "uuid", "source", "token_source", "status")
        self.tree = ttk.Treeview(frame, columns=cols, show="headings", height=16, selectmode="extended")
        widths = {"active": 70, "name": 170, "uuid": 250, "source": 130, "token_source": 150, "status": 210}
        for col in cols:
            self.tree.heading(col, text=col.upper())
            self.tree.column(col, width=widths.get(col, 120), anchor="w")
        self.tree.pack(side="left", fill="both", expand=True)
        sb = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
        sb.pack(side="left", fill="y")
        self.tree.config(yscrollcommand=sb.set)

        self.status = tk.StringVar(value="Ready.")
        ttk.Label(self, textvariable=self.status, anchor="w").pack(fill="x", padx=8, pady=(0,8))

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
            self.status.set(f"{count} account(s). Active: {active.get('name')}.")
        else:
            self.status.set(f"{count} account(s). No active account.")

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
            picked = filedialog.askopenfilename(
                title="Pick Prism accounts.json",
                filetypes=[("accounts.json", "accounts.json"), ("JSON", "*.json"), ("All files", "*.*")]
            )
            if not picked:
                return
            path = picked
        try:
            imported = import_prism_accounts(path)
            self.refresh()
            self.status.set(f"Imported {len(imported)} Prism account(s).")
        except Exception as exc:
            messagebox.showerror("Accounts", f"Import failed: {exc}")
            self.status.set(f"Import failed: {exc}")

    def add_manual(self):
        name = simpledialog.askstring("Minecraft Account", "Minecraft username:", parent=self)
        if not name:
            return
        profile_id = simpledialog.askstring("Minecraft Account", "Profile UUID (with or without dashes):", parent=self)
        if not profile_id:
            return
        access_token = simpledialog.askstring("Minecraft Account", "Session/access token:", parent=self, show="*")
        if not access_token:
            return
        refresh_token = simpledialog.askstring("Minecraft Account", "Refresh token (optional):", parent=self, show="*") or ""
        account = _normalize_mc_account(name, profile_id, access_token, refresh_token)
        account["source"] = "manual"
        account["token_source"] = "manual"
        if refresh_token:
            account["msa_client_id"] = simpledialog.askstring(
                "Minecraft Account",
                "MSA client id (optional; Prism fills this automatically):",
                parent=self
            ) or ""
        upsert_mc_accounts([account], active_uuid=account.get("uuid"))
        self.refresh()

    def import_tokens(self):
        """Import access/refresh tokens pasted as text (JWT eyJ... or M.C... Artifacts)."""
        dialog = tk.Toplevel(self)
        dialog.title("Import Tokens")
        dialog.geometry("560x400")
        dialog.transient(self)
        ttk.Label(
            dialog,
            text=(
                "Paste tokens, one per line.\n"
                "  eyJ...            -> Minecraft access token\n"
                "  name:M.C...       -> MSA refresh token (Artifacts)\n"
                "  M.C...            -> MSA refresh token (no name)"
            ),
            anchor="w",
            justify="left"
        ).pack(fill="x", padx=10, pady=8)
        text = tk.Text(dialog, height=14)
        text.pack(fill="both", expand=True, padx=10, pady=(0, 8))
        row = ttk.Frame(dialog)
        row.pack(fill="x", padx=10, pady=(0, 10))

        def do_import():
            imported = import_tokens_from_text(text.get("1.0", "end"))
            if not imported:
                messagebox.showinfo("Import Tokens", "No valid tokens found.", parent=dialog)
                return
            upsert_mc_accounts(imported)
            dialog.destroy()
            self.refresh()
            self.status.set(f"Imported {len(imported)} token(s). Probe them to fetch names/UUIDs.")

        ttk.Button(row, text="Import", command=do_import).pack(side="left", padx=4)
        ttk.Button(row, text="Cancel", command=dialog.destroy).pack(side="left", padx=4)

    def probe_accounts(self):
        """Test/enrich all stored accounts (refresh M.C... tokens, verify JWT tokens)."""
        data = _load_mc_accounts()
        pairs = [(a, _account_key(a)) for a in data.get("accounts", []) if a.get("access_token") or a.get("refresh_token")]
        if not pairs:
            messagebox.showinfo("Accounts", "No accounts to probe.")
            return
        self.status.set(f"Probing {len(pairs)} account(s)...")
        idx = [0]

        def on_update(acc, ok, msg):
            key = pairs[idx[0]][1] if idx[0] < len(pairs) else _account_key(acc)
            idx[0] += 1
            self.after(0, lambda a=acc, o=ok, m=msg, k=key: self._finish_probe(k, a, o, m))

        def on_progress(done, total):
            if done >= total:
                self.after(0, lambda: self.status.set(f"Probe complete: {total} account(s) tested."))

        probe_accounts_async([a for a, _ in pairs], on_update, progress_cb=on_progress)

    def _finish_probe(self, key, acc, ok, msg):
        self._probe_results[key] = (ok, msg)
        if acc.get("uuid"):
            self._probe_results[acc["uuid"]] = (ok, msg)
        if acc.get("name") and acc["name"] != key:
            self._probe_results[acc["name"]] = (ok, msg)
        self.refresh()
        self.status.set(f"Test {acc.get('name') or key}: {'OK' if ok else 'FAILED'} ({msg})")

    def test_selected(self):
        keys = self._selected_keys()
        if not keys:
            messagebox.showinfo("Accounts", "Select one or more accounts first.")
            return
        data = _load_mc_accounts()
        by_key = {_account_key(a): a for a in data.get("accounts", [])}
        accounts = [a for k in keys if k in by_key for a in [by_key[k]]]
        accounts = [a for a in accounts if a.get("access_token") or a.get("refresh_token")]
        if not accounts:
            messagebox.showinfo("Accounts", "No selected account has a token to test.")
            return
        self.status.set(f"Testing {len(accounts)} account(s)...")
        def worker():
            for a in accounts:
                acc, ok, msg = probe_account(a)
                k = _account_key(a)
                self.after(0, lambda a=acc, o=ok, m=msg, kk=k: self._finish_probe(kk, a, o, m))
        threading.Thread(target=worker, daemon=True).start()

    def set_active(self):
        key = self._selected_key()
        if not key:
            messagebox.showinfo("Accounts", "Select an account first.")
            return
        data = _load_mc_accounts()
        account = next((a for a in data.get("accounts", []) if _account_key(a) == key), None)
        if not account or not account.get("uuid"):
            messagebox.showinfo("Accounts", "This account has no UUID yet. Probe it first to fetch its UUID.")
            return
        data["active_uuid"] = account["uuid"]
        _save_mc_accounts(data)
        self.refresh()

    def remove_selected(self):
        keys = self._selected_keys()
        if not keys:
            messagebox.showinfo("Accounts", "Select one or more accounts first.")
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
        self.status.set(f"Removed {removed} account(s).")

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
            messagebox.showinfo("Accounts", "No failed accounts to remove.")
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
        self.status.set(f"Removed {len(removed)} failed account(s).")


class NetworkScanTab(ttk.Frame):
    def __init__(self, master):
        super().__init__(master)
        self.scan_rows = []
        self._scan_row_map = {}
        self._current_scan_ip = None
        self._whitelist_job_id = 0
        self.version_filter_var = tk.StringVar(value="All versions")
        self.pre_version_var = tk.StringVar(value="")
        self._build_ui()

    def _build_ui(self):
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        content = ttk.Frame(self)
        content.grid(row=0, column=0, sticky="nsew")
        top = ttk.Frame(content)
        top.pack(fill="x", padx=8, pady=8)

        ttk.Label(top, text="Targets (IP/CIDR/range/ASN, e.g. AS13335):").grid(row=0, column=0, sticky="w")
        self.targets_text = tk.Text(top, height=4, width=70)
        self.targets_text.grid(row=1, column=0, rowspan=4, sticky="ew", padx=(0, 8))
        self.targets_text.insert("1.0", "127.0.0.1/32")
        top.grid_columnconfigure(0, weight=1)

        ttk.Label(top, text="Ports:").grid(row=0, column=1, sticky="w")
        self.ports_var = tk.StringVar(value=NETWORK_SCAN_DEFAULT_PORTS)
        ttk.Entry(top, textvariable=self.ports_var, width=18).grid(row=1, column=1, sticky="ew")

        ttk.Label(top, text="Max hosts:").grid(row=2, column=1, sticky="w", pady=(6,0))
        self.max_hosts_var = tk.StringVar(value=str(NETWORK_SCAN_MAX_HOSTS))
        ttk.Entry(top, textvariable=self.max_hosts_var, width=18).grid(row=3, column=1, sticky="ew")

        controls = ttk.Frame(content)
        controls.pack(fill="x", padx=8, pady=(0,8))
        ttk.Button(controls, text="Scan Targets", command=self.scan_targets).pack(side="left", padx=4)
        ttk.Button(controls, text="Copy IP(s)", command=self.copy_selected).pack(side="left", padx=4)
        ttk.Button(controls, text="Add to Ignore", command=self.ignore_selected).pack(side="left", padx=4)
        ttk.Button(controls, text="Add to Saved", command=self.save_selected).pack(side="left", padx=4)
        ttk.Button(controls, text="Add to Monitor", command=self.add_selected_to_monitor).pack(side="left", padx=4)
        ttk.Label(controls, text="Pre version:").pack(side="left", padx=(14,4))
        ttk.Entry(controls, textvariable=self.pre_version_var, width=16).pack(side="left")
        ttk.Label(controls, text="Found version:").pack(side="left", padx=(14,4))
        self.version_filter_combo = ttk.Combobox(
            controls,
            textvariable=self.version_filter_var,
            values=["All versions"],
            width=18
        )
        self.version_filter_combo.pack(side="left")
        self.version_filter_combo.bind("<<ComboboxSelected>>", lambda _e: self.refresh_scan_tree())
        self.version_filter_combo.bind("<KeyRelease>", lambda _e: self.refresh_scan_tree())
        self.only_players_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(controls, text="Only players > 0", variable=self.only_players_var).pack(side="left", padx=(14, 4))
        self.check_whitelist_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(controls, text="Check whitelist", variable=self.check_whitelist_var).pack(side="left", padx=4)

        frame = ttk.Frame(content)
        frame.pack(fill="both", expand=True, padx=8, pady=(0,8))
        cols = ("ip", "motd", "players", "version", "whitelist", "active_players")
        self.scan_tree = ttk.Treeview(frame, columns=cols, show="headings", height=18, selectmode="extended")
        for col in cols:
            self.scan_tree.heading(col, text=col.upper())
            if col in ("motd", "active_players"):
                width = 260
            elif col == "whitelist":
                width = 220
            elif col in ("players", "version"):
                width = 120
            else:
                width = 170
            self.scan_tree.column(col, width=width, anchor="w")
        self.scan_tree.pack(side="left", fill="both", expand=True)
        sb = ttk.Scrollbar(frame, orient="vertical", command=self.scan_tree.yview)
        sb.pack(side="left", fill="y")
        self.scan_tree.config(yscrollcommand=sb.set)
        ttk.Button(content, text="Check Whitelist", command=lambda: check_selected_whitelist(self, self.scan_tree)).pack(anchor="w", padx=8, pady=(0,8))
        make_tree_sortable(self.scan_tree, {
            "ip": _ip_key,
            "motd": lambda v: str(v).lower(),
            "players": _players_key,
            "version": _version_key,
            "whitelist": lambda v: str(v).lower(),
            "active_players": lambda v: str(v).lower()
        })
        _get_icon_manager().attach_to_tree(self.scan_tree)

        self.status = tk.StringVar(value="Ready.")
        ttk.Label(self, textvariable=self.status, anchor="w").grid(row=1, column=0, sticky="ew", padx=8, pady=(0,8))

    def set_status(self, msg):
        self.status.set(msg)

    def _selected_rows(self):
        rows = []
        for iid in self.scan_tree.selection():
            vals = self.scan_tree.item(iid, "values")
            if vals:
                rows.append(vals)
        return rows

    def _update_version_filter_choices(self, rows):
        choices = collect_version_options([(r[0], r[1], r[2], r[3]) for r in rows])
        current = self.version_filter_var.get() or "All versions"
        self.version_filter_combo["values"] = choices
        if current not in choices:
            current = "All versions"
        self.version_filter_var.set(current)

    def refresh_scan_tree(self):
        self.scan_tree.delete(*self.scan_tree.get_children())
        self._scan_row_map = {}
        for row in self.scan_rows:
            if version_filter_allows(row[3], self.version_filter_var.get()):
                iid = self.scan_tree.insert("", "end", values=row)
                self._scan_row_map[row[0]] = iid

    def _update_scan_row_whitelist(self, ip, text):
        iid = self._scan_row_map.get(ip)
        if not iid:
            return
        vals = list(self.scan_tree.item(iid, "values"))
        if len(vals) >= 5:
            vals[4] = text
            self.scan_tree.item(iid, values=vals)
        for idx, row in enumerate(self.scan_rows):
            if row and row[0] == ip:
                row = list(row)
                row[4] = text
                self.scan_rows[idx] = tuple(row)
                break

    def scan_targets(self):
        try:
            max_hosts = int(self.max_hosts_var.get().strip() or NETWORK_SCAN_MAX_HOSTS)
        except ValueError:
            max_hosts = NETWORK_SCAN_MAX_HOSTS
        max_hosts = max(1, min(max_hosts, 65536))
        ports = parse_ports(self.ports_var.get())
        targets_raw = self.targets_text.get("1.0", "end")
        self.set_status("Expanding targets...")

        def work():
            try:
                targets = expand_scan_targets(targets_raw, ports, max_hosts=max_hosts)
                if not targets:
                    self.after(0, lambda: self.set_status("No valid targets to scan."))
                    return
                self.scan_rows = []
                self._scan_row_map = {}
                self.after(0, lambda: self.scan_tree.delete(*self.scan_tree.get_children()))
                check_whitelist = self.check_whitelist_var.get()
                account = get_active_mc_account() if check_whitelist else None
                if check_whitelist and not account:
                    self.after(0, lambda: self.set_status("Whitelist check canceled: no account selected."))
                    return
                if check_whitelist:
                    self._whitelist_job_id += 1
                whitelist_job = self._whitelist_job_id
                whitelist_entries = []
                whitelist_seen = set()
                lock = threading.Lock()
                pre_version = self.pre_version_var.get().strip()

                def on_start(ip):
                    self._current_scan_ip = ip

                def on_result(r, line):
                    if not r:
                        return
                    if self.only_players_var.get() and r.get("players", 0) <= 0:
                        return
                    if pre_version and not version_filter_allows(r.get("version", ""), pre_version):
                        return
                    row = (
                        r["ip"],
                        r["motd"],
                        f"{r['players']}/{r['max_players']}",
                        r["version"],
                        "Queued" if check_whitelist else "-",
                        format_player_list(r.get("players_sample"))
                    )
                    self.scan_rows.append(row)
                    def add_row(row=row):
                        if not version_filter_allows(row[3], self.version_filter_var.get()):
                            return
                        iid = self.scan_tree.insert("", "end", values=row)
                        self._scan_row_map[row[0]] = iid
                    self.after(0, add_row)
                    if check_whitelist:
                        with lock:
                            if r["ip"] not in whitelist_seen:
                                whitelist_seen.add(r["ip"])
                                whitelist_entries.append(r)

                def on_progress(done, total):
                    self.after(0, lambda d=done, t=total:
                               self.set_status(f"Network scan: {d}/{t}"))

                results, _ = scan_servers_gui(
                    targets,
                    on_start=on_start,
                    on_result=on_result,
                    on_progress=on_progress
                )
                self.after(0, lambda rows=list(self.scan_rows): self._update_version_filter_choices(rows))
                self.after(0, lambda: self.set_status(f"Scan complete. Responded: {len(results)}."))

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
            messagebox.showinfo("Network Scan", "Select one or more rows.")
            return
        self.clipboard_clear()
        self.clipboard_append("\n".join(row[0] for row in rows))
        self.set_status(f"Copied {len(rows)} IP(s).")

    def ignore_selected(self):
        rows = self._selected_rows()
        if not rows:
            messagebox.showinfo("Network Scan", "Select one or more rows.")
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
            messagebox.showinfo("Network Scan", "Select one or more rows.")
            return
        reason = simpledialog.askstring("Reason", "Why save? (optional)")
        for row in rows:
            add_to_saved(row[0], reason or "")
        self.set_status(f"Added {len(rows)} to saved.txt.")

    def add_selected_to_monitor(self):
        rows = self._selected_rows()
        if not rows:
            messagebox.showinfo("Network Scan", "Select one or more rows.")
            return
        added, invalid, duplicates = add_ips_to_monitor_list([row[0] for row in rows])
        self.set_status(format_monitor_feedback(added, invalid, duplicates))

class ProxyTab(ttk.Frame):
    """
    Proxy manager + bulk whitelist scanner.
      - Paste proxies as 'ip:port' (HTTP) or 'ip:port:user:pass' (SOCKS5).
      - Test each proxy, save the list to proxies.json.
      - Run a bulk whitelist scan that cycles accounts AND proxies in parallel.
    """
    def __init__(self, master):
        super().__init__(master)
        self.proxies = []
        self.servers = []          # list[str] ip:port
        self._bulk_job = 0
        self._current_bulk = None
        self._build_ui()
        self.refresh()

    def _build_ui(self):
        bar = ttk.Frame(self)
        bar.pack(fill="x", padx=8, pady=8)
        ttk.Button(bar, text="Import from Text", command=self.import_text).pack(side="left", padx=4)
        ttk.Button(bar, text="Import from File", command=self.import_file).pack(side="left", padx=4)
        ttk.Button(bar, text="Save", command=self.save).pack(side="left", padx=4)
        ttk.Button(bar, text="Test All", command=self.test_all).pack(side="left", padx=4)
        ttk.Button(bar, text="Test Selected", command=self.test_selected).pack(side="left", padx=4)
        ttk.Button(bar, text="Clear", command=self.clear).pack(side="left", padx=4)
        ttk.Button(bar, text="Reload", command=self.refresh).pack(side="left", padx=4)
        self.use_proxy_mode_var = tk.BooleanVar(value=whitelist_proxy_mode())
        ttk.Checkbutton(
            bar,
            text="Use proxies for all whitelist scans",
            variable=self.use_proxy_mode_var,
            command=self._toggle_proxy_mode
        ).pack(side="left", padx=(16, 4))

        paste_frame = ttk.Frame(self)
        paste_frame.pack(fill="x", padx=8, pady=(0, 8))
        ttk.Label(paste_frame, text="Paste proxies, one per line. 'ip:port' = HTTP, 'ip:port:user:pass' = SOCKS5:").pack(anchor="w")
        self.paste_text = tk.Text(paste_frame, height=5)
        self.paste_text.pack(fill="x")

        frame = ttk.Frame(self)
        frame.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        cols = ("host", "port", "type", "user", "status", "message")
        self.tree = ttk.Treeview(frame, columns=cols, show="headings", height=9, selectmode="extended")
        widths = {"host": 150, "port": 60, "type": 65, "user": 110, "status": 80, "message": 240}
        for col in cols:
            self.tree.heading(col, text=col.upper())
            self.tree.column(col, width=widths.get(col, 120), anchor="w")
        self.tree.pack(side="left", fill="both", expand=True)
        sb = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
        sb.pack(side="left", fill="y")
        self.tree.config(yscrollcommand=sb.set)

        # --- Bulk whitelist scan ---
        scan = ttk.LabelFrame(self, text="Bulk Whitelist Scan  (cycles accounts + proxies in parallel)")
        scan.pack(fill="x", padx=8, pady=(0, 8))

        row = ttk.Frame(scan)
        row.pack(fill="x", padx=8, pady=6)
        ttk.Label(row, text="Server list (.txt):").pack(side="left")
        self.server_file_var = tk.StringVar()
        ttk.Entry(row, textvariable=self.server_file_var, width=44).pack(side="left", padx=4)
        ttk.Button(row, text="Browse", command=self._pick_server_file).pack(side="left", padx=4)
        ttk.Button(row, text="Load", command=self._load_server_list).pack(side="left", padx=4)
        ttk.Label(row, text="  Loaded: ").pack(side="left")
        self.server_count_var = tk.StringVar(value="0")
        ttk.Label(row, textvariable=self.server_count_var, width=6).pack(side="left")

        row2 = ttk.Frame(scan)
        row2.pack(fill="x", padx=8, pady=(0, 6))
        ttk.Label(row2, text="Workers (0 = auto / per working proxy):").pack(side="left")
        self.workers_var = tk.StringVar(value="0")
        ttk.Entry(row2, textvariable=self.workers_var, width=6).pack(side="left", padx=4)
        self.use_all_accounts_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(row2, text="Use all accounts", variable=self.use_all_accounts_var).pack(side="left", padx=4)
        ttk.Button(row2, text="Start Scan", command=self.start_bulk_scan).pack(side="left", padx=8)
        ttk.Button(row2, text="Stop", command=self.stop_bulk_scan).pack(side="left", padx=4)
        ttk.Button(row2, text="Export Results", command=self.export_bulk_results).pack(side="left", padx=4)

        row3 = ttk.Frame(scan)
        row3.pack(fill="x", padx=8, pady=(0, 6))
        ttk.Label(row3, text="Initial scan via:").pack(side="left")
        self.initial_proxy_var = tk.StringVar(value="realip")
        ttk.Radiobutton(row3, text="My IP", variable=self.initial_proxy_var, value="realip").pack(side="left", padx=(8, 2))
        ttk.Radiobutton(row3, text="Single proxy", variable=self.initial_proxy_var, value="single").pack(side="left", padx=2)
        self.initial_proxy_choice_var = tk.StringVar()
        self.initial_proxy_combo = ttk.Combobox(row3, textvariable=self.initial_proxy_choice_var, state="readonly", width=26)
        self.initial_proxy_combo.pack(side="left", padx=4)
        ttk.Label(row3, text="  (status scan finds live servers, then whitelist scan uses the proxies)").pack(side="left")

        self.scan_status_var = tk.StringVar(value="Load a server list to begin.")
        ttk.Label(scan, textvariable=self.scan_status_var, anchor="w").pack(fill="x", padx=8, pady=(0, 6))

        res_frame = ttk.Frame(scan)
        res_frame.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        self.res_tree = ttk.Treeview(
            res_frame,
            columns=("ip", "result", "detail", "account", "proxy"),
            show="headings",
            height=8,
            selectmode="extended"
        )
        for c, w in (("ip", 180), ("result", 140), ("detail", 300), ("account", 130), ("proxy", 150)):
            self.res_tree.heading(c, text=c.upper())
            self.res_tree.column(c, width=w, anchor="w")
        self.res_tree.pack(side="left", fill="both", expand=True)
        rsb = ttk.Scrollbar(res_frame, orient="vertical", command=self.res_tree.yview)
        rsb.pack(side="left", fill="y")
        self.res_tree.config(yscrollcommand=rsb.set)

        self.status = tk.StringVar(value="Ready.")
        ttk.Label(self, textvariable=self.status, anchor="w").pack(fill="x", padx=8, pady=(0, 8))

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
        self.status.set(f"{len(self.proxies)} proxy(ies) loaded. {working} working.")
        choices = [proxy_display(p) for p in self.proxies]
        self.initial_proxy_combo["values"] = choices
        if choices and not self.initial_proxy_choice_var.get():
            self.initial_proxy_choice_var.set(choices[0])

    def _toggle_proxy_mode(self):
        enabled = self.use_proxy_mode_var.get()
        set_whitelist_proxy_mode(enabled)
        if enabled:
            self.status.set("Proxy mode ON: all whitelist scans cycle proxies + all accounts.")
        else:
            self.status.set("Proxy mode OFF: whitelist scans use a single account directly.")

    def import_text(self):
        text = self.paste_text.get("1.0", "end")
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
        self.status.set(f"Imported {added} new proxy(ies).")
        self.paste_text.delete("1.0", "end")

    def import_file(self):
        path = filedialog.askopenfilename(
            title="Import proxies",
            filetypes=[("Text", "*.txt"), ("All files", "*.*")]
        )
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read()
        except Exception as exc:
            messagebox.showerror("Proxies", f"Could not read file: {exc}")
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
        self.status.set(f"Imported {added} new proxy(ies) from file.")

    def save(self):
        save_proxies(self.proxies)
        self.status.set("Proxies saved to proxies.json.")

    def clear(self):
        self.proxies = []
        save_proxies(self.proxies)
        self.refresh()

    def test_all(self):
        if not self.proxies:
            messagebox.showinfo("Proxies", "No proxies loaded.")
            return
        self.status.set(f"Testing {len(self.proxies)} proxy(ies) in parallel...")
        def on_progress(done, total):
            if done >= total:
                self.after(150, self.refresh)
                self.after(0, lambda d=done: self.status.set(f"Proxy test complete: {d}/{total} tested."))
            else:
                self.after(0, lambda d=done, t=total: self.status.set(f"Testing proxies: {d}/{t}"))
        probe_proxies_async(self.proxies, lambda p, ok, msg: None, progress_cb=on_progress)

    def test_selected(self):
        selected = set(self.tree.selection())
        if not selected:
            messagebox.showinfo("Proxies", "Select one or more proxies first.")
            return
        targets = [p for iid, p in zip(self.tree.get_children(), self.proxies) if iid in selected]
        if not targets:
            return
        self.status.set(f"Testing {len(targets)} selected proxy(ies) in parallel...")
        def on_progress(done, total):
            if done >= total:
                self.after(150, self.refresh)
                self.after(0, lambda d=done: self.status.set(f"Selected proxy test complete: {d}/{total} tested."))
            else:
                self.after(0, lambda d=done, t=total: self.status.set(f"Testing selected proxies: {d}/{t}"))
        probe_proxies_async(targets, lambda p, ok, msg: None, progress_cb=on_progress)

    # ---- bulk whitelist scan ----
    def _pick_server_file(self):
        path = filedialog.askopenfilename(
            title="Pick server list",
            filetypes=[("Text", "*.txt"), ("All files", "*.*")]
        )
        if path:
            self.server_file_var.set(path)
            self._load_server_list()

    def _load_server_list(self):
        path = self.server_file_var.get().strip()
        if not path:
            messagebox.showinfo("Bulk Whitelist", "Pick a server list file first.")
            return
        try:
            self.servers = read_servers(path)
        except Exception as exc:
            messagebox.showerror("Bulk Whitelist", f"Could not read server list: {exc}")
            return
        self.server_count_var.set(str(len(self.servers)))
        self.scan_status_var.set(f"Loaded {len(self.servers)} server(s) from {os.path.basename(path)}.")

    def start_bulk_scan(self):
        if not self.servers:
            messagebox.showinfo("Bulk Whitelist", "Load a server list first.")
            return
        # Use all proxies that aren't known-dead. No need to pre-test the list —
        # dead proxies simply fail per-probe and are skipped as workers.
        proxies = [p for p in self.proxies if p.get("working") is not False]
        if not proxies:
            messagebox.showinfo("Bulk Whitelist", "No proxies loaded. Add some in the Proxies tab first.")
            return
        accounts = get_all_mc_accounts() if self.use_all_accounts_var.get() else [a for a in [get_active_mc_account()] if a]
        if not accounts:
            data = _load_mc_accounts()
            has_refresh = any(a.get("refresh_token") for a in data.get("accounts", []))
            hint = " Use 'Probe Accounts' in the Accounts tab first to fetch their tokens." if has_refresh else ""
            messagebox.showinfo("Bulk Whitelist", "No accounts with usable tokens." + hint)
            return
        try:
            workers = int(self.workers_var.get().strip() or "0")
        except ValueError:
            workers = 0
        job = self._bulk_job + 1
        self._bulk_job = job
        self.res_tree.delete(*self.res_tree.get_children())
        self._current_bulk = {"job": job, "accounts": accounts, "proxies": proxies, "workers": workers}

        # Stage 1: initial status scan (real IP, or optionally a single proxy) to
        # find live hosts before spending proxies + account auth on whitelist probes.
        initial_proxy = None
        if self.initial_proxy_var.get() == "single":
            chosen = self.initial_proxy_choice_var.get()
            for p in proxies:
                if proxy_display(p) == chosen:
                    initial_proxy = p
                    break
        via = proxy_display(initial_proxy) if initial_proxy else "your IP"
        self.scan_status_var.set(f"Initial scan of {len(self.servers)} server(s) via {via}...")

        live = []
        live_lock = threading.Lock()

        def on_init_result(server, result):
            if job != self._bulk_job:
                return
            if result:
                with live_lock:
                    live.append({"ip": result["ip"], "protocol": result.get("protocol")})

        def on_init_progress(done, total):
            if job != self._bulk_job:
                return
            if done >= total:
                self.after(0, lambda: self._start_whitelist_stage(job, list(live)))
            else:
                self.after(0, lambda d=done, t=total, n=len(live): self.scan_status_var.set(
                    f"Initial scan: {d}/{t} (found {n} live)..."))

        run_status_scan_async(self.servers, on_init_result, progress_cb=on_init_progress, proxy=initial_proxy)

    def _start_whitelist_stage(self, job, entries):
        """Stage 2: run the parallel whitelist scan only on live servers."""
        if job != self._bulk_job:
            return
        if not entries:
            self.scan_status_var.set("Initial scan found no live servers.")
            return
        bulk = self._current_bulk
        accounts = bulk["accounts"]
        proxies = bulk["proxies"]
        workers = bulk["workers"]
        self.scan_status_var.set(
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
                self.after(0, lambda: self.scan_status_var.set(
                    f"Bulk whitelist scan complete: {done}/{total} live servers. Export below."
                ))
            else:
                self.after(0, lambda d=done, t=total: self.scan_status_var.set(
                    f"Whitelist scan: {d}/{t} of {len(entries)} live servers"))

        run_bulk_whitelist_verifier_async(entries, accounts, proxies, on_update, progress_cb=on_progress, workers=workers)

    def stop_bulk_scan(self):
        self._bulk_job += 1
        self.scan_status_var.set("Bulk scan stopped.")

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
            messagebox.showinfo("Bulk Whitelist", "No results to export yet.")
            return
        path = filedialog.asksaveasfilename(
            title="Export bulk whitelist results",
            defaultextension=".txt",
            initialfile="bulk_whitelist_results.txt"
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write("# Whitelisted\n")
                f.write("\n".join(whitelisted) + "\n")
                f.write("# Not Whitelisted\n")
                f.write("\n".join(not_whitelisted) + "\n")
            self.scan_status_var.set(f"Exported {len(whitelisted)} whitelisted / {len(not_whitelisted)} not-whitelisted.")
        except Exception as exc:
            messagebox.showerror("Bulk Whitelist", f"Export failed: {exc}")

class FullAppGUI(tk.Tk):  #
    def __init__(self):
        super().__init__()
        self.title("Minecraft Server Scanner — GUI")
        self.geometry("1100x760")  # slightly taller
        self.create_widgets()

    def create_widgets(self):
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True)

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

        nb.add(self.shodan_tab, text="Shodan")
        nb.add(self.network_tab, text="Network Scan")
        nb.add(self.json_tab, text="JSON Search")
        nb.add(self.servers_tab, text="Servers")
        nb.add(self.import_tab, text="Export To MC")
        nb.add(self.saved_tab, text="Saved List")  
        nb.add(self.ignore_tab, text="Ignore List")
        nb.add(self.iplog_tab, text="IP Log")     
        nb.add(self.user_log_tab, text="User Log")
        nb.add(self.account_tab, text="Accounts")
        nb.add(self.proxy_tab, text="Proxies")
        nb.add(self.monitor_tab, text="Server Monitor")

        USER_LOG_MANAGER.attach_tab(self.user_log_tab)

# ---- Servers Tab ----
class ServersTab(ttk.Frame):  #
    def __init__(self, master):
        super().__init__(master)
        self.current_source = None
        self.servers = []  # list[str] of IP:PORT
        self.source_rows = []  # list[tuple(ip,motd,players,version)]
        self._in_ignore = False  # re-entrancy guard
        self.version_filter_var = tk.StringVar(value="All versions")
        self.check_whitelist_var = tk.BooleanVar(value=False)
        self._build_ui()
        self._current_scan_ip = None 
        self._scan_row_map = {}
        self._cracked_job_id = 0
        self._whitelist_job_id = 0

    def add_ignore(self):  #
        sel = self._selected_ips_any()
        if not sel:
            messagebox.showinfo("Info","Select one or more.")
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

    def add_saved(self):  #
        sel = self._selected_ips_any()
        if not sel:
            messagebox.showinfo("Info","Select one or more.")
            return
        reason = simpledialog.askstring("Reason","Why save? (optional)")
        for ip in sel:
            add_to_saved(ip, reason or "")
        self.set_status(f"Added {len(sel)} to saved.txt")

    def _build_ui(self):
        # Root grid: content (row 0) + footer (row 1) pinned
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        content = ttk.Frame(self)
        content.grid(row=0, column=0, sticky="nsew")

        # Paned: top (source) / middle (results)
        pane = tk.PanedWindow(content, orient="vertical", sashwidth=8)
        pane.pack(fill="both", expand=True, padx=8, pady=(8,0))
        pane_top = ttk.Frame(pane)
        pane_mid = ttk.Frame(pane)
        pane.add(pane_top, minsize=160)
        pane.add(pane_mid, minsize=220)

        # --- Source area (TOP) ---
        top = ttk.Frame(pane_top)
        top.pack(fill="x", padx=8, pady=8)

        self.src_label = ttk.Label(top, text="Source: (none)")
        self.src_label.pack(side="left")

        middle = ttk.Frame(pane_top)
        middle.pack(fill="both", expand=True, padx=8, pady=(0,8))

        # Source Tree (no icons here)
        cols = ("ip", "motd", "players", "version", "cracked")
        self.source_tree = ttk.Treeview(middle, columns=cols, show="headings", height=12, selectmode="extended")
        for c in cols:
            self.source_tree.heading(c, text=c.upper())
            if c == "motd":
                width = 240
            elif c == "players":
                width = 120
            elif c == "version":
                width = 120
            elif c == "cracked":
                width = 90
            else:
                width = 170
            self.source_tree.column(c, width=width, anchor="w")
        self.source_tree.pack(side="left", fill="both", expand=True)
        sb = ttk.Scrollbar(middle, orient="vertical", command=self.source_tree.yview)
        sb.pack(side="left", fill="y")
        self.source_tree.config(yscrollcommand=sb.set)
        make_tree_sortable(self.source_tree, {
            "ip": _ip_key,
            "motd": lambda v: str(v).lower(),
            "players": _players_key,
            "version": _version_key,
            "cracked": lambda v: (0 if str(v).lower() in ("false","no","0") else 1) if v is not None else -1
        })

        right = ttk.Frame(middle)
        right.pack(side="right", fill="y", padx=8)
        ttk.Button(right, text="Import .txt", command=self.load_txt).pack(fill="x", pady=(0,6))
        ttk.Button(right, text="Copy IP", command=self.copy_ip).pack(fill="x", pady=2)
        ttk.Button(right, text="Add to Ignore", command=self.add_ignore).pack(fill="x", pady=2)
        ttk.Button(right, text="Add to Saved", command=self.add_saved).pack(fill="x", pady=2)
        ttk.Button(right, text="Add to Monitor", command=self.add_search_selected_to_monitor).pack(fill="x", pady=2)
        ttk.Separator(right, orient="horizontal").pack(fill="x", pady=6)
        ttk.Button(right, text="Scan Selected", command=self.scan_selected).pack(fill="x", pady=2)
        ttk.Button(right, text="Scan All", command=self.scan_all).pack(fill="x", pady=2)
        self.only_players_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(right, text="Only players > 0", variable=self.only_players_var).pack(anchor="w", pady=(8,0))
        self.only_cracked_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(right, text="Only cracked servers", variable=self.only_cracked_var).pack(anchor="w")
        ttk.Checkbutton(right, text="Check whitelist", variable=self.check_whitelist_var).pack(anchor="w")
        ttk.Label(right, text="Version filter:").pack(anchor="w", pady=(8, 2))
        self.version_filter_combo = ttk.Combobox(
            right,
            textvariable=self.version_filter_var,
            values=["All versions"],
            width=18
        )
        self.version_filter_combo.pack(fill="x", pady=(0, 2))
        self.version_filter_combo.bind("<<ComboboxSelected>>", lambda _e: self.refresh_list())
        self.version_filter_combo.bind("<KeyRelease>", lambda _e: self.refresh_list())

        # --- Results area (MIDDLE) ---
        bottom = ttk.Frame(pane_mid)
        bottom.pack(fill="both", expand=True, padx=8, pady=8)
        ttk.Label(bottom, text="Results (select to copy/save/ignore):").pack(anchor="w")

        res_frame = ttk.Frame(bottom)
        res_frame.pack(fill="both", expand=True)

        cols2 = ("ip", "motd", "players", "version", "cracked", "whitelist", "active_players")
        # show icons ONLY in results tree
        self.results_tree = ttk.Treeview(res_frame, columns=cols2, show="headings", height=10, selectmode="extended")
        for c in cols2:
            self.results_tree.heading(c, text=c.upper())
            if c in ("motd", "active_players"):
                width = 240
            elif c == "players":
                width = 130
            elif c == "version":
                width = 130
            elif c == "whitelist":
                width = 220
            elif c == "cracked":
                width = 90
            else:
                width = 170
            self.results_tree.column(c, width=width, anchor="w")
        self.results_tree.pack(side="left", fill="both", expand=True)
        res_sb = ttk.Scrollbar(res_frame, orient="vertical", command=self.results_tree.yview)
        res_sb.pack(side="left", fill="y")
        self.results_tree.config(yscrollcommand=res_sb.set)
        make_tree_sortable(self.results_tree, {
            "ip": _ip_key,
            "motd": lambda v: str(v).lower(),
            "players": _players_key,
            "version": _version_key,
            "cracked": lambda v: (0 if str(v).lower() in ("false","no","0") else 1) if v is not None else -1,
            "whitelist": lambda v: str(v).lower(),
            "active_players": lambda v: str(v).lower()
        })

        # ------- Footer (pinned) -------
        footer = ttk.Frame(self)
        footer.grid(row=1, column=0, sticky="ew", padx=8, pady=(6,8))
        footer.grid_columnconfigure(1, weight=1)

        res_btns = ttk.Frame(footer)
        res_btns.grid(row=0, column=0, sticky="w")
        ttk.Button(res_btns, text="Copy IP(s)", command=self.copy_scan_selected).pack(side="left", padx=4)
        ttk.Button(res_btns, text="Add to Ignore", command=self.ignore_scan_selected).pack(side="left", padx=4)
        ttk.Button(res_btns, text="Add to Saved", command=self.save_scan_selected).pack(side="left", padx=4)
        ttk.Button(res_btns, text="Add to Monitor", command=self.add_scan_selected_to_monitor).pack(side="left", padx=4)
        ttk.Button(res_btns, text="Export Scan…", command=self.export_scan_results).pack(side="left", padx=4)
        ttk.Button(res_btns, text="Check Whitelist", command=lambda: check_selected_whitelist(self, self.results_tree)).pack(side="left", padx=4)
        self.player_search_var = tk.StringVar()
        search_entry = ttk.Entry(res_btns, textvariable=self.player_search_var, width=18)
        search_entry.pack(side="left", padx=(12,4))
        search_entry.bind("<Return>", lambda _e: self.search_players())
        ttk.Button(res_btns, text="Find Player", command=self.search_players).pack(side="left", padx=4)

        self.status = tk.StringVar(value="Ready.")
        ttk.Label(footer, textvariable=self.status, anchor="w").grid(row=0, column=1, sticky="ew", padx=(12,0))

        # ---------- ICONS attach (Servers: results only) ----------
        _get_icon_manager().attach_to_tree(self.results_tree)

    def set_status(self, msg):
        self.status.set(msg)

    def _update_version_filter_choices(self, rows):
        choices = collect_version_options(rows)
        current = self.version_filter_var.get() or "All versions"
        self.version_filter_combo["values"] = choices
        if current not in choices:
            current = "All versions"
        self.version_filter_var.set(current)

    def refresh_list(self, items=None):
        #populate source_tree using parsed rows when available
        for iid in self.source_tree.get_children():
            self.source_tree.delete(iid)
        if items is not None:
            rows = [(ip, "", "", "") for ip in items]  # explicit override
        elif self.source_rows:
            rows = self.source_rows
        else:
            rows = [(ip, "", "", "") for ip in self.servers]
        if items is None and rows and len(rows[0]) >= 4:
            rows = [row for row in rows if version_filter_allows(row[3], self.version_filter_var.get())]
        for row in rows:
            self.source_tree.insert("", "end", values=row)

    def load_txt(self):
        path = filedialog.askopenfilename(title="Open .txt", filetypes=[("Text files","*.txt"),("All files","*.*")])
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
            self.source_rows = rows  #
            self.servers = [ip for (ip, _, _, _) in rows]  # keep scan list intact
            self._update_version_filter_choices(rows)
            self.src_label.config(text=f"Source: {os.path.basename(path)} ({len(rows)} entries)")
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
            messagebox.showerror("Load error", str(e))

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
            messagebox.showinfo("Info","Select one or more.")
            return
        self.clipboard_clear()
        self.clipboard_append("\n".join(sel))
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
            messagebox.showinfo("Info", "Select results first.")
            return
        ips = [row[0] for row in rows]
        self.clipboard_clear()
        self.clipboard_append("\n".join(ips))
        self.set_status(f"Copied {len(ips)} IP(s) from results.")

    def ignore_scan_selected(self):  
        rows = self._scan_selected_rows()
        if not rows:
            messagebox.showinfo("Info", "Select results first.")
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
            messagebox.showinfo("Info", "Select results first.")
            return
        reason = simpledialog.askstring("Reason","Why save? (optional)")
        for ip, *_ in rows:
            add_to_saved(ip, reason or "")
        self.set_status(f"Added {len(rows)} to saved.txt from results.")

    def add_scan_selected_to_monitor(self):
        rows = self._scan_selected_rows()
        if not rows:
            messagebox.showinfo("Info", "Select results first.")
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
            messagebox.showinfo("Info", "No scan results to export.")
            return
        # default name uses source file name (if any)
        if self.current_source:
            base_name = os.path.splitext(os.path.basename(self.current_source))[0]
            base = sanitize_query_for_filename(base_name + "_scan")
        else:
            base = "servers_scan"
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files","*.txt")],
            title="Export Servers Scan Results",
            initialfile=f"{base}.txt"
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
        query_raw = self.player_search_var.get() or ""
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
        only_cracked = self.only_cracked_var.get()
        check_whitelist = self.check_whitelist_var.get()
        account = get_active_mc_account() if check_whitelist else None
        if check_whitelist and not account:
            messagebox.showinfo("Accounts", "Import or add a Minecraft account first.")
            self.set_status("Whitelist check canceled: no account selected.")
            return
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
                    self.after(0, lambda ip=ip: self.set_status(f"Currently scanning: {ip} [0/{total}]"))

                def on_result(r, line):
                    if not r:
                        return
                    discovered_rows.append((r['ip'], r['motd'], f"{r['players']}/{r['max_players']}", r['version']))

                    if self.only_players_var.get() and r.get('players', 0) <= 0:
                        return

                    if only_cracked and should_skip_cracked_probe(r):
                        return
                    if not version_filter_allows(r.get("version", ""), self.version_filter_var.get()):
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
                                remaining = len(self.results_tree.get_children())
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
                if discovered_rows:
                    self.after(0, lambda rows=discovered_rows: self._update_version_filter_choices(rows))
            except Exception as e:
                self.after(0, lambda: self.set_status(f"Scan failed: {e}"))

        threading.Thread(target=work, daemon=True).start()

    def scan_selected(self):
        sel = self._selected_ips_any()
        if not sel:
            messagebox.showinfo("Info","Select one or more.")
            return
        self._scan(sel)

    def scan_all(self):
        if not self.servers:
            messagebox.showinfo("Info","Load a .txt first.")
            return
        self._scan(self.servers)


def _servers_tab_add_search_selected_to_monitor(self):
    sel = self._selected_ips_any()
    if not sel:
        messagebox.showinfo("Info","Select items first.")
        return
    added, invalid, duplicates = add_ips_to_monitor_list(sel)
    self.set_status(format_monitor_feedback(added, invalid, duplicates))


ServersTab.add_search_selected_to_monitor = _servers_tab_add_search_selected_to_monitor

class ServerMonitorTab(ttk.Frame):
    def __init__(self, master):
        super().__init__(master)
        self.monitor_state = load_server_monitor_state()
        self.interval_var = tk.IntVar(value=DEFAULT_MONITOR_INTERVAL)
        self.status_var = tk.StringVar(value="Monitor idle.")
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
        self.grid_rowconfigure(2, weight=1)
        self.grid_columnconfigure(0, weight=1)

        input_frame = ttk.Frame(self)
        input_frame.grid(row=0, column=0, sticky="ew", padx=8, pady=(8, 4))
        input_frame.columnconfigure(0, weight=1)
        ttk.Label(input_frame, text="Add servers (one IP:PORT per line):").grid(row=0, column=0, sticky="w")
        self.server_input = tk.Text(input_frame, height=3, wrap="none")
        self.server_input.grid(row=1, column=0, sticky="ew", padx=(0, 4))
        input_scroll = ttk.Scrollbar(input_frame, orient="vertical", command=self.server_input.yview)
        input_scroll.grid(row=1, column=1, sticky="ns")
        self.server_input.configure(yscrollcommand=input_scroll.set)
        btn_frame = ttk.Frame(input_frame)
        btn_frame.grid(row=2, column=0, columnspan=2, sticky="w", pady=(4, 0))
        ttk.Button(btn_frame, text="Add to Monitor", command=self.add_servers_from_input).pack(side="left")
        ttk.Button(btn_frame, text="Clear Input", command=self.clear_input).pack(side="left", padx=6)
        ttk.Button(btn_frame, text="Remove Selected", command=self.remove_selected_servers).pack(side="left")
        ttk.Button(btn_frame, text="Copy Selected", command=self.copy_monitored_ips).pack(side="left", padx=6)

        control_frame = ttk.Frame(self)
        control_frame.grid(row=1, column=0, sticky="ew", padx=8, pady=4)
        control_frame.columnconfigure(6, weight=1)
        ttk.Label(control_frame, text="Ping interval (secs):").grid(row=0, column=0, sticky="w")
        ttk.Entry(control_frame, width=6, textvariable=self.interval_var).grid(row=0, column=1, sticky="w", padx=(4, 12))
        self.start_btn = ttk.Button(control_frame, text="Start Monitoring", command=self.start_monitoring)
        self.start_btn.grid(row=0, column=2, padx=4)
        self.stop_btn = ttk.Button(control_frame, text="Stop", command=self.stop_monitoring, state="disabled")
        self.stop_btn.grid(row=0, column=3, padx=4)
        ttk.Button(control_frame, text="Export Player Log", command=self.export_players).grid(row=0, column=4, padx=4)

        main_pane = tk.PanedWindow(self, orient="vertical", sashwidth=8)
        main_pane.grid(row=2, column=0, sticky="nsew", padx=8, pady=4)
        main_pane.rowconfigure(0, weight=1)
        main_pane.columnconfigure(0, weight=1)

        server_frame = ttk.Frame(main_pane)
        server_frame.rowconfigure(0, weight=1)
        server_frame.columnconfigure(0, weight=1)
        cols = ("ip", "status", "players", "version", "cracked", "motd", "last_ping")
        self.server_tree = ttk.Treeview(server_frame, columns=cols, show="headings", height=10, selectmode="extended")
        for col in cols:
            self.server_tree.heading(col, text=col.replace("_", " ").title())
            if col == "ip":
                width = 150
            elif col == "status":
                width = 100
            elif col == "players":
                width = 110
            elif col == "version":
                width = 120
            elif col == "cracked":
                width = 90
            elif col == "motd":
                width = 260
            else:
                width = 170
            self.server_tree.column(col, width=width, anchor="w")
        self.server_tree.grid(row=0, column=0, sticky="nsew")
        tree_scroll = ttk.Scrollbar(server_frame, orient="vertical", command=self.server_tree.yview)
        tree_scroll.grid(row=0, column=1, sticky="ns")
        self.server_tree.configure(yscrollcommand=tree_scroll.set)
        self.server_tree.bind("<<TreeviewSelect>>", lambda e: self._on_server_selected())
        self.server_tree.tag_configure("status_offline", background="#ffe6e6")
        make_tree_sortable(self.server_tree, {
            "ip": _ip_key,
            "status": lambda v: str(v).lower(),
            "players": _players_key,
            "version": _version_key,
            "cracked": lambda v: 0 if str(v).lower() in ("false","no","0") else 1,
            "motd": lambda v: str(v).lower(),
            "last_ping": lambda v: v or ""
        })
        main_pane.add(server_frame, minsize=260)

        players_frame = ttk.Frame(main_pane)
        players_frame.rowconfigure(1, weight=1)
        players_frame.columnconfigure(0, weight=1)
        ttk.Label(players_frame, text="Recorded players for selected server:").grid(row=0, column=0, sticky="w", pady=(0,4))
        player_cols = ("uuid", "name", "last_seen")
        self.players_tree = ttk.Treeview(players_frame, columns=player_cols, show="headings", height=6)
        for col in player_cols:
            self.players_tree.heading(col, text=col.replace("_", " ").title())
            if col == "uuid":
                width = 260
            elif col == "name":
                width = 200
            else:
                width = 170
            self.players_tree.column(col, width=width, anchor="w")
        self.players_tree.grid(row=1, column=0, sticky="nsew")
        player_scroll = ttk.Scrollbar(players_frame, orient="vertical", command=self.players_tree.yview)
        player_scroll.grid(row=1, column=1, sticky="ns")
        self.players_tree.configure(yscrollcommand=player_scroll.set)
        self.players_tree.tag_configure("player_online", foreground="#0b8f0b")
        btn_frame = ttk.Frame(players_frame)
        btn_frame.grid(row=2, column=0, sticky="w", pady=(4,0))
        ttk.Button(btn_frame, text="Copy Username(s)", command=self.copy_selected_player_names).pack(side="left")
        main_pane.add(players_frame, minsize=160)

        footer = ttk.Frame(self)
        footer.grid(row=3, column=0, sticky="ew", padx=8, pady=(8, 8))
        ttk.Label(footer, textvariable=self.status_var, anchor="w").pack(fill="x")

    def _set_status(self, msg):
        self.status_var.set(msg)

    def add_servers_from_input(self):
        raw = self.server_input.get("1.0", "end").strip()
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
        self.server_input.delete("1.0", "end")

    def clear_input(self):
        self.server_input.delete("1.0", "end")
        self._set_status("Input cleared.")

    def remove_selected_servers(self):
        selected = self.server_tree.selection()
        if not selected:
            messagebox.showinfo("Info", "Select rows to remove.")
            return
        removed = 0
        for iid in selected:
            vals = self.server_tree.item(iid, "values")
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

    def copy_monitored_ips(self):
        selected = self.server_tree.selection()
        if not selected:
            messagebox.showinfo("Info", "Select rows first.")
            return
        ips = []
        for iid in selected:
            vals = self.server_tree.item(iid, "values")
            if vals:
                ips.append(vals[0])
        if not ips:
            messagebox.showinfo("Info", "No valid IPs selected.")
            return
        self.clipboard_clear()
        self.clipboard_append("\n".join(ips))
        self._set_status(f"Copied {len(ips)} monitored server(s).")

    def copy_selected_player_names(self):
        selected = self.players_tree.selection()
        if not selected:
            messagebox.showinfo("Info", "Select player rows first.")
            return
        names = []
        for iid in selected:
            vals = self.players_tree.item(iid, "values")
            if vals and len(vals) >= 2:
                name = vals[1]
                if isinstance(name, str) and name.strip():
                    names.append(name.strip())
        if not names:
            messagebox.showinfo("Info", "No player names selected.")
            return
        self.clipboard_clear()
        self.clipboard_append("\n".join(names))
        self._set_status(f"Copied {len(names)} player name(s).")

    def start_monitoring(self):
        if self._monitoring:
            return
        interval = self._read_interval()
        if not interval:
            messagebox.showinfo("Info", "Enter a valid interval (in seconds).")
            return
        ips = self._get_monitored_ips()
        if not ips:
            messagebox.showinfo("Info", "Add at least one server to monitor.")
            return
        self._monitor_interval = interval
        self._stop_event.clear()
        self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._monitor_thread.start()
        self._monitoring = True
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self._set_status(f"Monitoring {len(ips)} server(s) every {interval}s.")

    def stop_monitoring(self):
        if not self._monitoring:
            return
        self._stop_event.set()
        self._monitoring = False
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self._set_status("Monitoring paused.")

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
            messagebox.showinfo("Info", "Select a server first.")
            return
        entry = self.monitor_state.get("servers", {}).get(ip)
        if not entry:
            messagebox.showinfo("Info", "Server data unavailable.")
            return
        log = entry.get("player_log", {})
        if not log:
            messagebox.showinfo("Info", "No player data for this server yet.")
            return
        safe_name = ip.replace(":", "_")
        path = filedialog.asksaveasfilename(
            title="Export Player Log",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt")],
            initialfile=f"{safe_name}_players.txt"
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

    def _get_monitored_ips(self):
        return list(self.monitor_state.get("servers", {}).keys())

    def _read_interval(self):
        try:
            val = int(self.interval_var.get())
            return max(5, val)
        except Exception:
            return None

    def _refresh_server_tree(self):
        current = self._last_selected_ip
        target_iid = None
        self.server_tree.delete(*self.server_tree.get_children())
        for ip in sorted(self.monitor_state.get("servers", {})):
            entry = self.monitor_state["servers"][ip]
            players = entry.get("players_online", 0)
            max_players = entry.get("max_players", 0)
            status = entry.get("last_status", "unknown")
            last_ping = format_timestamp(entry.get("last_ping"))
            version = entry.get("version", "N/A")
            cracked = "Yes" if entry.get("cracked") else "No"
            motd = sanitize_motd(entry.get("motd", ""))
            iid = self.server_tree.insert(
                "",
                "end",
                values=(ip, status.title(), f"{players}/{max_players}", version, cracked, motd, last_ping),
                tags=("status_offline",) if status.strip().lower() != "online" and status.strip() else ()
            )
            if ip == current:
                target_iid = iid
        if target_iid:
            self.server_tree.selection_set(target_iid)
            self.server_tree.see(target_iid)

    def _refresh_players_tree(self, ip=None):
        if ip is None:
            ip = self._last_selected_ip
        self.players_tree.delete(*self.players_tree.get_children())
        if not ip:
            return
        entry = self.monitor_state.get("servers", {}).get(ip)
        if not entry:
            return
        current_online = set(entry.get("current_players") or [])
        rows = []
        for uid, pdata in entry.get("player_log", {}).items():
            rows.append((uid, pdata.get("name", ""), pdata.get("last_seen", 0)))
        rows.sort(key=lambda item: item[2], reverse=True)
        for uid, name, last_seen in rows:
            tags = ("player_online",) if uid in current_online else ()
            self.players_tree.insert("", "end", values=(uid, name, format_timestamp(last_seen)), tags=tags)

    def _on_server_selected(self):
        selection = self.server_tree.selection()
        if not selection:
            self._last_selected_ip = None
            self._refresh_players_tree(None)
            return
        vals = self.server_tree.item(selection[0], "values")
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

# ---- Shodan Tab ----
class ShodanTab(ttk.Frame):  
    def __init__(self, master):
        super().__init__(master)
        self.results = []  # list[tuple(ip,motd,players,version)]
        self.scan_rows = []
        self._in_ignore = False
        self.version_filter_var = tk.StringVar(value="All versions")
        self.check_whitelist_var = tk.BooleanVar(value=False)
        self._build_ui()
        self._current_scan_ip = None
        self._scan_row_map = {}
        self._cracked_job_id = 0
        self._whitelist_job_id = 0

    def _build_ui(self):
        # Root grid: content (row 0) + footer (row 1) pinned
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        content = ttk.Frame(self)
        content.grid(row=0, column=0, sticky="nsew")

        # Paned window: top (search + table) / bottom (scan output)
        pane = tk.PanedWindow(content, orient="vertical", sashwidth=8)
        pane.pack(fill="both", expand=True, padx=8, pady=(8,0))
        pane_top = ttk.Frame(pane)
        pane_bottom = ttk.Frame(pane)
        pane.add(pane_top, minsize=300)
        pane.add(pane_bottom, minsize=240)

        bar = ttk.Frame(pane_top)
        bar.pack(fill="x", padx=8, pady=8)
        ttk.Label(bar, text="Query (without 'minecraft'): ").pack(side="left")
        self.query_var = tk.StringVar()
        ttk.Entry(bar, textvariable=self.query_var, width=50).pack(side="left", padx=6)
        ttk.Button(bar, text="Search", command=self.do_search).pack(side="left")
        ttk.Button(bar, text="Export Search…", command=self.export_search_results).pack(side="left", padx=6)
        ttk.Label(bar, text="Version:").pack(side="left", padx=(12, 4))
        self.version_filter_combo = ttk.Combobox(
            bar,
            textvariable=self.version_filter_var,
            values=["All versions"],
            width=18
        )
        self.version_filter_combo.pack(side="left")
        self.version_filter_combo.bind("<<ComboboxSelected>>", lambda _e: self._refresh_search_tree())
        self.version_filter_combo.bind("<KeyRelease>", lambda _e: self._refresh_search_tree())

        mid = ttk.Frame(pane_top)
        mid.pack(fill="both", expand=True, padx=8, pady=4)

        cols = ("ip","motd","players","version")
        self.tree = ttk.Treeview(mid, columns=cols, show="headings", height=14, selectmode="extended")
        for c in cols:
            self.tree.heading(c, text=c.upper())
            if c == "motd":
                width = 240
            elif c == "players":
                width = 120
            elif c == "version":
                width = 120
            else:
                width = 170
            self.tree.column(c, width=width, anchor="w")
        self.tree.pack(side="left", fill="both", expand=True)
        sb = ttk.Scrollbar(mid, orient="vertical", command=self.tree.yview)
        sb.pack(side="left", fill="y")
        self.tree.config(yscrollcommand=sb.set)

        make_tree_sortable(self.tree, {
            "ip": _ip_key,
            "motd": lambda v: str(v).lower(),
            "players": _players_key,
            "version": _version_key
        })

        right = ttk.Frame(mid)
        right.pack(side="right", fill="y", padx=8)
        ttk.Button(right, text="Copy IP(s)", command=self.copy_selected).pack(fill="x", pady=2)
        ttk.Button(right, text="Add to Ignore", command=self.ignore_selected).pack(fill="x", pady=2)
        ttk.Button(right, text="Add to Saved", command=self.save_selected).pack(fill="x", pady=2)
        ttk.Button(right, text="Add to Monitor", command=self.add_search_selected_to_monitor).pack(fill="x", pady=2)
        ttk.Separator(right, orient="horizontal").pack(fill="x", pady=6)
        ttk.Button(right, text="Scan Selected", command=self.scan_selected).pack(fill="x", pady=2)
        ttk.Button(right, text="Scan All", command=self.scan_all).pack(fill="x", pady=2)
        self.only_players_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(right, text="Only players > 0", variable=self.only_players_var).pack(anchor="w", pady=(8,0))
        self.only_cracked_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(right, text="Only cracked servers", variable=self.only_cracked_var).pack(anchor="w")
        ttk.Checkbutton(right, text="Check whitelist", variable=self.check_whitelist_var).pack(anchor="w")

        # BOTTOM: Scan output table
        out = ttk.Frame(pane_bottom)
        out.pack(fill="both", expand=True, padx=8, pady=(0,8))
        ttk.Label(out, text="Scan Output (select to copy/save/ignore):").pack(anchor="w")
        of = ttk.Frame(out)
        of.pack(fill="both", expand=True)

        cols_out = ("ip","motd","players","version","cracked","whitelist","active_players")
        self.scan_tree = ttk.Treeview(of, columns=cols_out, show="headings", height=8, selectmode="extended")
        for c in cols_out:
            self.scan_tree.heading(c, text=c.upper())
            if c in ("motd", "active_players"):
                width = 240
            elif c == "players":
                width = 130
            elif c == "version":
                width = 130
            elif c == "whitelist":
                width = 220
            elif c == "cracked":
                width = 90
            else:
                width = 170
            self.scan_tree.column(c, width=width, anchor="w")
        self.scan_tree.pack(side="left", fill="both", expand=True)
        osb = ttk.Scrollbar(of, orient="vertical", command=self.scan_tree.yview)
        osb.pack(side="left", fill="y")
        self.scan_tree.config(yscrollcommand=osb.set)
        make_tree_sortable(self.scan_tree, {
            "ip": _ip_key,
            "motd": lambda v: str(v).lower(),
            "players": _players_key,
            "version": _version_key,
            "cracked": lambda v: (0 if str(v).lower() in ("false","no","0") else 1) if v is not None else -1,
            "whitelist": lambda v: str(v).lower(),
            "active_players": lambda v: str(v).lower()
        })

        # ------- Footer (pinned) -------
        footer = ttk.Frame(self)
        footer.grid(row=1, column=0, sticky="ew", padx=8, pady=(6,8))
        footer.grid_columnconfigure(1, weight=1)

        obtns = ttk.Frame(footer)
        obtns.grid(row=0, column=0, sticky="w")
        ttk.Button(obtns, text="Copy IP(s)", command=self.copy_scan_selected).pack(side="left", padx=4)
        ttk.Button(obtns, text="Add to Ignore", command=self.ignore_scan_selected_from_output).pack(side="left", padx=4)
        ttk.Button(obtns, text="Add to Saved", command=self.save_scan_selected_from_output).pack(side="left", padx=4)
        ttk.Button(obtns, text="Add to Monitor", command=self.add_scan_output_selected_to_monitor).pack(side="left", padx=4)
        ttk.Button(obtns, text="Export Scan…", command=self.export_scan_output).pack(side="left", padx=4)
        ttk.Button(obtns, text="Check Whitelist", command=lambda: check_selected_whitelist(self, self.scan_tree)).pack(side="left", padx=4)

        self.status = tk.StringVar(value="Ready.")
        ttk.Label(footer, textvariable=self.status, anchor="w").grid(row=0, column=1, sticky="ew", padx=(12,0))

        # ---------- ICONS: attach (Shodan: search & output) ----------
        _get_icon_manager().attach_to_tree(self.tree)
        _get_icon_manager().attach_to_tree(self.scan_tree)

    def set_status(self, msg):
        self.status.set(msg)

    def _update_version_filter_choices(self, rows):
        choices = collect_version_options(rows)
        current = self.version_filter_var.get() or "All versions"
        self.version_filter_combo["values"] = choices
        if current not in choices:
            current = "All versions"
        self.version_filter_var.set(current)

    def _refresh_search_tree(self):
        self.tree.delete(*self.tree.get_children())
        for row in self.results:
            if version_filter_allows(row[3], self.version_filter_var.get()):
                self.tree.insert("", "end", values=row)

    def _refresh_scan_tree(self):
        self.scan_tree.delete(*self.scan_tree.get_children())
        for row in self.scan_rows:
            if version_filter_allows(row[3], self.version_filter_var.get()):
                self.scan_tree.insert("", "end", values=row)

    def do_search(self):
        q = self.query_var.get().strip()
        full_query = f"minecraft {q}" if q else "minecraft"

        # MAIN THREAD: ensure key (may open a dialog)
        key = ensure_shodan_key_ui(self)
        if not key:
            self.set_status("Search canceled: no Shodan API key.")
            return

        self.set_status(f"Searching: {full_query}")
        self.tree.delete(*self.tree.get_children())

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

            except shodan.APIError as e:
                msg = str(e)

                def report_error():
                    self.set_status(f"Search failed: {msg}")
                    if "invalid" in msg.lower() or "unauthorized" in msg.lower():
                        try:
                            if os.path.exists(SHODAN_KEY_PATH):
                                os.remove(SHODAN_KEY_PATH)
                        except Exception:
                            pass
                        messagebox.showerror(
                            "Shodan",
                            "The Shodan API key appears to be invalid.\n"
                            "I removed shodan_key.txt. Search again and enter a valid key."
                        )

                self.after(0, report_error)

            except Exception as e:
                self.after(0, lambda: self.set_status(f"Search failed: {e}"))

        threading.Thread(target=work, daemon=True).start()
        return


    def _search_selected_ips(self):
        sel = []
        for iid in self.tree.selection():
            vals = self.tree.item(iid, "values")
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
    def _scan_selected_rows(self):  #
        out = []
        for iid in self.scan_tree.selection():
            vals = self.scan_tree.item(iid, "values")
            if vals:
                out.append(vals)
        return out

    def copy_scan_selected(self):
        rows = self._scan_selected_rows()
        if not rows:
            messagebox.showinfo("Info", "Select scan output rows.")
            return
        ips = [row[0] for row in rows]
        self.clipboard_clear()
        self.clipboard_append("\n".join(ips))
        self.set_status(f"Copied {len(ips)} IP(s) from scan output.")

    def ignore_selected(self):  
        sel = self._all_selected_ips()
        if not sel:
            messagebox.showinfo("Info","Select items first.")
            return
        reason = ask_reason_with_whitelist(self, "Reason", "Why ignore? (optional)")
        if reason is None:
            self.set_status("Ignore cancelled.")
            return
        for ip in sel:
            add_to_ignore(ip, reason or "")
        for iid in list(self.tree.selection()):
            self.tree.delete(iid)
        self.set_status(f"Added {len(sel)} to ignore.txt")

    def save_selected(self):  
        sel = self._all_selected_ips()
        if not sel:
            messagebox.showinfo("Info","Select items first.")
            return
        reason = simpledialog.askstring("Reason","Why save? (optional)")
        for ip in sel:
            add_to_saved(ip, reason or "")
        self.set_status(f"Added {len(sel)} to saved.txt")

    def add_search_selected_to_monitor(self):
        sel = self._all_selected_ips()
        if not sel:
            messagebox.showinfo("Info","Select items first.")
            return
        added, invalid, duplicates = add_ips_to_monitor_list(sel)
        self.set_status(format_monitor_feedback(added, invalid, duplicates))

    def ignore_scan_selected_from_output(self):
        rows = self._scan_selected_rows()
        if not rows:
            messagebox.showinfo("Info", "Select scan output rows.")
            return
        reason = ask_reason_with_whitelist(self, "Reason", "Why ignore? (optional)")
        if reason is None:
            self.set_status("Ignore cancelled.")
            return
        for ip, *_ in rows:
            add_to_ignore(ip, reason or "")
        for iid in list(self.scan_tree.selection()):
            self.scan_tree.delete(iid)
        self.set_status(f"Added {len(rows)} to ignore.txt from scan output.")

    def save_scan_selected_from_output(self):
        rows = self._scan_selected_rows()
        if not rows:
            messagebox.showinfo("Info", "Select scan output rows.")
            return
        reason = simpledialog.askstring("Reason","Why save? (optional)")
        for ip, *_ in rows:
            add_to_saved(ip, reason or "")
        self.set_status(f"Added {len(rows)} to saved.txt from scan output.")

    def add_scan_output_selected_to_monitor(self):
        rows = self._scan_selected_rows()
        if not rows:
            messagebox.showinfo("Info", "Select scan output rows.")
            return
        ips = [row[0] for row in rows]
        added, invalid, duplicates = add_ips_to_monitor_list(ips)
        self.set_status(format_monitor_feedback(added, invalid, duplicates))

    def export_scan_output(self):  
        rows = []
        for iid in self.scan_tree.get_children():
            vals = self.scan_tree.item(iid, "values")
            if vals:
                rows.append(vals)
        if not rows:
            messagebox.showinfo("Info", "No scan output to export.")
            return
        q = self.query_var.get().strip()
        base = sanitize_query_for_filename((q if q else "minecraft") + "_scan")
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files","*.txt")],
            title="Export Shodan Scan Output",
            initialfile=f"{base}.txt"
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
        query_raw = self.player_search_var.get() or ""
        query = query_raw.strip().lower()
        if not query:
            self.set_status("Enter a player name to search.")
            return
        matches = []
        for iid in self.scan_tree.get_children():
            vals = self.scan_tree.item(iid, "values")
            if not vals:
                continue
            players_text = vals[-1] if vals else ""
            if isinstance(players_text, str) and query in players_text.lower():
                matches.append(iid)
        current_sel = self.scan_tree.selection()
        if current_sel:
            self.scan_tree.selection_remove(current_sel)
        if matches:
            self.scan_tree.selection_set(matches)
            self.scan_tree.focus(matches[0])
            self.scan_tree.see(matches[0])
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
        vals = list(self.scan_tree.item(iid, "values"))
        if len(vals) >= 5:
            vals[4] = text
            self.scan_tree.item(iid, values=vals)

    def _update_scan_row_whitelist(self, ip, text):
        iid = self._scan_row_map.get(ip)
        if not iid:
            return
        vals = list(self.scan_tree.item(iid, "values"))
        if len(vals) >= 6:
            vals[5] = text
            self.scan_tree.item(iid, values=vals)

    def _remove_scan_row(self, ip):
        iid = self._scan_row_map.pop(ip, None)
        if iid:
            self.scan_tree.delete(iid)

    def _scan_and_show(self, items):
        for iid in self.scan_tree.get_children():
            self.scan_tree.delete(iid)
        self.set_status("Preparing scan...")
        only_cracked = self.only_cracked_var.get()
        check_whitelist = self.check_whitelist_var.get()
        account = get_active_mc_account() if check_whitelist else None
        if check_whitelist and not account:
            messagebox.showinfo("Accounts", "Import or add a Minecraft account first.")
            self.set_status("Whitelist check canceled: no account selected.")
            return
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
                    self.after(0, lambda ip=ip: self.set_status(f"Currently scanning: {ip} [0/{len(items)}]"))

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

                    if self.only_players_var.get() and r.get('players', 0) <= 0:
                        return
                    if only_cracked and should_skip_cracked_probe(r):
                        return
                    if not version_filter_allows(r.get("version", ""), self.version_filter_var.get()):
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
                        iid = self.scan_tree.insert("", "end", values=v)
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
                                remaining = len(self.scan_tree.get_children())
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
        sel = self._all_selected_ips()
        if not sel:
            messagebox.showinfo("Info","Select items in the table.")
            return
        self._scan_and_show(sel)

    def scan_all(self): 
        if not self.results:
            messagebox.showinfo("Info","Run a search first.")
            return
        all_ips = [row[0] for row in self.results]
        self._scan_and_show(all_ips)

    def copy_selected(self):
        sel = self._all_selected_ips()
        if not sel:
            messagebox.showinfo("Info","Select items first.")
            return
        self.clipboard_clear()
        self.clipboard_append("\n".join(sel))
        self.set_status(f"Copied {len(sel)} IP(s).")

    def export_search_results(self): 
        if not self.results:
            messagebox.showinfo("Info","No search results to export.")
            return
        q = self.query_var.get().strip()
        base = sanitize_query_for_filename(q if q else "minecraft")
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files","*.txt")],
            title="Export Shodan Search Results",
            initialfile=f"{base}.txt"
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

# ---- JSON Search Tab ----
class JSONTab(ttk.Frame):  
    def __init__(self, master):
        super().__init__(master)
        self._in_ignore = False
        self.json_entries = []
        self.all_rows = []
        self._loaded_json_path = None
        self.scan_rows = []
        self.version_filter_var = tk.StringVar(value="All versions")
        self.check_whitelist_var = tk.BooleanVar(value=False)
        self._build_ui()
        self._current_scan_ip = None
        self._scan_row_map = {}
        self._cracked_job_id = 0
        self._whitelist_job_id = 0
        self.search_rows = []  # list[tuple(ip,motd,players,version)]
        default_path = self.file_var.get().strip()
        if default_path and os.path.exists(default_path):
            self.load_json_file(default_path)

    def _build_ui(self):
        # Root grid: content (row 0) + footer (row 1) pinned
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        content = ttk.Frame(self)
        content.grid(row=0, column=0, sticky="nsew")

        bar = ttk.Frame(content)
        bar.pack(fill="x", padx=8, pady=8)

        self.file_var = tk.StringVar(value=DEFAULT_JSONL_FILE)
        ttk.Entry(bar, textvariable=self.file_var, width=48).pack(side="left", padx=4)
        ttk.Button(bar, text="Import .json", command=self.pick_json).pack(side="left", padx=4)

        self.query_var = tk.StringVar()
        ttk.Entry(bar, textvariable=self.query_var, width=48).pack(side="left", padx=4)
        ttk.Button(bar, text="Search", command=self.search).pack(side="left")
        ttk.Button(bar, text="Export Search…", command=self.export_search_results).pack(side="left", padx=6)
        ttk.Label(bar, text="Version:").pack(side="left", padx=(12, 4))
        self.version_filter_combo = ttk.Combobox(
            bar,
            textvariable=self.version_filter_var,
            values=["All versions"],
            width=18
        )
        self.version_filter_combo.pack(side="left")
        self.version_filter_combo.bind("<<ComboboxSelected>>", lambda _e: self._populate_search_tree(self.search_rows))
        self.version_filter_combo.bind("<KeyRelease>", lambda _e: self._populate_search_tree(self.search_rows))

        pane = tk.PanedWindow(content, orient="vertical", sashwidth=8)
        pane.pack(fill="both", expand=True, padx=8, pady=4)

        mid = ttk.Frame(pane)
        pane.add(mid, minsize=260)

        # Search results Treeview with same columns
        cols = ("ip","motd","players","version")
        self.search_tree = ttk.Treeview(mid, columns=cols, show="headings", height=12, selectmode="extended")
        for c in cols:
            self.search_tree.heading(c, text=c.upper())
            if c == "motd":
                width = 240
            elif c == "players":
                width = 120
            elif c == "version":
                width = 120
            else:
                width = 170
            self.search_tree.column(c, width=width, anchor="w")
        self.search_tree.pack(side="left", fill="both", expand=True)
        sb = ttk.Scrollbar(mid, orient="vertical", command=self.search_tree.yview)
        sb.pack(side="left", fill="y")
        self.search_tree.config(yscrollcommand=sb.set)
        make_tree_sortable(self.search_tree, {
            "ip": _ip_key,
            "motd": lambda v: str(v).lower(),
            "players": _players_key,
            "version": _version_key
        })

        right = ttk.Frame(mid)
        right.pack(side="right", fill="y", padx=8)
        ttk.Button(right, text="Copy IP(s)", command=self.copy_ip).pack(fill="x", pady=2)
        ttk.Button(right, text="Add to Ignore", command=self.add_ignore).pack(fill="x", pady=2)
        ttk.Button(right, text="Add to Saved", command=self.add_saved).pack(fill="x", pady=2)
        ttk.Button(right, text="Add to Monitor", command=self.add_search_selected_to_monitor).pack(fill="x", pady=2)
        ttk.Separator(right, orient="horizontal").pack(fill="x", pady=6)
        ttk.Button(right, text="Scan Selected", command=self.scan_selected).pack(fill="x", pady=2)
        ttk.Button(right, text="Scan All", command=self.scan_all).pack(fill="x", pady=2)
        self.only_players_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(right, text="Only players > 0", variable=self.only_players_var).pack(anchor="w", pady=(8,0))
        self.only_cracked_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(right, text="Only cracked servers", variable=self.only_cracked_var).pack(anchor="w")
        ttk.Checkbutton(right, text="Check whitelist", variable=self.check_whitelist_var).pack(anchor="w")

        # Scan output -> Treeview (still inside content)
        out = ttk.Frame(pane)
        pane.add(out, minsize=220)
        ttk.Label(out, text="Scan Output (select to copy/save/ignore):").pack(anchor="w")
        of = ttk.Frame(out)
        of.pack(fill="both", expand=True)

        cols2 = ("ip","motd","players","version","cracked","whitelist","active_players")
        self.scan_tree = ttk.Treeview(of, columns=cols2, show="headings", height=8, selectmode="extended")
        for c in cols2:
            self.scan_tree.heading(c, text=c.upper())
            if c in ("motd", "active_players"):
                width = 240
            elif c == "players":
                width = 130
            elif c == "version":
                width = 130
            elif c == "whitelist":
                width = 220
            elif c == "cracked":
                width = 90
            else:
                width = 170
            self.scan_tree.column(c, width=width, anchor="w")
        self.scan_tree.pack(side="left", fill="both", expand=True)
        osb = ttk.Scrollbar(of, orient="vertical", command=self.scan_tree.yview)
        osb.pack(side="left", fill="y")
        self.scan_tree.config(yscrollcommand=osb.set)
        make_tree_sortable(self.scan_tree, {
            "ip": _ip_key,
            "motd": lambda v: str(v).lower(),
            "players": _players_key,
            "version": _version_key,
            "cracked": lambda v: (0 if str(v).lower() in ("false","no","0") else 1) if v is not None else -1,
            "whitelist": lambda v: str(v).lower(),
            "active_players": lambda v: str(v).lower()
        })

        # ------- Footer (pinned) -------
        footer = ttk.Frame(self)
        footer.grid(row=1, column=0, sticky="ew", padx=8, pady=(6,8))
        footer.grid_columnconfigure(1, weight=1)

        obtns = ttk.Frame(footer)
        obtns.grid(row=0, column=0, sticky="w")
        ttk.Button(obtns, text="Copy IP(s)", command=self.copy_scan_selected).pack(side="left", padx=4)
        ttk.Button(obtns, text="Add to Ignore", command=self.ignore_scan_selected).pack(side="left", padx=4)
        ttk.Button(obtns, text="Add to Saved", command=self.save_scan_selected).pack(side="left", padx=4)
        ttk.Button(obtns, text="Add to Monitor", command=self.add_scan_output_selected_to_monitor).pack(side="left", padx=4)
        ttk.Button(obtns, text="Export Scan…", command=self.export_scan_output).pack(side="left", padx=4)
        ttk.Button(obtns, text="Check Whitelist", command=lambda: check_selected_whitelist(self, self.scan_tree)).pack(side="left", padx=4)
        self.player_search_var = tk.StringVar()
        search_entry = ttk.Entry(obtns, textvariable=self.player_search_var, width=18)
        search_entry.pack(side="left", padx=(12,4))
        search_entry.bind("<Return>", lambda _e: self.search_players())
        ttk.Button(obtns, text="Find Player", command=self.search_players).pack(side="left", padx=4)

        self.status = tk.StringVar(value="Ready.")
        ttk.Label(footer, textvariable=self.status, anchor="w").grid(row=0, column=1, sticky="ew", padx=(12,0))

        # ---------- ICONS: attach (JSON: search & output) ----------
        _get_icon_manager().attach_to_tree(self.search_tree)
        _get_icon_manager().attach_to_tree(self.scan_tree)

    def set_status(self,msg):
        self.status.set(msg)

    def _update_version_filter_choices(self, rows):
        choices = collect_version_options(rows)
        current = self.version_filter_var.get() or "All versions"
        self.version_filter_combo["values"] = choices
        if current not in choices:
            current = "All versions"
        self.version_filter_var.set(current)

    def _populate_search_tree(self, rows):
        self.search_tree.delete(*self.search_tree.get_children())
        for ip, motd, players, version in rows:
            if version_filter_allows(version, self.version_filter_var.get()):
                self.search_tree.insert("", "end", values=(ip, motd, players, version))

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
        path = filedialog.askopenfilename(title="Pick JSON Lines", filetypes=[("JSON/JSONL","*.json *.jsonl *.*")])
        if path:
            self.file_var.set(path)
            self.load_json_file(path)

    def search(self):
        file_path = self.file_var.get().strip()
        query = self.query_var.get().strip()
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

    def _search_selected_rows(self):  #
        out = []
        for iid in self.search_tree.selection():
            vals = self.search_tree.item(iid, "values")
            if vals:
                out.append(vals)
        return out

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
            messagebox.showinfo("Info","Select items first.")
            return
        self.clipboard_clear()
        self.clipboard_append("\n".join(ips))
        self.set_status(f"Copied {len(ips)} IP(s).")

    def add_ignore(self):
        if self._in_ignore:
            return
        rows = self._search_selected_rows()
        if not rows:
            messagebox.showinfo("Info","Select items first.")
            return
        reason = ask_reason_with_whitelist(self, "Reason", "Why ignore? (optional)")
        if reason is None:
            self.set_status("Ignore cancelled.")
            return
        self._in_ignore = True
        try:
            for (ip, *_rest) in rows:
                add_to_ignore(ip, reason or "")
            # remove from tree
            for iid in list(self.search_tree.selection()):
                self.search_tree.delete(iid)
            self.set_status(f"Added {len(rows)} to ignore.txt")
        finally:
            self._in_ignore = False

    def add_saved(self):
        rows = self._search_selected_rows()
        if not rows:
            messagebox.showinfo("Info","Select items first.")
            return
        reason = simpledialog.askstring("Reason","Why save? (optional)")
        for (ip, *_rest) in rows:
            add_to_saved(ip, reason or "")
        self.set_status(f"Added {len(rows)} to saved.txt")

    def add_search_selected_to_monitor(self):
        ips = self._all_selected_ips()
        if not ips:
            messagebox.showinfo("Info","Select items first.")
            return
        added, invalid, duplicates = add_ips_to_monitor_list(ips)
        self.set_status(format_monitor_feedback(added, invalid, duplicates))

    def add_search_selected_to_monitor(self):
        rows = self._search_selected_rows()
        if not rows:
            messagebox.showinfo("Info","Select items first.")
            return
        ips = [row[0] for row in rows]
        added, invalid, duplicates = add_ips_to_monitor_list(ips)
        self.set_status(format_monitor_feedback(added, invalid, duplicates))

    # ---- JSON scan-output helpers ----
    def _scan_selected_rows(self):
        out = []
        for iid in self.scan_tree.selection():
            vals = self.scan_tree.item(iid, "values")
            if vals:
                out.append(vals)
        return out

    def search_players(self):
        query_raw = self.player_search_var.get() or ""
        query = query_raw.strip().lower()
        if not query:
            self.set_status("Enter a player name to search.")
            return
        matches = []
        for iid in self.scan_tree.get_children():
            vals = self.scan_tree.item(iid, "values")
            if not vals:
                continue
            players_text = vals[-1] if vals else ""
            if isinstance(players_text, str) and query in players_text.lower():
                matches.append(iid)
        current_sel = self.scan_tree.selection()
        if current_sel:
            self.scan_tree.selection_remove(current_sel)
        if matches:
            self.scan_tree.selection_set(matches)
            self.scan_tree.focus(matches[0])
            self.scan_tree.see(matches[0])
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
        vals = list(self.scan_tree.item(iid, "values"))
        if len(vals) >= 5:
            vals[4] = text
            self.scan_tree.item(iid, values=vals)

    def _update_scan_row_whitelist(self, ip, text):
        iid = self._scan_row_map.get(ip)
        if not iid:
            return
        vals = list(self.scan_tree.item(iid, "values"))
        if len(vals) >= 6:
            vals[5] = text
            self.scan_tree.item(iid, values=vals)

    def _remove_scan_row(self, ip):
        iid = self._scan_row_map.pop(ip, None)
        if iid:
            self.scan_tree.delete(iid)

    def _scan_and_show(self, items):
        for iid in self.scan_tree.get_children():
            self.scan_tree.delete(iid)
        self.set_status("Preparing scan...")
        only_cracked = self.only_cracked_var.get()
        check_whitelist = self.check_whitelist_var.get()
        account = get_active_mc_account() if check_whitelist else None
        if check_whitelist and not account:
            messagebox.showinfo("Accounts", "Import or add a Minecraft account first.")
            self.set_status("Whitelist check canceled: no account selected.")
            return
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

                    if self.only_players_var.get() and r.get('players', 0) <= 0:
                        return
                    if only_cracked and should_skip_cracked_probe(r):
                        return
                    if not version_filter_allows(r.get("version", ""), self.version_filter_var.get()):
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
                        iid = self.scan_tree.insert("", "end", values=v)
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
                                remaining = len(self.scan_tree.get_children())
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
            messagebox.showinfo("Info","Select items first.")
            return
        self._scan_and_show(ips)

    def scan_all(self):
        if not self.search_rows:
            messagebox.showinfo("Info","Run a search first.")
            return
        ips = [row[0] for row in self.search_rows]
        self._scan_and_show(ips)

    def copy_scan_selected(self):
        rows = self._scan_selected_rows()
        if not rows:
            messagebox.showinfo("Info", "Select scan output rows.")
            return
        ips = [row[0] for row in rows]
        self.clipboard_clear()
        self.clipboard_append("\n".join(ips))
        self.set_status(f"Copied {len(ips)} IP(s) from scan output.")

    def ignore_scan_selected(self):
        rows = self._scan_selected_rows()
        if not rows:
            messagebox.showinfo("Info", "Select scan output rows.")
            return
        reason = ask_reason_with_whitelist(self, "Reason", "Why ignore? (optional)")
        if reason is None:
            self.set_status("Ignore cancelled.")
            return
        for (ip, *_rest) in rows:
            add_to_ignore(ip, reason or "")
        for iid in list(self.scan_tree.selection()):
            self.scan_tree.delete(iid)
        self.set_status(f"Added {len(rows)} to ignore.txt from scan output.")

    def save_scan_selected(self):
        rows = self._scan_selected_rows()
        if not rows:
            messagebox.showinfo("Info", "Select scan output rows.")
            return
        reason = simpledialog.askstring("Reason", "Why save? (optional)")
        for (ip, *_rest) in rows:
            add_to_saved(ip, reason or "")
        self.set_status(f"Added {len(rows)} to saved.txt from scan output.")

    def add_scan_output_selected_to_monitor(self):
        rows = self._scan_selected_rows()
        if not rows:
            messagebox.showinfo("Info", "Select scan output rows.")
            return
        ips = [row[0] for row in rows]
        added, invalid, duplicates = add_ips_to_monitor_list(ips)
        self.set_status(format_monitor_feedback(added, invalid, duplicates))

    def export_search_results(self):  #
        if not self.search_rows:
            messagebox.showinfo("Info","No search results to export.")
            return
        q = self.query_var.get().strip()
        base = sanitize_query_for_filename(q if q else "json_search")
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files","*.txt")],
            title="Export JSON Search Results",
            initialfile=f"{base}.txt"
        )
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            for (ip, motd, players, version) in self.search_rows:
                online, maximum = ("N","A")
                if "/" in players:
                    parts = players.split("/",1)
                    online, maximum = parts[0], parts[1]
                f.write(format_result_line(ip, motd, online, maximum, version) + "\n")
        self.set_status(f"Exported {len(self.search_rows)} rows to {os.path.basename(path)}")

    def export_scan_output(self):  
        rows = []
        for iid in self.scan_tree.get_children():
            vals = self.scan_tree.item(iid, "values")
            if vals:
                rows.append(vals)
        if not rows:
            messagebox.showinfo("Info","No scan output to export.")
            return
        q = self.query_var.get().strip()
        base = sanitize_query_for_filename((q if q else "json_search") + "_scan")
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files","*.txt")],
            title="Export JSON Scan Output",
            initialfile=f"{base}.txt"
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
                    online, maximum = str(players).split("/",1)
                else:
                    online, maximum = "N","A"
                f.write(format_result_line(ip, motd, online, maximum, version) + "\n")
        self.set_status(f"Exported {len(rows)} scan rows to {os.path.basename(path)}")

# ---- Export Tab ----
class ExportTab(ttk.Frame):  #
    def __init__(self, master):
        super().__init__(master)
        self._build_ui()

    def _build_ui(self):
        box = ttk.Frame(self)
        box.pack(fill="x", padx=8, pady=8)

        self.file_var = tk.StringVar()
        ttk.Entry(box, textvariable=self.file_var, width=60).pack(side="left", padx=4)
        ttk.Button(box, text="Pick .txt", command=self.pick_txt).pack(side="left", padx=4)

        self.backup_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(self, text="Backup servers.dat if no backup exists", variable=self.backup_var).pack(anchor="w", padx=8)

        btns = ttk.Frame(self)
        btns.pack(fill="x", padx=8, pady=8)
        ttk.Button(btns, text="Export to servers.dat", command=self.do_import).pack(side="left", padx=4)
        ttk.Button(btns, text="Restore Backup", command=self.restore_backup).pack(side="left", padx=4)

        self.status = tk.StringVar(value="Ready.")
        ttk.Label(self, textvariable=self.status).pack(fill="x", padx=8, pady=8)

    def set_status(self,msg):
        self.status.set(msg)

    def pick_txt(self):
        path = filedialog.askopenfilename(title="Pick .txt source", filetypes=[("Text files","*.txt")])
        if path:
            self.file_var.set(path)

    def do_import(self):
        path = self.file_var.get().strip()
        if not path:
            messagebox.showinfo("Info","Pick a .txt first.")
            return
        def work():
            ok, msg = import_file_to_servers_dat(path, do_backup=self.backup_var.get())
            self.set_status(msg if ok else f"Failed: {msg}")
        threading.Thread(target=work, daemon=True).start()
        self.set_status("Importing...")

    def restore_backup(self):
        try:
            if not os.path.exists(BACKUP_PATH):
                messagebox.showinfo("Info","No backup found.")
                return
            shutil.copyfile(BACKUP_PATH, SERVERS_DAT_PATH)
            self.set_status("Backup restored.")
        except Exception as e:
            self.set_status(f"Restore failed: {e}")

# ---- Saved / Ignore (Reason file) Tab ----
class _ReasonFileTab(ttk.Frame):
    def __init__(self, master, file_path, tab_name):
        super().__init__(master)
        self.file_path = file_path
        self.tab_name = tab_name
        self.rows = []  # list[(ip, reason)]
        self._build_ui()
        self._load()

    def _build_ui(self):
        bar = ttk.Frame(self); bar.pack(fill="x", padx=8, pady=8)
        ttk.Button(bar, text="Add", command=self._add).pack(side="left", padx=2)
        ttk.Button(bar, text="Edit", command=self._edit).pack(side="left", padx=2)
        ttk.Button(bar, text="Remove", command=self._remove).pack(side="left", padx=2)
        ttk.Button(bar, text="Copy IP(s)", command=self._copy).pack(side="left", padx=8)
        ttk.Button(bar, text="Reload", command=self._load).pack(side="left", padx=8)
        ttk.Button(bar, text="Save", command=self._save).pack(side="left", padx=2)
        if self.tab_name == "Ignore":
            ttk.Button(bar, text="Scan Entire List for Whitelist", command=self._scan_whitelist).pack(side="left", padx=12)

        mid = ttk.Frame(self); mid.pack(fill="both", expand=True, padx=8, pady=(0,8))
        cols = ("ip", "reason", "whitelist") if self.tab_name == "Ignore" else ("ip", "reason")
        self._columns = cols
        self.tree = ttk.Treeview(mid, columns=cols, show="headings", height=16, selectmode="extended")
        for c in cols:
            self.tree.heading(c, text=c.upper())
            width = 240 if c == "ip" else (240 if c == "whitelist" else 600)
            self.tree.column(c, width=width, anchor="w")
        self.tree.pack(side="left", fill="both", expand=True)
        sb = ttk.Scrollbar(mid, orient="vertical", command=self.tree.yview)
        sb.pack(side="left", fill="y")
        self.tree.config(yscrollcommand=sb.set)

        # enable sorting
        make_tree_sortable(self.tree, {
            "ip": _ip_key,
            "reason": lambda v: str(v).lower()
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
        messagebox.showinfo(self.tab_name, "Saved.")

    def _scan_whitelist(self):
        account = get_active_mc_account()
        if not account:
            messagebox.showinfo("Ignore", "Select/probe an active Minecraft account first.", parent=self)
            return
        entries = []
        for iid in self.tree.get_children(""):
            values = self.tree.item(iid, "values")
            if values and is_valid_ip_port(values[0]):
                entries.append({"ip": values[0]})
                self.tree.set(iid, "whitelist", "Queued")
        if not entries:
            self.status = tk.StringVar(value="")
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
        if hasattr(self, "_scan_status_label"):
            self._scan_status_label.configure(text=text)
        else:
            self._scan_status_label = ttk.Label(self, text=text, anchor="w")
            self._scan_status_label.pack(fill="x", padx=8, pady=(0, 8))

    def _selected_iids(self):
        return list(self.tree.selection())

    def _add(self):
        ip = simpledialog.askstring(self.tab_name, "IP:PORT")
        if not ip or not is_valid_ip_port(ip): return
        reason = simpledialog.askstring(self.tab_name, "Reason (optional)") or ""
        self.tree.insert("", "end", values=(get_ip_only(ip), reason))

    def _edit(self):
        iids = self._selected_iids()
        if not iids: return
        values = self.tree.item(iids[0], "values")
        ip, reason = values[:2]
        new_ip = simpledialog.askstring(self.tab_name, "IP:PORT", initialvalue=ip) or ip
        if not is_valid_ip_port(get_ip_only(new_ip)): return
        new_reason = simpledialog.askstring(self.tab_name, "Reason", initialvalue=reason) or ""
        values = (get_ip_only(new_ip), new_reason, values[2]) if self.tab_name == "Ignore" else (get_ip_only(new_ip), new_reason)
        self.tree.item(iids[0], values=values)

    def _remove(self):
        for iid in self._selected_iids():
            self.tree.delete(iid)

    def _copy(self):
        ips = []
        for iid in self._selected_iids():
            v = self.tree.item(iid, "values")
            if v: ips.append(v[0])
        if not ips: return
        self.clipboard_clear(); self.clipboard_append("\n".join(ips))

class SavedTab(_ReasonFileTab):
    def __init__(self, master):
        super().__init__(master, SAVED_FILE, "Saved")

class IgnoreTab(_ReasonFileTab):
    def __init__(self, master):
        super().__init__(master, IGNORE_FILE, "Ignore")

# ---- IP Log (ips.txt) Tab ----
class IpLogTab(ttk.Frame):
    def __init__(self, master):
        super().__init__(master)
        self.rows = []  # list[(ip,motd,players,version)]
        self._build_ui()
        self._load()

    def _build_ui(self):
        bar = ttk.Frame(self); bar.pack(fill="x", padx=8, pady=8)
        ttk.Button(bar, text="Add", command=self._add).pack(side="left", padx=2)
        ttk.Button(bar, text="Edit", command=self._edit).pack(side="left", padx=2)
        ttk.Button(bar, text="Remove", command=self._remove).pack(side="left", padx=2)
        ttk.Button(bar, text="Copy IP(s)", command=self._copy).pack(side="left", padx=8)
        ttk.Button(bar, text="Reload", command=self._load).pack(side="left", padx=8)
        ttk.Button(bar, text="Save", command=self._save).pack(side="left", padx=2)

        mid = ttk.Frame(self); mid.pack(fill="both", expand=True, padx=8, pady=(0,8))
        cols = ("ip","motd","players","version")
        self.tree = ttk.Treeview(mid, columns=cols, show="headings", height=16, selectmode="extended")
        for c in cols:
            self.tree.heading(c, text=c.upper())
            if c == "motd":
                width = 240
            elif c == "players":
                width = 120
            elif c == "version":
                width = 120
            else:
                width = 170
            self.tree.column(c, width=width, anchor="w")
        self.tree.pack(side="left", fill="both", expand=True)
        sb = ttk.Scrollbar(mid, orient="vertical", command=self.tree.yview)
        sb.pack(side="left", fill="y")
        self.tree.config(yscrollcommand=sb.set)

        # enable sorting
        make_tree_sortable(self.tree, {
            "ip": _ip_key,
            "motd": lambda v: str(v).lower(),
            "players": _players_key,
            "version": _version_key
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
        messagebox.showinfo("IP Log", "Saved.")

    def _selected_iids(self):
        return list(self.tree.selection())

    def _add(self):
        ip = simpledialog.askstring("IP Log", "IP:PORT")
        if not ip or not is_valid_ip_port(ip): return
        motd = simpledialog.askstring("IP Log", "MOTD (optional)") or ""
        players = simpledialog.askstring("IP Log", "Players (e.g. 0/20 or N/A)", initialvalue="N/A") or "N/A"
        version = simpledialog.askstring("IP Log", "Version (optional)") or "N/A"
        self.tree.insert("", "end", values=(get_ip_only(ip), motd, players, version))

    def _edit(self):
        iids = self._selected_iids()
        if not iids: return
        ip, motd, players, version = self.tree.item(iids[0], "values")
        new_ip = simpledialog.askstring("IP Log", "IP:PORT", initialvalue=ip) or ip
        if not is_valid_ip_port(get_ip_only(new_ip)): return
        motd = simpledialog.askstring("IP Log", "MOTD", initialvalue=motd) or ""
        players = simpledialog.askstring("IP Log", "Players", initialvalue=players) or players
        version = simpledialog.askstring("IP Log", "Version", initialvalue=version) or version
        self.tree.item(iids[0], values=(get_ip_only(new_ip), motd, players, version))

    def _remove(self):
        for iid in self._selected_iids():
            self.tree.delete(iid)

    def _copy(self):
        ips = []
        for iid in self._selected_iids():
            v = self.tree.item(iid, "values")
            if v: ips.append(v[0])
        if not ips: return
        self.clipboard_clear(); self.clipboard_append("\n".join(ips))


class UserLogTab(ttk.Frame):
    def __init__(self, master):
        super().__init__(master)
        self._manager = None
        self._refresh_pending = False
        self._cached_entries = []
        self._build_ui()

    def _build_ui(self):
        bar = ttk.Frame(self); bar.pack(fill="x", padx=8, pady=8)
        ttk.Button(bar, text="Copy Player(s)", command=self.copy_players).pack(side="left", padx=2)
        ttk.Button(bar, text="Copy IP(s)", command=self.copy_ips).pack(side="left", padx=2)
        ttk.Button(bar, text="Export Log…", command=self.export_log).pack(side="left", padx=8)
        self.user_search_var = tk.StringVar()
        ttk.Entry(bar, textvariable=self.user_search_var, width=20).pack(side="left", padx=(4,4))
        ttk.Button(bar, text="Search Player", command=self.search_player_log).pack(side="left", padx=4)
        ttk.Button(bar, text="Clear Search", command=self.clear_player_log_search).pack(side="left", padx=4)

        mid = ttk.Frame(self); mid.pack(fill="both", expand=True, padx=8, pady=(0,8))
        cols = ("player", "ip", "motd", "last_seen")
        self.tree = ttk.Treeview(mid, columns=cols, show="headings", height=18, selectmode="extended")
        for c in cols:
            self.tree.heading(c, text=c.upper())
            if c == "motd":
                width = 360
            elif c == "ip":
                width = 170
            elif c == "last_seen":
                width = 170
            else:
                width = 200
            self.tree.column(c, width=width, anchor="w")
        self.tree.pack(side="left", fill="both", expand=True)
        sb = ttk.Scrollbar(mid, orient="vertical", command=self.tree.yview)
        sb.pack(side="left", fill="y")
        self.tree.config(yscrollcommand=sb.set)

        make_tree_sortable(self.tree, {
            "player": lambda v: str(v).lower(),
            "ip": _ip_key,
            "motd": lambda v: str(v).lower(),
            "last_seen": lambda v: str(v)
        })

        self.status = tk.StringVar(value="Ready.")
        ttk.Label(self, textvariable=self.status, anchor="w").pack(fill="x", padx=8, pady=(0,8))

    def bind_manager(self, manager: UserLogManager):
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
        self.status.set(f"Tracking {len(entries)} player(s).")
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
                    self._format_last_seen(entry["last_seen"])
                )
            )

    def search_player_log(self):
        query = (self.user_search_var.get() or "").strip().lower()
        if not query:
            self.set_status("Enter a player name to search.")
            return
        matches = [
            entry for entry in self._cached_entries
            if query in (entry.get("player") or "").lower()
        ]
        self._populate_user_tree(matches)
        self.set_status(f"{len(matches)} match(es) for '{self.user_search_var.get().strip()}'.")

    def clear_player_log_search(self):
        self.user_search_var.set("")
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
            messagebox.showinfo("User Log", "Select one or more rows.")
            return
        players = [row[0] for row in rows]
        self.clipboard_clear()
        self.clipboard_append("\n".join(players))
        self.status.set(f"Copied {len(players)} player(s).")

    def copy_ips(self):
        rows = self._selected_rows()
        if not rows:
            messagebox.showinfo("User Log", "Select one or more rows.")
            return
        ips = [row[1] for row in rows]
        self.clipboard_clear()
        self.clipboard_append("\n".join(ips))
        self.status.set(f"Copied {len(ips)} IP(s).")

    def export_log(self):
        if not self._cached_entries:
            messagebox.showinfo("User Log", "Nothing to export yet.")
            return
        path = filedialog.asksaveasfilename(
            title="Export User Log",
            defaultextension=".txt",
            filetypes=[("Text files","*.txt")]
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                for entry in self._cached_entries:
                    ts = self._format_last_seen(entry["last_seen"])
                    motd = sanitize_motd(entry["motd"])
                    f.write(f"{entry['player']} | {entry['ip']} | Last Seen: {ts} | MOTD: {motd}\n")
            self.status.set(f"Exported {len(self._cached_entries)} player(s) to {os.path.basename(path)}.")
        except Exception as e:
            self.status.set(f"Export failed: {e}")
            messagebox.showerror("User Log", f"Export failed: {e}")



def main():  #gone but not forgotten
    pass

# ==================== GUI Entry ====================

if __name__ == "__main__":  #
    app = FullAppGUI()
    app.mainloop()
