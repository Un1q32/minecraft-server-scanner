# Minecraft Server Scanner

![Screenshot](https://i.imgur.com/NCpx7u0.png)

Minecraft Server Scanner is a Windows desktop application that discovers, checks, organizes, and exports Minecraft servers through a Qt (PySide6) GUI.

## Features

### Server discovery and scanning

- Searches Shodan for Minecraft servers with a Shodan API key.
- Loads local Shodan JSON and JSONL files.
- Searches JSON data with boolean expressions using AND, OR, NOT, and parentheses.
- Loads server lists from text files.
- Scans individual servers or complete result sets concurrently.
- The Stop button cancels a running Network Scan (a new scan cancels the old one); results found so far are kept.
- Shows server icons, MOTD, online players, maximum players, version, and sampled player names.
- Filters scan results by player count.
- Filters versions with an editable substring search, such as 26.3.
- Sorts result tables by IP, players, version, MOTD, whitelist status, and other displayed fields.
- Exports server results in a consistent text format.

### Network Scan

The Network Scan tab accepts individual IPv4 addresses, CIDR ranges, explicit IPv4 ranges such as 192.0.2.1-192.0.2.20, and ASNs such as AS13335 or 13335 — any mix of them, separated by commas, spaces, semicolons or newlines (spaced ranges like `192.0.2.1 - 192.0.2.20` work too). Every range is swept; the masscan backend passes them all through natively while the Python backend enumerates them within the Max hosts cap.

Anything listed in `exclude.conf` (same folder as the scanner) is carved out of every search on every backend: searching `1.0.0.0/8` while `1.5.0.0/16` is excluded sweeps the `/8` minus that `/16`, and `0.0.0.0/0` searches skip all of it. Entries may be CIDRs (short form like `165.160/16` works), `start-end` ranges, or single IPs, with `#` comments. The file is re-read whenever it changes, so edits apply without restarting; the status line shows how many entries are loaded.

ASN scanning resolves announced IPv4 prefixes through BGPView, expands the prefixes within the configured host limit, and scans the configured ports. The scan supports multiple ports and protects the application with a maximum-host limit.

#### masscan backend (fast)

The Backend selector controls port discovery:

- `Auto (masscan → minescan → Python)` (default): masscan SYN discovery
  when the binary is available (plus the Minecraft handshake only on open
  ports), otherwise the minescan (webscan) async backend when its binary is
  available — unprivileged, no sudo needed — otherwise pure Python.
  Falls back down the chain when a helper is missing or fails.
- `minescan (unprivileged async)`: requires the webscan binary and fails
  clearly when it is missing instead of falling back.
- `masscan (fast SYN + handshake)`: requires masscan and fails clearly when it is missing or unprivileged instead of falling back.
- `Python (handshake only)`: original ThreadPool handshake scan, no helpers.

The minescan backend is the companion Rust `webscan` scanner: drop the built
binary next to `scanner.py` (as `webscan`), build it with
`cargo build --release` from the webscan source (binary:
`target/release/webscan`), or point `WEBSCAN_BIN` at it. Targets (IPs, CIDRs,
ASN prefixes) stream to it natively; hits arrive with MOTD/players/version
already known, so no second handshake pool is needed. It scans at a
deliberate 500 concurrent connections with 1 retry per host (tunable via
`MINESCAN_CONCURRENCY` / `MINESCAN_RETRIES` in scanner.py) — slower than
masscan's raw-socket sweep, but reliable on home routers and shared links.

The `MS rate` box caps minescan handshakes/sec (default 200). Keep it low:
a burst of full handshakes trips target-side flood protection and the
affected servers get missed entirely (a /24 at 10k/s earned a minutes-long
block in testing). Unlike masscan's SYN rate, this counts complete TCP +
Minecraft handshakes from your IP, so the two boxes are not comparable.
where 10k-wide blasts lose hosts to connection-table overflow.

Phase 1 (masscan) passes CIDR/range/ASN prefixes directly to masscan (`-p <ports> --open --rate <pps> --wait <s> --interactive -oL -`), so large ranges do not need per-host Python expansion. `--interactive` makes masscan print and flush one `Discovered open port ...` line per hit, which the scanner reads live from masscan's stdout pipe — each open port is handed to the Minecraft handshake pool immediately and rows appear in the table as hosts are discovered and verified, not batched at the end. (masscan's `-oL` file output is libc-buffered and only lands in chunks, which is why file-tailing can't stream; the interactive stream is flushed per result. `-oL -` list lines on the same pipe act as backup, and very old masscan builds without `--interactive` fall back to parsing those.) Everything flows through pipes — no temp files — so privileged and unprivileged runs can't disagree over output files. While the sweep runs, the status bar shows live progress from masscan's own stats (`masscan: 42% @ 9.83kpps | 12 open | handshake: 40 | Minecraft: 3`). Tune packets-per-second with Rate and post-scan wait with Wait. The kill-timeout scales with the sweep size (hosts × ports ÷ rate + wait + margin — a /8 at 10kpps gets ~30min, not a fixed cutoff), and the starting status shows the estimate (`masscan: discovering open ports (live) (~28 min)...`). If the timeout still hits first, results found so far are kept and the status says the results are partial. masscan needs raw-socket privileges: run as root/Administrator (Linux: `sudo`, Windows: admin + Npcap). Without privileges the Auto backend falls back to Python automatically.

When masscan reports insufficient privileges and `sudo` is available (Linux/macOS), the scanner first tries passwordless sudo (`sudo -n true`, which also succeeds when credentials are cached) and otherwise prompts for the sudo password in a popup, then reruns discovery as `sudo -S masscan ...`. The password is fed once through a pipe, kept only in memory for that scan, and never written to disk. Canceling the prompt aborts the masscan backend (strict mode) or falls back to Python (Auto mode).

#### Cracked column

The result table has a CRACKED column. Every handshake already detects likely offline-mode servers (a sampled player's UUID matching the offline-mode UUID for its name), so rows show `Yes`/`No` immediately. Tick `Check cracked` before scanning to login-probe each found server for confirmation (`Yes`, `No`, `Unknown`; previously seen servers show `Yes (cached)` from `known_cracked_servers.json`). The `Check Cracked` button probes only the selected rows. The column is sortable.

### Whitelist verification

- Checks whitelist access with your stored Minecraft accounts.
- Distributes whitelist probes across all accounts in rotation (no active account).
- Uses the server’s detected protocol for each whitelist login probe.
- Provides a Check Whitelist action below result tables for selected rows.
- Supports whitelist checks during normal scans.
- Scans the entire Ignore list for whitelist status.
- Records whitelist probes in whitelist_scan.log.
- Displays whitelist, not-whitelisted, unknown, authentication, timeout, and protocol-mismatch results.

### Minecraft accounts and tokens

- Imports Prism Launcher accounts.
- Imports Minecraft access tokens and Microsoft refresh tokens.
- Accepts USERNAME:TOKEN lines.
- Accepts username-prefixed MSA refresh-token lines and standalone MSA refresh-token lines.
- Accepts JWT-style Minecraft access tokens when the token contains a Minecraft profile.
- Tests selected accounts or all stored accounts.
- Resolves account names and UUIDs from valid access tokens.
- Refreshes Microsoft accounts when refresh-token data is available.
- Removes failed accounts.

### Proxy management

- Imports HTTP and authenticated SOCKS5 proxies from text or files.
- Tests all proxies or only selected proxies.
- Saves proxy state in proxies.json.
- Routes whitelist probes through working proxies when proxy mode is enabled.
- Rotates accounts and proxies during bulk whitelist scans.
- Configures worker counts for bulk scans.
- Performs an optional initial status scan through the local connection or one selected proxy.

### Server classification

- Detects likely cracked or offline-mode servers through status data and optional login probing.
- Caches cracked-server results in known_cracked_servers.json.
- Supports cracked-server filtering in applicable result workflows.

### Lists and logs

- Keeps a local SQLite history (`servers.db`) of every server ever seen via a
  successful status ping, with first-discovery and last-seen dates plus
  times-seen count. Every scan records automatically — no manual add step.
  Bogons (loopback, private LAN, etc.) are never stored: they scan and
  display normally, but local test servers don't belong in history (or in
  other people's databases via sync).
- Each server also keeps two player-name lists from status-ping samples:
  players online now (latest sample) and everyone ever seen (union of all
  samples, kept after logout, capped at 500 names per server).
- The Servers tab browses that history (search, rescan, copy, export, add to
  Saved/Ignore/Monitor, delete). Search also matches player names, so you
  can find every server a player has been seen on.
- The Servers tab can sync that history with a shared network DB
  (`dbserver.py`): one Sync DB button uploads your new sightings and
  downloads other clients' servers, refreshing last-seen dates both ways.
- Maintains Saved and Ignore lists with optional reasons.
- Filters ignored servers from scan workflows.
- Maintains a player log with each player’s latest known server.
- Copies selected IPs and exports selected result sets.

### Server Monitor

- Monitors selected servers on a recurring interval.
- Records online status, MOTD, version, player counts, and player names.
- Stores monitor state in server_monitor_log.json.

### Minecraft server-list export

- Imports a text server list into %APPDATA%\.minecraft\servers.dat.
- Creates %APPDATA%\.minecraft\servers.dat.bak before the first export when a backup does not already exist.
- Restores the backup through the Export to MC tab.

## Tabs

- Accounts: imports, tests, activates, and removes Minecraft accounts and tokens.
- Network Scan: scans IPs, ranges, CIDRs, and ASNs across selected ports.
- Proxies: manages proxies and runs bulk whitelist scans.
- Servers: browses the automatic servers.db history (first/last seen).
- JSON Search: searches local Shodan JSON or JSONL data and scans matches.
- Server Monitor: monitors saved servers and records player activity.
- Export to MC: writes text lists to Minecraft’s servers.dat.
- Saved: manages saved servers.
- Ignore: manages ignored servers and scans the complete list for whitelist status.
- Player Log: searches and exports discovered player records.
- Shodan: searches Shodan and scans search results (needs the optional shodan package).

## Shared network DB (`dbserver.py`)

Multiple scanner clients can pool their finds through one central server:

1. On a machine you can port-forward, run:

       python3 dbserver.py --port 8777

   The first run prints a random shared token (saved as `.dbserver_token`,
   mode 0600). Forward TCP 8777 to that machine.
2. In every client's Servers tab, paste the server URL
   (e.g. `http://your-host:8777`) and the token into the Shared DB row,
   then press **Sync DB**. That is the whole setup.

Each sync uploads the servers this client has seen since its last sync and
downloads everything other clients added, merging first-seen (oldest wins)
and last-seen/MOTD/players/version (newest wins) on both sides. Player lists
merge too: currently-online follows the newer sighting, ever-seen is the
union of both sides. A confirmed
cracked verdict is never downgraded by a re-sight.

Security: every `/api/*` endpoint requires auth — unauthenticated reads and
writes get 401 and reveal nothing. Clients sign requests with HMAC-SHA256
(the token itself never travels on the wire; plain `Bearer` is also accepted
for curl debugging), nonces are single-use, timestamps must be within
±5 minutes, and 5 bad logins from one IP earns a 1-minute throttle (HTTP 429).
Traffic is plain HTTP so setup stays trivial; pass `--tls-cert/--tls-key`
(or run behind Caddy/nginx/Tailscale) if your list is sensitive.

## Requirements

- Windows.
- Python 3.10 or newer.
- PySide6 for the Qt GUI (`pip install PySide6`).
- A valid Shodan API key for Shodan searches (optional; the shodan package itself is optional too — `pip install shodan` only if you use that tab).
- The cryptography package for authenticated whitelist probes.
- Network access for Shodan, Minecraft status probes, account services, and ASN prefix lookup.
- Optional: masscan for fast Network Scan discovery (requires root/Administrator + Npcap on Windows). Without it, the scanner falls back to the Python backend.

## Running the application

Run:

    python scanner.py

The application stores its working files in the current working directory unless a path uses %APPDATA% explicitly.

## Headless CLI (`mcscan.py`)

The same scanning/DB/sync code with no Qt dependency, for headless
servers — `import scanner` falls back to inert UI stubs when PySide6 is
absent, and every CLI path below avoids them. Target syntax is identical
to the GUI's Network Scan box (IPs, CIDRs, `start-end` ranges, ASNs,
hostnames). Run it from the same working directory as the GUI so it
shares `servers.db`, `netdb.json`, `exclude.conf`, and `ignore.txt`:

    python mcscan.py --init-db URL TOKEN    # save shared-DB creds to netdb.json
    python mcscan.py --sync                  # sync shared DB (netdb.json creds)
    python mcscan.py --scan 1.0.0.0/8 AS13335  # scan, print hits live, then sync
    python mcscan.py --export out.csv        # dump the full local DB as CSV
    python mcscan.py --continuous            # self-tuning forever scan

Useful flags: `--backend {auto,masscan,minescan,python}` (default `auto`,
masscan first like the GUI), `--ports 25565,25566`, `--rate`, `--wait`,
`--max-hosts`. Discovery only (status ping + player sample) — whitelist
and cracked login probes stay in the GUI. Like the GUI, masscan needs
raw-socket privileges: run as root, rely on passwordless sudo for the
automatic retry, or pick another backend. Ctrl-C stops a running scan
and keeps results found so far.

#### Continuous mode

    python mcscan.py --continuous

Runs forever and picks what to scan next from what has been paying off
(matscan-inspired). Each round alternates **normal** and **rescan**:

Normal rounds choose one strategy, weighted by history:

| strategy | targets |
| --- | --- |
| `slash0` | whole IPv4 space on 25565 (time-boxed, masscan's random order) |
| `slash16a` | `/16`s around servers seen in the last 30 days |
| `slash16b` | `/16`s with ≥ 32 known IPs (busy subnets, last 365 days) |
| `slash24a` | `/24`s around servers seen in the last 365 days, port 25565 |
| `slash24b` | the same `/24`s on 25566-25568 |
| `slash24c` | the same `/24`s on 25560-25564 and 25569-25570 |
| `slash32a` | known IPs (last 30 days) on every port 1024-65535 |
| `slash32b` | known IPs (last 365 days) on every port 1024-65535 |
| `slash32c` | IPs hosting ≥ 8 servers, on every port 1024-65535 |

After each normal round the strategy is scored as new servers per hour,
`(new + 5×new_on_25565 + 0.1×revived) × 3600 / (seconds + 30)` — finds on
the default port count 5× (they last longer), a server unseen for a week
that answers again counts 0.1×. Scores persist in `strategies.json`
(`--state-file`); 90% of rounds take the best strategy, 10% explore a
random one, and untried strategies go first so the empty case bootstraps
with `slash0`.

Rescan rounds revisit servers by age: last pinged 2h-1d, 1-7d, 7-30d,
30-365d, or over a year ago, plus one fast tier (every 10 minutes) for
servers that currently have players online. Older-with-25565 hosts are
diluted into their `/20` so a rescan doesn't burst at known addresses.

Every scan is time-boxed by `--scan-duration` (default 300s), so `slash0`
sweeps a random slice of the internet rather than all four billion
addresses. While a round runs, a status line at the bottom of the terminal
counts servers found so far in that round — `new`, `updated` and total
hits — and is rewritten in place as results arrive (when output is piped
it prints a plain summary line every 15 seconds instead). The shared DB is
synced every `--sync-every` seconds (default 300) and once more on exit, so
peers see new finds promptly.

`--strategies slash24a,slash32b` restricts the pool, `--no-rescan` skips
the rescan half, and `--rounds N` stops after N rounds (useful for
testing). The deep-port strategies need masscan and root; without them the
Python backend skips rounds whose probe count exceeds its cap.

## Text format

The standard exported server line is:

    IP:PORT | MOTD: text | Players: online/maximum | Version: version

The importer accepts this format and common IP:PORT lines.

## JSON search

JSON Search matches common Shodan fields including IP, port, data, Minecraft metadata, location, hostnames, and version values.

Example:

    java AND (version.1.21 OR version.1.20) AND (survival OR anarchy)

## Notes

- Shodan searches follow Shodan API limits and terms.
- Minecraft servers can reject status or login probes, throttle connections, require a different protocol, or return incomplete metadata.
- ASN expansion depends on the external BGPView API and the configured host limit.
- Whitelist probing rotates across all stored accounts, and can rotate proxies too when proxy mode is enabled.
