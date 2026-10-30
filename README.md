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
    python mcscan.py --recheck-whitelist 1.2.3.4:25565  # probe whitelist status

Useful flags: `--backend {auto,masscan,minescan,python}` (default `auto`,
masscan first like the GUI), `--ports 25565,25566`, `--rate`, `--wait`,
`--max-hosts`. Discovery only (status ping + player sample), except
`--recheck-whitelist`, which runs the same login probes as the GUI's
Check Whitelist button. Cracked login probes stay in the GUI. Like the
GUI, masscan needs
raw-socket privileges: run as root, rely on passwordless sudo for the
automatic retry, or pick another backend. Ctrl-C stops a running scan
and keeps results found so far — it abandons queued probes rather than
waiting for them, skips the end-of-scan sync, and a second Ctrl-C forces
an immediate exit. The GUI behaves the same (closing the window also
stops in-flight scans).

#### Continuous mode

    python mcscan.py --continuous

Runs forever and picks what to scan next from what has been paying off
(matscan-inspired). Each round alternates **normal** and **rescan**:

Normal rounds choose one strategy, weighted by history:

| strategy | targets |
| --- | --- |
| `slash0` | whole IPv4 space on the configured ports (default 25565; time-boxed, masscan's random order) |
| `slash16a` | `/16`s around servers seen in the last 30 days |
| `slash16b` | `/16`s with ≥ 32 known IPs (busy subnets, last 365 days) |
| `slash24a` | `/24`s around servers seen in the last 365 days |
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
addresses. `--ports` (e.g. `--ports 25565,25566,25600-25610`) sets the
ports used by the broad `slash0`, `slash16a`, `slash16b` and `slash24a`
strategies; `slash24b`/`slash24c` keep their fixed nearby-port sets and
the `slash32*` strategies still sweep every port on known IPs. Rescans
always use each server's stored port. While a round runs, a status line at the bottom of the terminal
counts servers found so far in that round — `new`, `updated` and total
hits — and is rewritten in place as results arrive (when output is piped
it prints a plain summary line every 15 seconds instead). The shared DB is
synced every `--sync-every` seconds (default 300) and once more on exit, so
peers see new finds promptly.

`--strategies slash24a,slash32b` restricts the pool, `--no-rescan` skips
the rescan half, and `--rounds N` stops after N rounds (useful for
testing). The deep-port strategies need masscan and root; without them the
Python backend skips rounds whose probe count exceeds its cap.

#### Running several machines

Continuous mode is deterministic where it matters (ranges come from the
DB, and the best-scoring strategy wins), so independent machines would
otherwise overlap — especially at bootstrap, where every fresh DB picks
`slash0` and sweeps the same address space. Give each machine a distinct
slice instead:

    mcscan.py --continuous --shard 1/3     # machine 1
    mcscan.py --continuous --shard 2/3     # machine 2
    mcscan.py --continuous --shard 3/3     # machine 3

masscan divides the space itself (`--shard I/N`), and all machines must
shuffle from the same seed or their shards will drift into each other, so
sharding passes a fixed `--seed` (`--scan-seed` to override; use the same
value everywhere). The Python backend, which has no native sharding, takes
every Nth expanded target instead. Strategy ties are also broken randomly
per machine, so hosts with similar histories diversify over time.

Do not mix shard counts mid-run: a machine at `1/3` and one at `1/2` are
not disjoint.

`exclude.conf` applies to every round, to both halves: strategy ranges and
rescan targets (including padded /20s) are carved before any backend runs,
and masscan additionally receives them as an `--excludefile`. The round
header reports how many specs that removed, and edits to the file apply to
the next round without a restart.

## Rust DB viewer (`dbviewer`)

The Python GUI builds a widget per server, which becomes slow once the
shared DB has tens of thousands of rows. `dbviewer/` is a small Rust + Qt 6
(QML) application that only views `servers.db`: it opens the database
read-only, exposes the rows through a `QAbstractTableModel`, and lets Qt's
`TableView` ask for just the visible cells. Scanning is not implemented
there, but **Sync DB** runs `mcscan.py --sync` and **Recheck whitelist**
runs the same probes as the GUI for the selected rows.

On a 113k-row database, the release build opens the whole table in about
80–110 ms; searches take 45–90 ms and sorting is in memory (a few ms to
about 45 ms).

### Build and run

Requirements: a Rust toolchain, Qt 6.5 or newer (Quick and Quick Controls 2),
CMake, and `qmake`/`qmake6` on `PATH`. CXX-Qt handles Linux, Windows and macOS; there is
no platform-specific code beyond suppressing the console window on Windows.

    cd dbviewer
    cargo build --release
    ./target/release/dbviewer [servers.db]

    dbviewer --db servers.db --query "players>=10" --sort last_seen:desc

Command-line options:

- `--db PATH` (or a bare path) — database to open; defaults to
  `servers.db` in the current directory. A directory works too.
- `--query EXPR` — initial search expression.
- `--sort COL[:asc|desc]` — initial sort (`ip_port`, `motd`, `players`,
  `version`, `cracked`, `whitelist`, `first_seen`, `last_seen`,
  `times_seen`). The direction defaults to ascending.

You can also drag a `.db` file onto the window, or use **Open DB…** (Ctrl+O).
The table follows the desktop's Qt palette (light or dark). Columns use the
native Qt table header: drag the divider between headers to resize them. The
vertical scrollbar has its own column beside the table and the horizontal one
its own strip below it, so both are easy to grab (and clicking anywhere on a
bar jumps that way). The columns match
the Python Servers tab — IP, MOTD, PLAYERS, VERSION, CRACKED, WHITELIST,
ONLINE NAMES, SEEN NAMES, FIRST SEEN, LAST SEEN and TIMES SEEN. Clicking a
header sorts with the same keys and direction as the Python GUI: the first
click ascending, the next descending, with versions compared numerically
(`1.9 < 1.21.1 < 1.21.10`), IPs as octets, and timestamps by displayed
minute. Clicks stack: the last-clicked column is the primary sort and
earlier columns break ties (sorting by version and then whitelist keeps the
version order inside each whitelist group). A sync/recheck reload re-applies
the whole stack, not just the last column.

### Searching

Type in the search box; results update as you type (Enter searches
immediately, Esc clears). Terms combine with AND. A bare word searches IP,
MOTD, version, whitelist and sampled player names.

    anarchy                  anywhere in the text fields
    motd:"anarchy server"    field contains text (quotes keep spaces)
    ip:1.2.3.                IP/port prefix
    version~1.21             contains
    cracked=yes              status text (matches cached/heuristic too)
    whitelist=yes|no|unknown whitelist status
    players>=10  max<100     numeric compare
    seen<7d  first>30d       time windows with s/m/h/d/w suffix
    names:Notch              player seen on the server
    -motd:test               exclude a term
    times>3 players:0        multiple terms AND together

Every value is bound as a SQL parameter and every field name comes from a
whitelist, so search input cannot change the query shape.

### Sync

**Sync DB** runs `<python> mcscan.py --sync` in the database's directory
(where `netdb.json` lives). The log dialog opens automatically only if the
command is still running after 10 seconds or exits non-zero; a quick
successful sync stays quiet and its output is available from the **Log**
button. The viewer reloads the current query when the sync finishes and
re-applies the active sort, so changed rows move into their new positions.
`mcscan.py` is
looked for next to the database, one directory up, then in the working
directory; the interpreter is `python3` (`python` on Windows), or whatever
`DBVIEWER_PYTHON` names:

    DBVIEWER_PYTHON=py dbviewer          # Windows launcher, if needed

### Recheck whitelist

Select one or more rows and click **Recheck whitelist** (click, Ctrl-click
or Shift-click to select). The viewer runs

    <python> mcscan.py --recheck-whitelist IP:PORT ...

in the database's directory and reloads the table when it finishes. Its log
follows the same rule: the dialog appears only for a job still running after
10 seconds or one that exits non-zero, and the table reloads and re-applies
the active sort when it ends (e.g. a freshly checked whitelist row moves into
place). The same row selection feeds
**Copy IP(s)**, which puts the selected `IP:PORT` values on the clipboard,
one per line. Offline-mode servers are
answered without an account; online-mode probes rotate the accounts stored
in `mc_accounts.json`, exactly like the GUI's Check Whitelist button.

## Web DB viewer (`webui`)

A browser UI for the same `servers.db`, for when you want the table without
launching Qt. It is read-only: there is no Open DB picker, no whitelist
recheck, and no scan/sync action. **Refresh** just reloads `servers.db` from
disk, so it picks up changes written by a scanner running elsewhere. The 11
columns, numeric version/IP sorting, stacked sort keys, search language,
detail pane and Copy IP(s) all match the Rust viewer.

    python webui/webui.py
    python webui/webui.py --db /path/to/servers.db --port 8080
    python webui/webui.py --no-browser

It binds to `127.0.0.1` by default. The Python server takes a consistent
SQLite snapshot (including the WAL) and serves it; the page loads that
snapshot into `webui/static/core.wasm`, a small Emscripten/SQLite build, so
filtering, sorting and formatting run in the browser. A 120k-row database
opens in roughly 100-170 ms and sorts in roughly 60-110 ms on a desktop.
The table is virtualized: only the visible rows are drawn, so scrolling
stays smooth. Drag the divider on the right edge of a header to resize a
column; widths persist in the browser.

`--ports`, scanning and the continuous loop are not part of this UI.
**Refresh** re-fetches the current database snapshot and re-applies the
active query and sort. It never starts a scan or a sync.

The generated WASM is committed. Rebuild it after changing `webui/core.cpp`
with Emscripten installed:

    ./webui/build.sh

The build compiles the SQLite 3.54.0 amalgamation directly (downloaded into
`webui/.sqlite/`), rather than using Emscripten's port manager, so it also
works when Emscripten has a frozen cache.

### Hosting with nginx

Run the app on loopback and let nginx terminate TLS and proxy requests:

    python webui/webui.py --host 127.0.0.1 --port 8080 --no-browser

`webui/nginx.conf.example` is a complete reverse-proxy site (HTTP redirect,
TLS, and streaming for the database snapshot). `webui/mc-webui.service.example`
is the matching systemd unit. Basic outline:

    sudo cp webui/nginx.conf.example /etc/nginx/sites-available/mc-webui
    sudo ln -s /etc/nginx/sites-available/mc-webui /etc/nginx/sites-enabled/
    sudo certbot --nginx -d db.example.com
    sudo nginx -t && sudo systemctl reload nginx

Use a dedicated hostname (the page fetches `/core.js`, `/servers.db` and
`/api/*` from the site root). The app has no authentication; keep the Python
server bound to `127.0.0.1` and, if the hostname is reachable beyond a trusted
LAN, add your own access control in nginx (Basic auth or `allow`/`deny`).
The database snapshot is about 30 MB, so `proxy_buffering off` keeps the first
load responsive.

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
