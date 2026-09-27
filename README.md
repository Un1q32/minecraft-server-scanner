# Minecraft Server Scanner

![Screenshot](https://i.imgur.com/NCpx7u0.png)

Minecraft Server Scanner is a Windows desktop application that discovers, checks, organizes, and exports Minecraft servers through a Tkinter GUI.

## Features

### Server discovery and scanning

- Searches Shodan for Minecraft servers with a Shodan API key.
- Loads local Shodan JSON and JSONL files.
- Searches JSON data with boolean expressions using AND, OR, NOT, and parentheses.
- Loads server lists from text files.
- Scans individual servers or complete result sets concurrently.
- Shows server icons, MOTD, online players, maximum players, version, and sampled player names.
- Filters scan results by player count.
- Filters versions with an editable substring search, such as 26.3.
- Sorts result tables by IP, players, version, MOTD, whitelist status, and other displayed fields.
- Exports server results in a consistent text format.

### Network Scan

The Network Scan tab accepts individual IPv4 addresses, CIDR ranges, explicit IPv4 ranges such as 192.0.2.1-192.0.2.20, and ASNs such as AS13335 or 13335.

ASN scanning resolves announced IPv4 prefixes through BGPView, expands the prefixes within the configured host limit, and scans the configured ports. The scan supports multiple ports and protects the application with a maximum-host limit.

### Whitelist verification

- Checks whitelist access with an authenticated Minecraft account.
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
- Sets an active account for manual whitelist checks.
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

- Maintains Saved and Ignore lists with optional reasons.
- Filters ignored servers from scan workflows.
- Maintains a global IP Log in the IP Log tab.
- Maintains a player log with each player’s latest known server.
- Copies selected IPs and exports selected result sets.

Network Scan results remain in the scan result table unless they are explicitly added to another list. A network scan does not automatically write every result to ips.txt.

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
- Servers: loads, scans, filters, checks, and exports text server lists.
- Shodan: searches Shodan and scans search results.
- JSON Search: searches local Shodan JSON or JSONL data and scans matches.
- Server Monitor: monitors saved servers and records player activity.
- Export to MC: writes text lists to Minecraft’s servers.dat.
- Saved: manages saved servers.
- Ignore: manages ignored servers and scans the complete list for whitelist status.
- IP Log: manages the global ips.txt server log.
- Player Log: searches and exports discovered player records.

## Requirements

- Windows.
- Python 3.10 or newer.
- A valid Shodan API key for Shodan searches.
- The cryptography package for authenticated whitelist probes.
- Network access for Shodan, Minecraft status probes, account services, and ASN prefix lookup.

## Running the application

Run:

    python MC_Scanner.py

The application stores its working files in the current working directory unless a path uses %APPDATA% explicitly.

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
- Whitelist probing uses authenticated accounts and can rotate accounts and proxies when those options are enabled.
