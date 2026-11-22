# UniFi-ready IP blocklists

Well-known public IP blocklists, mirrored in a clean format that UniFi
Network 11 "Network Lists" (Source: Dynamic) can import directly. A GitHub
Actions job re-fetches every source every 6 hours and commits the result.

**The data is not mine.** Every list belongs to its upstream project and stays
under that project's terms. See [`lists/NOTICE.md`](lists/NOTICE.md) for the
owner, licence and unmodified copyright header of each list. Only the scripts
in this repository are covered by [`LICENSE`](LICENSE).

## URLs

```
https://raw.githubusercontent.com/lucacanonica/unifi-blocklist-mirror/main/lists/combined_v4.txt
```

| File | Content |
| --- | --- |
| `combined_v4.txt` | All sources marked "combined", merged and de-duplicated |
| `<source>_v4.txt` | One source on its own |
| `*_v6.txt` | IPv6, only where the source publishes IPv6 |
| `*_cidr.txt` | Same data, every entry with a prefix (hosts as `/32` or `/128`) |
| `*_partN.txt` | Only created if a list exceeds 100,000 entries |

Two formats per list:

- **without `_cidr`** - single addresses bare (`1.2.3.4`), networks with a
  prefix (`1.2.3.0/24`). Use this one in UniFi.
- **with `_cidr`** - every line has a prefix (`1.2.3.4/32`). For firewalls
  that want pure CIDR input (nftables, pfSense, OPNsense, MikroTik).

## Sources

| ID | Source | In combined | Licence (short) |
| --- | --- | --- | --- |
| `spamhaus_drop` | Spamhaus DROP | yes | Spamhaus DROP Fair Use Policy |
| `firehol_level1` | FireHOL Level 1 | yes | see included feeds |
| `dshield` | DShield Recommended Block List | yes | CC BY-NC-SA 2.5 |
| `feodo_tracker` | abuse.ch Feodo Tracker | yes | CC0 |
| `emerging_threats` | Emerging Threats Block IPs | yes | BSD-style |
| `ipsum_level2` | IPsum, level 2 | yes | Unlicense |
| `tor_exit` | Tor exit nodes | no | see upstream |
| `blocklist_de` | blocklist.de (all) | disabled | see upstream |
| `cins_army` | CINS Army | disabled | see upstream |

Each list remains under its upstream's terms, which are linked in
[`lists/NOTICE.md`](lists/NOTICE.md).

## What the clean-up does

- removes comments and extra columns, one entry per line
- merges duplicates and overlapping networks
- removes private and reserved ranges (`10.0.0.0/8`, `192.168.0.0/16`, ...),
  which FireHOL Level 1 includes on purpose and which would lock you out of
  your own LAN
- ignores anything wider than `/8` (IPv4) or `/16` (IPv6)
- keeps the last good version of a list if its upstream is unreachable

## Configuration

Edit [`sources.json`](sources.json): `enabled` publishes a source, `combined`
merges it into the combined list. Run locally with:

```bash
python3 scripts/build.py
```

## No warranty

Blocklists produce false positives. Use at your own risk; neither this
repository nor the upstream projects are liable for blocked traffic.
