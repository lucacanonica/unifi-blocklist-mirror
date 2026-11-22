#!/usr/bin/env python3
"""Fetch public IP blocklists, clean them and write import-ready files.

Standard library only. For every enabled source in sources.json it writes

    lists/<id>_v4.txt        single hosts bare, networks with a prefix (UniFi)
    lists/<id>_v4_cidr.txt   every entry with a prefix (hosts as /32)
    lists/<id>_v6*.txt       the same for IPv6, only if the source has IPv6

plus lists/combined_* for the sources flagged "combined", lists/NOTICE.md with
the attribution and the verbatim upstream file headers, and lists/status.json.

If a source cannot be fetched (or comes back empty), its previously published
file is kept, so a broken upstream never empties a published list.
"""

import argparse
import datetime as dt
import ipaddress
import json
import os
import re
import sys
import time
import urllib.request

MAX_ENTRIES = 100_000  # UniFi limit per Network List
MIN_PREFIX = {4: 8, 6: 16}  # refuse anything wider: almost certainly a mistake
HEADER_LINES = 60  # upstream comment lines kept verbatim in NOTICE.md

# Never publish these: blocking them on a gateway breaks the local network.
# (FireHOL Level 1 deliberately contains bogons such as 10.0.0.0/8.)
RESERVED = {
    4: [
        "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
        "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
        "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
        "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
    ],
    6: [
        "::/8", "64:ff9b::/96", "100::/64", "2001:db8::/32", "fc00::/7",
        "fe80::/10", "ff00::/8",
    ],
}
RESERVED = {v: [ipaddress.ip_network(n) for n in nets] for v, nets in RESERVED.items()}

COMMENT = re.compile(r"\s*[#;].*$")


def parse_generic(line):
    """First token of a line: an IP, a CIDR, or a JSON object with "cidr"."""
    line = line.strip()
    if line.startswith("{"):
        try:
            return json.loads(line).get("cidr")
        except ValueError:
            return None
    line = COMMENT.sub("", line).strip()
    return line.split()[0] if line else None


def parse_dshield(line):
    """DShield block.txt: start <tab> end <tab> prefix-length <tab> ..."""
    line = COMMENT.sub("", line).strip()
    cols = line.split()
    if len(cols) >= 3 and cols[2].isdigit():
        return f"{cols[0]}/{cols[2]}"
    return None


PARSERS = {"generic": parse_generic, "dshield": parse_dshield}


def parse(text, parser="generic"):
    """Return ({4: set(networks), 6: set(networks)}, [header comment lines])."""
    fn = PARSERS[parser]
    nets = {4: set(), 6: set()}
    header, in_header = [], True
    for raw in text.splitlines():
        stripped = raw.strip()
        if in_header and stripped[:1] in ("#", ";"):
            if len(header) < HEADER_LINES:
                header.append(stripped)
            continue
        if stripped:
            in_header = False
        token = fn(raw)
        if not token:
            continue
        try:
            net = ipaddress.ip_network(token, strict=False)
        except ValueError:
            continue
        if net.prefixlen < MIN_PREFIX[net.version]:
            continue
        nets[net.version].add(net)
    return nets, header


def clean(nets, version):
    """Merge overlaps, cut out reserved ranges, return a sorted list."""
    out = []
    for net in ipaddress.collapse_addresses(nets):
        pieces = [net]
        for res in RESERVED[version]:
            nxt = []
            for p in pieces:
                if p.subnet_of(res):
                    continue
                if res.subnet_of(p):
                    nxt.extend(p.address_exclude(res))
                else:
                    nxt.append(p)
            pieces = nxt
        out.extend(pieces)
    return sorted(ipaddress.collapse_addresses(out))


def fmt(net, cidr):
    if not cidr and net.prefixlen == net.max_prefixlen:
        return str(net.network_address)
    return str(net)


def fetch(url, retries=3):
    repo = os.environ.get("GITHUB_REPOSITORY")
    agent = "blocklist-mirror/1.0" + (f" (+https://github.com/{repo})" if repo else "")
    req = urllib.request.Request(url, headers={"User-Agent": agent})
    last = None
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                return resp.read().decode("utf-8", errors="replace")
        except Exception as exc:  # noqa: BLE001 - any failure means "retry"
            last = exc
            time.sleep(5 * (attempt + 1))
    raise RuntimeError(f"{url}: {last}")


def read_previous(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return {ipaddress.ip_network(l.strip()) for l in fh if l.strip()}
    except (OSError, ValueError):
        return None


def write_list(out_dir, stem, nets, written):
    """Write plain + cidr variants, and numbered parts if over the UniFi limit."""
    for suffix, cidr in (("", False), ("_cidr", True)):
        lines = [fmt(n, cidr) for n in nets]
        chunks = [(f"{stem}{suffix}.txt", lines)]
        if len(lines) > MAX_ENTRIES:
            chunks += [
                (f"{stem}{suffix}_part{i // MAX_ENTRIES + 1}.txt", lines[i:i + MAX_ENTRIES])
                for i in range(0, len(lines), MAX_ENTRIES)
            ]
        for name, chunk in chunks:
            with open(os.path.join(out_dir, name), "w", encoding="utf-8", newline="\n") as fh:
                fh.write("\n".join(chunk) + ("\n" if chunk else ""))
            written.add(name)


def build(sources_path, out_dir):
    with open(sources_path, encoding="utf-8") as fh:
        sources = [s for s in json.load(fh)["sources"] if s.get("enabled", True)]
    os.makedirs(out_dir, exist_ok=True)
    now = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    try:
        with open(os.path.join(out_dir, "status.json"), encoding="utf-8") as fh:
            old_status = json.load(fh).get("sources", {})
    except (OSError, ValueError):
        old_status = {}

    written, status, notice = set(), {}, []
    combined = {4: set(), 6: set()}
    failures = 0

    for src in sources:
        sid = src["id"]
        nets, headers, error = {4: set(), 6: set()}, [], None
        try:
            for url in src["urls"]:
                got, header = parse(fetch(url), src.get("parser", "generic"))
                for v in (4, 6):
                    nets[v] |= got[v]
                headers.append((url, header))
            if not (nets[4] or nets[6]) and not src.get("allow_empty"):
                raise RuntimeError("no usable entries in upstream file")
        except Exception as exc:  # noqa: BLE001
            error = str(exc)

        prev = old_status.get(sid, {})
        if error:
            failures += 1
            print(f"WARN {sid}: {error} - keeping previous data", file=sys.stderr)
            for v in (4, 6):
                nets[v] = read_previous(os.path.join(out_dir, f"{sid}_v{v}_cidr.txt")) or set()
            fetched, headers = prev.get("fetched", "never"), prev.get("headers", [])
        else:
            fetched = now

        counts = {}
        for v in (4, 6):
            cleaned = clean(nets[v], v)
            counts[f"v{v}"] = len(cleaned)
            if cleaned or v == 4:
                write_list(out_dir, f"{sid}_v{v}", cleaned, written)
            if src.get("combined"):
                combined[v] |= set(cleaned)
        status[sid] = {"fetched": fetched, "stale": bool(error), "error": error,
                       "entries": counts, "headers": headers}
        print(f"{sid}: {counts['v4']} v4, {counts['v6']} v6" + (" (stale)" if error else ""))

        notice += [
            f"## {src['name']}", "",
            f"- Owner / source of the data: **{src['owner']}**",
            f"- Homepage: <{src['homepage']}>",
            f"- Terms: <{src['terms']}>",
            f"- Licence: {src['license']}",
            f"- Files: `{sid}_v4.txt`, `{sid}_v4_cidr.txt`"
            + (f", `{sid}_v6.txt`, `{sid}_v6_cidr.txt`" if counts["v6"] else ""),
            f"- In combined list: {'yes' if src.get('combined') else 'no'}",
            f"- Last fetched from upstream: {fetched}" + (" (**stale**, last fetch failed)" if error else ""),
            f"- Entries after clean-up: {counts['v4']} IPv4, {counts['v6']} IPv6", "",
        ]
        for url, header in headers:
            if header:
                notice += [f"Unmodified header of <{url}>:", "", "```", *header, "```", ""]

    combined_counts = {}
    for v in (4, 6):
        cleaned = clean(combined[v], v)
        combined_counts[f"v{v}"] = len(cleaned)
        if cleaned or v == 4:
            write_list(out_dir, f"combined_v{v}", cleaned, written)
    print(f"combined: {combined_counts['v4']} v4, {combined_counts['v6']} v6")

    members = ", ".join(s["name"] for s in sources if s.get("combined"))
    intro = [
        "# Notice and attribution", "",
        "The IP data in this folder is **not** original work of this repository.",
        "Every list belongs to the upstream project named below and stays under",
        "that project's terms. This repository only mirrors the lists in a",
        "cleaned-up form: comments removed, duplicates and overlaps merged,",
        "private and reserved ranges removed, sorted, one entry per line.", "",
        "The published `.txt` files carry no comment lines because UniFi cannot",
        "import files that contain them. The copyright statements and time",
        "stamps from the upstream files are therefore kept here instead.", "",
        f"Generated: {now}", "",
        "## Combined list", "",
        f"`combined_v4.txt` / `combined_v4_cidr.txt` merge: {members}.", "",
        "Each included list remains under the terms of its upstream project,",
        "linked below.", "",
        f"Entries: {combined_counts['v4']} IPv4, {combined_counts['v6']} IPv6", "",
    ]
    with open(os.path.join(out_dir, "NOTICE.md"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(intro + notice))
    with open(os.path.join(out_dir, "status.json"), "w", encoding="utf-8", newline="\n") as fh:
        json.dump({"generated": now, "combined": combined_counts, "sources": status}, fh, indent=1)
        fh.write("\n")

    # Remove list files left over from disabled sources or old split parts.
    for name in os.listdir(out_dir):
        if name.endswith(".txt") and name not in written:
            os.remove(os.path.join(out_dir, name))

    if failures == len(sources):
        print("ERROR: every source failed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--sources", default=os.path.join(root, "sources.json"))
    ap.add_argument("--out", default=os.path.join(root, "lists"))
    args = ap.parse_args()
    sys.exit(build(args.sources, args.out))
