# Copyright (c) The Conn3x Authors
# SPDX-License-Identifier: MPL-2.0
"""Watches upstream security advisories for the software Conn3x circuits install.

security/watchlist.json names each piece of software, the circuits that
install it, and where its advisories are published: distro packages, which
are looked up in OSV for every distro the circuits support; other OSV
packages, such as Go modules; and GitHub repositories' own advisories. Each
run opens one issue per piece of software with advisories published in the
last --days days that no earlier issue has listed, labelled
upstream-advisory, so someone checks the circuits' defaults, pins and docs.

Its feeds are vendors' own RSS feeds, such as Oracle's security alerts, which
publish days before OSV has the CVEs. Each new item opens an issue naming the
entries it may cover.

Usage: python3 scripts/advisory_watch.py [--days 7] [--dry-run]
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime

OSV = "https://api.osv.dev/v1"
LABEL = "upstream-advisory"
ASSIGNEE = "jamesconwaydev"
# Every advisory ID an issue covers, so a later run doesn't open it again.
MARKER = re.compile(r"<!-- advisory-ids: ([^>]*) -->")
# A CVE, alone or inside a distro's ID for it, such as UBUNTU-CVE-2026-1.
CVE = re.compile(r"(?:^|-)(CVE-\d{4}-\d+)$")


def http_json(url, payload=None):
    data = None if payload is None else json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.load(r)
        except OSError as e:
            if attempt == 2:
                sys.exit(f"{url}: {e}")
            time.sleep(5 * (attempt + 1))


def gh(*args):
    out = subprocess.run(["gh", *args], capture_output=True, text=True, check=False)
    if out.returncode != 0:
        sys.exit(f"gh {' '.join(args[:3])} failed: {out.stderr.strip()}")
    return out.stdout


def github_advisories(repo):
    """A repository's published advisories, or None if GitHub refused, such as
    an organisation's IP allow list turning the Actions token away. One repo
    mustn't stop every other entry's issue, so the caller skips it and warns."""
    out = subprocess.run(["gh", "api", f"repos/{repo}/security-advisories?state=published&sort=published&direction=desc&per_page=30"],
                         capture_output=True, text=True, check=False)
    if out.returncode != 0:
        return None
    return json.loads(out.stdout or "[]")


def http_text(url):
    # Some vendors' sites turn away urllib's default user agent.
    req = urllib.request.Request(url, headers={"User-Agent": "conn3x-advisory-watch"})
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return r.read().decode("utf-8", "replace")
        except OSError as e:
            if attempt == 2:
                print(f"::warning::{url}: {e}")
                return None
            time.sleep(5 * (attempt + 1))


def feed_items(xml):
    """An RSS feed's items as id, title, link and published time. The id is
    the guid, or the link when there is none."""
    items = []
    for it in ET.fromstring(xml).iter("item"):
        text = {k: " ".join((it.findtext(k) or "").split()) for k in ("title", "link", "guid", "pubDate")}
        try:
            published = parsedate_to_datetime(text["pubDate"])
        except (TypeError, ValueError):
            published = None
        items.append({"id": text["guid"] or text["link"], "title": text["title"], "link": text["link"], "published": published})
    return items


def render_feed(feed, item, entries):
    lines = [
        f"{feed['name']} published a security advisory: [{md(item['title'])}]({item['link']}), on {item['published']:%Y-%m-%d}.",
        "",
        "Its CVEs usually reach OSV, and so this watch's per-package issues, only once distros ship a fix. Check now whether it covers any of these:",
        "",
    ]
    lines += [f"- **{e['name']}**, installed by " + ", ".join(f"`{c}`" for c in e["circuits"]) for e in entries]
    lines += [
        "",
        "**To check**",
        "",
        "- [ ] Which of the above does the advisory list, and at which versions?",
        "- [ ] Is a fixed build out from the vendor, the distros, or the image publisher? If not, note it here and keep this open.",
        "- [ ] Does a circuit's default, pinned image, docs or example need changing?",
        "",
        "Opened by `scripts/advisory_watch.py` from `security/watchlist.json`. Close it when everything above is checked.",
        "",
        f"<!-- advisory-ids: {feed_key(feed, item)} -->",
    ]
    return "\n".join(lines)


def feed_key(feed, item):
    return f"{feed['name'].lower()}:{''.join(item['id'].split())}"


def parse_time(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00")) if s else None


def osv_queries(watchlist):
    """(entry index, OSV package) for every package to look up."""
    out = []
    for i, e in enumerate(watchlist["entries"]):
        for name in e.get("packages", []):
            for eco in watchlist["ecosystems"]:
                out.append((i, {"name": name, "ecosystem": eco}))
        for p in e.get("osv", []):
            out.append((i, {"name": p["name"], "ecosystem": p["ecosystem"]}))
    return out


def query_key(p):
    return f"{p['ecosystem']}/{p['name']}"


def osv_recent(queries, cutoff):
    """{entry index: set of OSV IDs modified since cutoff}, and {query key:
    every OSV ID for that package}. querybatch gives only IDs and modified
    times, so this keeps the detail fetches few."""
    found, every = {}, {}
    for start in range(0, len(queries), 500):
        chunk = queries[start:start + 500]
        res = http_json(f"{OSV}/querybatch", {"queries": [{"package": p} for _, p in chunk]})
        for (i, p), r in zip(chunk, res.get("results", [])):
            # A query with more results than one page returns a next_page_token.
            vulns, token = r.get("vulns", []), r.get("next_page_token")
            while token:
                more = http_json(f"{OSV}/query", {"package": p, "page_token": token})
                vulns += more.get("vulns", [])
                token = more.get("next_page_token")
            every.setdefault(query_key(p), set()).update(v["id"] for v in vulns)
            for v in vulns:
                m = parse_time(v.get("modified"))
                if m and m >= cutoff:
                    found.setdefault(i, set()).add(v["id"])
    return found, every


def late_ids(queries, every, state):
    """{entry index: IDs a package has now that the last run's state didn't},
    such as an old CVE a distro has just marked as affecting it. A package
    with no state, on the first run or newly added to the watchlist, only
    starts its state, or every old CVE would be reported."""
    late = {}
    for i, p in queries:
        k = query_key(p)
        if k in state:
            new = every.get(k, set()) - set(state[k])
            if new:
                late.setdefault(i, set()).update(new)
    return late


# OSV ecosystems that are distro releases, of which only the watchlist's are shown.
DISTROS = ("Debian", "Ubuntu", "Rocky Linux", "AlmaLinux", "Red Hat", "Alpine")


def fixed_versions(vuln, ecosystems=()):
    """'ecosystem version' for each fixed event, so the issue says what to update
    to: for a distro, only the releases the circuits support."""
    out = []
    for a in vuln.get("affected", []):
        eco = a.get("package", {}).get("ecosystem", "")
        if eco.startswith(DISTROS) and eco not in ecosystems:
            continue
        for r in a.get("ranges", []):
            for ev in r.get("events", []):
                if "fixed" in ev:
                    out.append(f"{eco} {ev['fixed']}".strip())
    return sorted(set(out))


def severity(vuln):
    """A word such as high, where the record has one. A CVSS vector alone
    isn't shown: cut to fit a table it says nothing, and the link has it."""
    s = (vuln.get("database_specific") or {}).get("severity")
    return s.lower() if isinstance(s, str) and s else ""


def cves(ids):
    return sorted({m.group(1) for m in map(CVE.search, ids) if m})


def from_osv(vuln, ecosystems=()):
    # Distro notices such as a DSA or a USN name their CVEs in related or upstream.
    named = vuln.get("aliases", []) + vuln.get("upstream", []) + vuln.get("related", [])
    return {
        "id": vuln["id"],
        "cves": cves(named + [vuln["id"]]),
        "aliases": set(named),
        "published": vuln.get("published", ""),
        "summary": (vuln.get("summary") or vuln.get("details") or "").strip().split("\n")[0][:160],
        "severity": severity(vuln),
        "fixed": fixed_versions(vuln, ecosystems),
        "url": f"https://osv.dev/vulnerability/{vuln['id']}",
    }


def from_github(adv):
    return {
        "id": adv["ghsa_id"],
        "cves": cves([adv.get("cve_id") or ""]),
        "aliases": {adv["cve_id"]} if adv.get("cve_id") else set(),
        "published": adv.get("published_at", ""),
        "summary": (adv.get("summary") or "").strip()[:160],
        "severity": adv.get("severity") or "",
        "fixed": sorted({p["patched_versions"] for p in adv.get("vulnerabilities") or [] if p.get("patched_versions")}),
        "url": adv.get("html_url", ""),
    }


def group(records):
    """Rows, one per CVE where there is one. A record naming one CVE, such as
    DEBIAN-CVE-2026-1 or GHSA-x for CVE-2026-1, joins that CVE's row; one
    naming several, such as a DSA, is listed under each; one naming none is a
    row of its own."""
    rows = {}
    for rec in records:
        keys = rec["cves"] or [rec["id"]]
        for k in keys:
            row = rows.setdefault(k, {"key": k, "ids": set(), "aliases": set(), "published": rec["published"], "summary": "", "severity": "", "fixed": set(), "urls": {}})
            row["ids"].add(rec["id"])
            row["aliases"].update(rec["aliases"])
            row["urls"][rec["id"]] = rec["url"]
            row["published"] = min(filter(None, [row["published"], rec["published"]]), default="")
            # Prefer a summary from a record about this CVE alone.
            if rec["summary"] and (not row["summary"] or len(keys) == 1):
                row["summary"] = rec["summary"]
            row["severity"] = row["severity"] or rec["severity"]
            row["fixed"].update(rec["fixed"])
    return sorted(rows.values(), key=lambda r: (r["published"], r["key"]))


def new_rows(records, seen):
    """The rows from records that no earlier issue listed, by CVE, by any
    record's ID, or by an ID a record gives as its alias, such as a GHSA."""
    return [r for r in group(records) if r["key"] not in seen and not ((r["ids"] | r["aliases"]) & seen)]


def seen_ids(bodies):
    ids = set()
    for b in bodies:
        for m in MARKER.finditer(b or ""):
            ids.update(m.group(1).split())
    return ids


def md(s):
    return s.replace("|", "\\|").replace("\n", " ")


def render(entry, rows):
    circuits = ", ".join(f"`{c}`" for c in entry["circuits"])
    lines = [
        f"New security advisories for **{entry['name']}**, which these circuits install: {circuits}.",
        "",
        "| Advisory | Published | Severity | Summary | Fixed in |",
        "|---|---|---|---|---|",
    ]
    for r in rows:
        link = r["urls"].get(r["key"]) or next(iter(r["urls"].values()))
        fixed = "<br>".join(md(f) for f in sorted(r["fixed"])[:8]) or "not yet"
        lines.append(f"| [{r['key']}]({link}) | {r['published'][:10]} | {md(r['severity'])} | {md(r['summary'])} | {fixed} |")
    others = sorted({i for r in rows for i in r["ids"]} - {r["key"] for r in rows})
    if others:
        lines += ["", "Distro and upstream records: " + ", ".join(others) + "."]
    pinned = entry.get("pinned", [])
    lines += ["", "**To check**", ""]
    if pinned:
        lines.append("- [ ] Is a circuit's default affected? " + "; ".join(f"`{p['circuit']}` `{p['variable']}` = `{p['default']}`" for p in pinned))
    else:
        lines.append("- [ ] Do the circuits install a fixed version? They use the distro's or vendor's package, so hosts are fixed by updating it.")
    lines += [
        "- [ ] Do docs, examples or test images name an affected version or image tag?",
        "- [ ] Does a circuit need a release, or its README a note, and do Conn3x users need telling?",
        "",
        "Opened by `scripts/advisory_watch.py` from `security/watchlist.json`. Close it when everything above is checked.",
        "",
        f"<!-- advisory-ids: {' '.join(sorted({r['key'] for r in rows} | {i for r in rows for i in r['ids']}))} -->",
    ]
    return "\n".join(lines)


def title(entry, rows):
    first = rows[0]["key"]
    more = f" and {len(rows) - 1} more" if len(rows) > 1 else ""
    return f"Upstream advisory for {entry['name']}: {first}{more}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--watchlist", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "security", "watchlist.json"))
    ap.add_argument("--days", type=int, default=7)
    ap.add_argument("--repo", default="conn3xorg/conn3x")
    ap.add_argument("--dry-run", action="store_true", help="print the issues instead of opening them")
    ap.add_argument("--state", help="JSON file of every OSV ID seen per package, read at the start and written at the end")
    args = ap.parse_args()

    with open(args.watchlist) as f:
        watchlist = json.load(f)
    cutoff = datetime.now(timezone.utc) - timedelta(days=args.days)

    state = {}
    if args.state and os.path.exists(args.state):
        with open(args.state) as f:
            state = json.load(f)

    records = {i: [] for i in range(len(watchlist["entries"]))}
    details = {}

    def detail(vid):
        if vid not in details:
            details[vid] = from_osv(http_json(f"{OSV}/vulns/{vid}"), watchlist["ecosystems"])
        return details[vid]

    queries = osv_queries(watchlist)
    recent, every = osv_recent(queries, cutoff)
    late = late_ids(queries, every, state)
    for i in records:
        for vid in sorted(recent.get(i, set()) | late.get(i, set())):
            rec = detail(vid)
            p = parse_time(rec["published"])
            if vid in late.get(i, ()) or (p and p >= cutoff):
                records[i].append(rec)
    skipped = []
    for i, e in enumerate(watchlist["entries"]):
        for repo in e.get("github", []):
            advs = github_advisories(repo)
            if advs is None:
                skipped.append(repo)
                # An Actions warning, shown on the run's summary page.
                print(f"::warning::GitHub refused {repo}'s advisories; its OSV and distro sources were still read")
                continue
            for a in advs:
                p = parse_time(a.get("published_at"))
                if p and p >= cutoff:
                    records[i].append(from_github(a))

    # Every issue's body, paged, so no cap on how many earlier issues count.
    bodies = gh("api", "--paginate", f"repos/{args.repo}/issues?labels={LABEL}&state=all&per_page=100", "--jq", ".[].body") if not args.dry_run or os.environ.get("GH_TOKEN") else ""
    seen = seen_ids([bodies])

    opened = 0
    issues = []
    by_name = {e["name"]: e for e in watchlist["entries"]}
    for feed in watchlist.get("feeds", []):
        xml = http_text(feed["url"])
        if xml is None:
            skipped.append(feed["url"])
            continue
        for item in feed_items(xml):
            key = feed_key(feed, item)
            if key in seen or not item["published"] or item["published"] < cutoff:
                continue
            issues.append((f"Vendor advisory from {feed['name']}: {item['title']}", render_feed(feed, item, [by_name[n] for n in feed["entries"]])))
            seen.add(key)
    for i, e in enumerate(watchlist["entries"]):
        rows = new_rows(records[i], seen)
        if not rows:
            continue
        issues.append((title(e, rows), render(e, rows)))
        seen |= {r["key"] for r in rows} | {x for r in rows for x in r["ids"]}
    for t, body in issues:
        if args.dry_run:
            print(f"=== {t}\n{body}\n")
        else:
            gh("issue", "create", "-R", args.repo, "--title", t, "--body", body, "--label", LABEL, "--label", "security", "--assignee", ASSIGNEE)
        opened += 1
    if args.state and not args.dry_run:
        with open(args.state, "w") as f:
            json.dump({k: sorted(v) for k, v in every.items()}, f)
    print(f"{opened} issue(s) {'would be ' if args.dry_run else ''}opened from {sum(map(len, records.values()))} advisory records since {cutoff:%Y-%m-%d}.")
    if skipped:
        print(f"Skipped {len(skipped)} source(s) that refused or failed: {', '.join(skipped)}.")


if __name__ == "__main__":
    main()
