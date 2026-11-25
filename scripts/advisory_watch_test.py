# Copyright (c) The Conn3x Authors
# SPDX-License-Identifier: MPL-2.0
"""Tests for advisory_watch.py: grouping, filtering and what an issue says. No network."""

import os
import sys
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import advisory_watch as w  # noqa: E402

ECOS = ["Debian:13", "Ubuntu:24.04:LTS", "Rocky Linux:10"]


def osv(vid, published="2026-11-18T00:00:00Z", summary="", fixed=(), **kw):
    v = {"id": vid, "published": published, "summary": summary,
         "affected": [{"package": {"ecosystem": e}, "ranges": [{"events": [{"introduced": "0"}, {"fixed": f}]}]} for e, f in fixed]}
    v.update(kw)
    return w.from_osv(v, ECOS)


class Group(unittest.TestCase):
    def test_distro_records_join_their_cve(self):
        rows = w.group([
            osv("DEBIAN-CVE-2026-1", summary="use-after-free in HTTP/2", fixed=[("Debian:13", "1.26.3-3+deb13u11")]),
            osv("UBUNTU-CVE-2026-1", fixed=[("Ubuntu:24.04:LTS", "1.24.0-2ubuntu7.20")]),
            # A USN names its CVEs by the distro's IDs, in upstream.
            osv("USN-1-1", published="2026-11-19T00:00:00Z", summary="nginx vulnerabilities", upstream=["UBUNTU-CVE-2026-1", "UBUNTU-CVE-2026-2"]),
        ])
        self.assertEqual([r["key"] for r in rows], ["CVE-2026-1", "CVE-2026-2"])
        one = rows[0]
        self.assertEqual(one["ids"], {"DEBIAN-CVE-2026-1", "UBUNTU-CVE-2026-1", "USN-1-1"})
        # The single-CVE record's summary wins over the notice's.
        self.assertEqual(one["summary"], "use-after-free in HTTP/2")
        self.assertEqual(one["published"], "2026-11-18T00:00:00Z")
        self.assertEqual(one["fixed"], {"Debian:13 1.26.3-3+deb13u11", "Ubuntu:24.04:LTS 1.24.0-2ubuntu7.20"})

    def test_a_record_without_a_cve_is_its_own_row(self):
        rows = w.group([osv("GO-2026-9", summary="a Go advisory")])
        self.assertEqual([r["key"] for r in rows], ["GO-2026-9"])

    def test_github_advisory_joins_its_cve(self):
        gh = w.from_github({"ghsa_id": "GHSA-aaaa-bbbb-cccc", "cve_id": "CVE-2026-5", "published_at": "2026-11-18T00:00:00Z",
                            "summary": "path traversal", "severity": "high", "html_url": "https://github.com/x",
                            "vulnerabilities": [{"patched_versions": "1.31.4"}]})
        rows = w.group([gh, osv("GO-2026-5", aliases=["CVE-2026-5", "GHSA-aaaa-bbbb-cccc"])])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["severity"], "high")
        self.assertEqual(rows[0]["fixed"], {"1.31.4"})


class Fixed(unittest.TestCase):
    def test_only_supported_distro_releases_and_other_ecosystems(self):
        rec = osv("DEBIAN-CVE-2026-1", fixed=[("Debian:12", "a"), ("Debian:13", "b"), ("Ubuntu:Pro:16.04:LTS", "c"), ("Go", "v1.2.3")])
        self.assertEqual(rec["fixed"], ["Debian:13 b", "Go v1.2.3"])

    def test_a_cvss_vector_isnt_shown_as_severity(self):
        rec = osv("CVE-2026-1", severity=[{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N"}])
        self.assertEqual(rec["severity"], "")


class Seen(unittest.TestCase):
    def test_marker_ids_are_skipped(self):
        seen = w.seen_ids(["text\n<!-- advisory-ids: CVE-2026-1 DSA-1-1 -->", None])
        self.assertEqual(seen, {"CVE-2026-1", "DSA-1-1"})
        records = [osv("DEBIAN-CVE-2026-1"), osv("DEBIAN-CVE-2026-2"), osv("GO-2026-3", aliases=["DSA-1-1"])]
        self.assertEqual([r["key"] for r in w.new_rows(records, seen)], ["CVE-2026-2"])

    def test_issue_lists_every_id_in_its_marker(self):
        rows = w.group([osv("DEBIAN-CVE-2026-1"), osv("USN-1-1", upstream=["UBUNTU-CVE-2026-1"])])
        body = w.render({"name": "nginx", "circuits": ["circuit-nginx"]}, rows)
        self.assertEqual(w.seen_ids([body]), {"CVE-2026-1", "DEBIAN-CVE-2026-1", "USN-1-1"})


class GitHub(unittest.TestCase):
    def test_a_refused_repo_is_skipped_not_fatal(self):
        import subprocess
        real = subprocess.run
        subprocess.run = lambda *a, **k: subprocess.CompletedProcess(a, 1, "", "HTTP 403: IP allow list")
        try:
            self.assertIsNone(w.github_advisories("bridgecrewio/checkov"))
        finally:
            subprocess.run = real


RSS = """<rss><channel>
<item><title>Oracle Critical Security Patch Update Advisory -
  November 2026</title><link>https://www.oracle.com/security-alerts/cspunov2026.html
</link><pubDate>Tue, 17 Nov 2026 13:00:00 -0700</pubDate><guid isPermaLink="false">CSPUNov2026</guid></item>
<item><title>No guid or date</title><link>https://example.com/a</link></item>
</channel></rss>"""


class Feed(unittest.TestCase):
    def test_items_are_parsed_and_whitespace_folded(self):
        a, b = w.feed_items(RSS)
        self.assertEqual(a["title"], "Oracle Critical Security Patch Update Advisory - November 2026")
        self.assertEqual(a["link"], "https://www.oracle.com/security-alerts/cspunov2026.html")
        self.assertEqual(a["published"].isoformat(), "2026-11-17T13:00:00-07:00")
        self.assertEqual(b["id"], "https://example.com/a")
        self.assertIsNone(b["published"])

    def test_issue_marker_skips_the_item_next_run(self):
        feed = {"name": "Oracle"}
        item = w.feed_items(RSS)[0]
        body = w.render_feed(feed, item, [{"name": "mysql", "circuits": ["circuit-mysql"]}])
        self.assertIn("**mysql**, installed by `circuit-mysql`", body)
        self.assertEqual(w.seen_ids([body]), {w.feed_key(feed, item)})
        self.assertEqual(w.feed_key(feed, item), "oracle:CSPUNov2026")


class Late(unittest.TestCase):
    Q = [(0, {"name": "nginx", "ecosystem": "Debian:13"}), (1, {"name": "php8.4", "ecosystem": "Debian:13"})]

    def test_an_old_id_new_to_a_package_is_late(self):
        every = {"Debian:13/nginx": {"DEBIAN-CVE-2020-1", "DEBIAN-CVE-2026-1"}, "Debian:13/php8.4": {"DEBIAN-CVE-2026-2"}}
        state = {"Debian:13/nginx": ["DEBIAN-CVE-2026-1"], "Debian:13/php8.4": ["DEBIAN-CVE-2026-2"]}
        self.assertEqual(w.late_ids(self.Q, every, state), {0: {"DEBIAN-CVE-2020-1"}})

    def test_first_run_and_new_packages_report_nothing(self):
        every = {"Debian:13/nginx": {"DEBIAN-CVE-2020-1"}, "Debian:13/php8.4": {"DEBIAN-CVE-2021-1"}}
        self.assertEqual(w.late_ids(self.Q, every, {}), {})
        # nginx has state; php8.4 was just added to the watchlist.
        self.assertEqual(w.late_ids(self.Q, every, {"Debian:13/nginx": ["DEBIAN-CVE-2020-1"]}), {})

    def test_a_corrupt_state_file_is_no_state(self):
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            f.write('{"Debian:13/nginx": [')
        try:
            self.assertEqual(w.load_state(f.name), {})
        finally:
            os.unlink(f.name)
        self.assertEqual(w.load_state(None), {})

    def test_a_state_file_of_the_wrong_shape_is_no_state(self):
        import json
        import tempfile
        for bad in ({"Debian:13/nginx": 5}, {"Debian:13/nginx": "DEBIAN-CVE-2026-1"}, ["DEBIAN-CVE-2026-1"]):
            with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
                json.dump(bad, f)
            try:
                self.assertEqual(w.load_state(f.name), {}, bad)
            finally:
                os.unlink(f.name)


class Watchlist(unittest.TestCase):
    def test_every_feed_entry_exists(self):
        import json
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "security", "watchlist.json")) as f:
            wl = json.load(f)
        names = {e["name"] for e in wl["entries"]}
        for feed in wl.get("feeds", []):
            self.assertEqual(set(feed["entries"]) - names, set(), feed["name"])


class Render(unittest.TestCase):
    def test_title_and_table(self):
        rows = w.group([osv("CVE-2026-1", summary="a | b"), osv("CVE-2026-2")])
        e = {"name": "nginx", "circuits": ["circuit-nginx"], "pinned": [{"circuit": "circuit-nginx", "variable": "v", "default": "1.29"}]}
        self.assertEqual(w.title(e, rows), "Upstream advisory for nginx: CVE-2026-1 and 1 more")
        body = w.render(e, rows)
        self.assertIn("a \\| b", body)
        self.assertIn("`circuit-nginx` `v` = `1.29`", body)
        self.assertIn("| not yet |", body)


NODE = {
    "201": {"cve": ["CVE-2026-106072"], "vulnerable": "22.x || 24.x || 26.x", "patched": "^22.23.4 || ^24.22.1 || ^26.12.1",
            "ref": "https://nodejs.org/en/blog/vulnerability/october-2026-security-releases",
            "description": "Improper certificate validation", "overview": "A flaw.", "severity": "medium"},
    "90": {"cve": ["CVE-2018-1"], "vulnerable": "4.x || 6.x  || 8.x || 9.x", "patched": "^4.9.0 || ^6.14.0 || ^8.11.0 || ^9.10.0", "overview": "Old.\nMore.", "severity": "high"},
    "91": {"cve": [], "vulnerable": ">= 10.9.0", "patched": "", "overview": "No CVE, no fix."},
}


class Node(unittest.TestCase):
    def test_ranges(self):
        v = w.semver
        self.assertTrue(w.satisfies(v("26.13.0"), "22.x || 26.x"))
        self.assertFalse(w.satisfies(v("27.0.0"), "22.x || 26.x"))
        self.assertTrue(w.satisfies(v("26.12.1"), "^24.22.1 || ^26.12.1"))
        self.assertFalse(w.satisfies(v("26.12.0"), "^24.22.1 || ^26.12.1"))
        self.assertFalse(w.satisfies(v("27.0.0"), "^26.12.1"))
        self.assertTrue(w.satisfies(v("0.10.48"), "^0.10.48"))
        self.assertFalse(w.satisfies(v("0.11.0"), "^0.10.48"))
        self.assertTrue(w.satisfies(v("9.7.3"), "9.7.x || 10.x"))
        self.assertTrue(w.satisfies(v("6.1.0"), ">=6.0.0 <6.2.0 || 5.x"))
        self.assertFalse(w.satisfies(v("6.2.0"), ">=6.0.0 <6.2.0 || 5.x"))
        self.assertTrue(w.satisfies(v("10.9.0"), ">= 10.9.0"))
        self.assertTrue(w.satisfies(v("10.99.0"), "<= 10"))
        self.assertFalse(w.satisfies(v("11.0.0"), "<= 10"))
        self.assertTrue(w.satisfies(v("8.5.0"), "8.5.0"))
        self.assertFalse(w.satisfies(v("8.5.1"), "8.5.0"))
        self.assertFalse(w.satisfies(v("26.0.0"), ""))
        with self.assertRaises(ValueError):
            w.satisfies(v("26.0.0"), "latest")

    def test_only_advisories_affecting_a_full_pinned_default(self):
        entry = {"name": "nodejs", "pinned": [{"default": "26"}, {"default": "26.12.0"}]}
        recs = w.node_records(NODE, entry)
        # 91 has no patched range, so every version from 10.9.0 is affected.
        self.assertEqual([r["id"] for r in recs], ["CVE-2026-106072", "nodejs-security-wg:91"])
        r = recs[0]
        self.assertEqual(r["fixed"], ["Node.js 22.23.4", "Node.js 24.22.1", "Node.js 26.12.1"])
        self.assertEqual((r["severity"], r["summary"]), ("medium", "Improper certificate validation"))
        self.assertTrue(r["url"].startswith("https://nodejs.org/"))
        self.assertEqual(w.node_records(NODE, {"pinned": [{"default": "26.12.1"}]})[0]["id"], "nodejs-security-wg:91")
        # A bare major installs the newest release, so it isn't checked.
        self.assertEqual(w.node_records(NODE, {"pinned": [{"default": "26"}]}), [])

    def test_a_range_it_cant_read_is_skipped(self):
        bad = {"1": {"cve": ["CVE-2026-9"], "vulnerable": "next", "patched": ""}}
        self.assertEqual(w.node_records(bad, {"pinned": [{"default": "26.0.0"}]}), [])

    def test_a_cve_an_earlier_issue_listed_isnt_opened_again(self):
        recs = w.node_records(NODE, {"pinned": [{"default": "26.12.0"}]})
        # An OSV-sourced issue such as #1362 named the CVE by a distro's ID too.
        seen = w.seen_ids(["<!-- advisory-ids: CVE-2026-106072 UBUNTU-CVE-2026-106072 -->"])
        self.assertEqual([r["key"] for r in w.new_rows(recs, seen)], ["nodejs-security-wg:91"])
        # And a Node record joins the OSV record for the same CVE in one row.
        rows = w.group(recs[:1] + [osv("UBUNTU-CVE-2026-106072")])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["ids"], {"CVE-2026-106072", "UBUNTU-CVE-2026-106072"})


class Backfill(unittest.TestCase):
    def test_backfill_reaches_back_30_days(self):
        from datetime import datetime, timedelta, timezone
        now = datetime(2026, 11, 25, tzinfo=timezone.utc)
        advs = [{"ghsa_id": "GHSA-r", "cve_id": "CVE-2026-119101", "published_at": "2026-11-12T10:00:00Z"},
                {"ghsa_id": "GHSA-o", "cve_id": "CVE-2026-1", "published_at": "2026-10-20T10:00:00Z"},
                {"ghsa_id": "GHSA-u", "cve_id": None, "published_at": None}]
        self.assertEqual(w.github_recent(advs, now - timedelta(days=7)), [])
        self.assertEqual([r["id"] for r in w.github_recent(advs, now - timedelta(days=w.BACKFILL_DAYS))], ["GHSA-r"])


if __name__ == "__main__":
    unittest.main()
