# Copyright (c) The Conn3x Authors
# SPDX-License-Identifier: MPL-2.0
"""Tests for dashboards.py: escaping, claims and PR buckets. No network."""

import os
import re
import sys
import unittest
from datetime import datetime, timezone

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dashboards as d  # noqa: E402


def pr(**kw):
    base = {
        "isDraft": False, "mergeable": "MERGEABLE", "createdAt": "2026-11-01T00:00:00Z",
        "author": {"__typename": "User", "login": "dev"},
        "commits": {"nodes": [{"commit": {"committedDate": "2026-11-01T00:00:00Z",
                                           "statusCheckRollup": {"state": "SUCCESS"}}}]},
        "reviews": {"nodes": []}, "comments": {"nodes": []},
    }
    base.update(kw)
    return base


def comment(login, when, role="NONE"):
    return {"author": {"login": login}, "authorAssociation": role, "createdAt": when}


class Escaping(unittest.TestCase):
    def test_handles_never_bare(self):
        out = d.esc("thanks @someone and @org/team, mail a@b.com, `@quoted`")
        self.assertIsNone(re.search(r"(?<!`)@(someone|org/team)\b", out), out)
        self.assertIn("`@someone`", out)
        self.assertIn("`@org/team`", out)
        self.assertIn("a@b.com", out)
        self.assertNotIn("``@quoted``", out)
        self.assertEqual(d.handle("dev"), "`@dev`")

    def test_table_and_markup(self):
        self.assertEqual(d.esc("a | b\n<!-- c --> #12"), "a \\| b &lt;!-- c --> `#12`")


class Buckets(unittest.TestCase):
    def test_new_pr_waits_on_us(self):
        self.assertEqual(d.bucket(pr()), ("maintainer", "2026-11-01T00:00:00Z"))

    def test_maintainer_reply_hands_turn_to_author(self):
        p = pr(comments={"nodes": [comment("jamesconwaydev", "2026-11-02T00:00:00Z", "OWNER")]})
        self.assertEqual(d.bucket(p), ("author", "2026-11-02T00:00:00Z"))

    def test_author_reply_hands_it_back(self):
        p = pr(comments={"nodes": [comment("jamesconwaydev", "2026-11-02T00:00:00Z", "OWNER"),
                                   comment("dev", "2026-11-03T00:00:00Z")]})
        self.assertEqual(d.bucket(p), ("maintainer", "2026-11-03T00:00:00Z"))

    def test_outsider_comment_does_not_count(self):
        p = pr(comments={"nodes": [comment("passerby", "2026-11-02T00:00:00Z")]})
        self.assertEqual(d.bucket(p)[0], "maintainer")

    def test_order_draft_rebase_ci(self):
        red = {"nodes": [{"commit": {"committedDate": "2026-11-01T00:00:00Z", "statusCheckRollup": {"state": "FAILURE"}}}]}
        self.assertEqual(d.bucket(pr(isDraft=True, mergeable="CONFLICTING", commits=red))[0], "draft")
        self.assertEqual(d.bucket(pr(mergeable="CONFLICTING", commits=red))[0], "rebase")
        self.assertEqual(d.bucket(pr(commits=red))[0], "ci")

    def test_outside_excludes_core_and_bots(self):
        self.assertTrue(d.outside(pr()))
        self.assertFalse(d.outside(pr(author={"__typename": "Bot", "login": "dependabot"})))
        self.assertFalse(d.outside(pr(author={"__typename": "User", "login": "jamesconwaydev"})))


class Claims(unittest.TestCase):
    def issue(self, assignees=(), comments=(), prs=0):
        return {"assignees": {"nodes": [{"login": a} for a in assignees]},
                "comments": {"nodes": [{"author": {"login": w}, "body": b} for w, b in comments]},
                "closedByPullRequestsReferences": {"totalCount": prs}}

    def test_claims(self):
        self.assertIsNone(d.claim(self.issue(comments=[("dev", "Nice idea")])))
        self.assertEqual(d.claim(self.issue(comments=[("dev", "I'd like to work on this")])), "taken by `@dev`")
        self.assertIsNone(d.claim(self.issue(comments=[("jamesconwaydev", "can I take this? kidding")])))
        self.assertEqual(d.claim(self.issue(assignees=["a"])), "taken by `@a`")
        self.assertEqual(d.claim(self.issue(prs=1)), "taken (PR open)")


class Fitting(unittest.TestCase):
    def test_body_shrinks_under_limit(self):
        now = datetime(2026, 11, 6, tzinfo=timezone.utc)
        issues = [{"title": "x" * 400, "url": "https://example.com", "createdAt": "2026-11-01T00:00:00Z",
                   "repository": {"name": "circuit-x"}, "labels": {"nodes": [{"name": "help wanted"}]},
                   "assignees": {"nodes": []}, "comments": {"nodes": []},
                   "closedByPullRequestsReferences": {"totalCount": 0}}] * 400
        body = d.help_board(issues, now)
        self.assertLess(len(body), d.BODY_LIMIT)
        self.assertIn("more. [See them all]", body)


if __name__ == "__main__":
    unittest.main()
