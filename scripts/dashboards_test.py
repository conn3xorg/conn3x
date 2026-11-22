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

    def test_questions_are_not_claims(self):
        for body in ["I would like to know why this fails", "the claim in the README is wrong", "I'd love to see this land"]:
            self.assertIsNone(d.claim(self.issue(comments=[("dev", body)])), body)
        self.assertEqual(d.claim(self.issue(comments=[("dev", "I would love to help with this")])), "taken by `@dev`")

    def test_another_maintainers_comment_is_not_a_claim(self):
        issue = self.issue()
        issue["comments"]["nodes"] = [{"author": {"login": "other"}, "authorAssociation": "MEMBER", "body": "I'll take this"}]
        self.assertIsNone(d.claim(issue))


def issue(title, repo="circuit-x", labels=("help wanted",), assignees=()):
    return {"title": title, "url": f"https://github.com/conn3xorg/{repo}/issues/1",
            "createdAt": "2026-11-01T00:00:00Z", "repository": {"name": repo},
            "labels": {"nodes": [{"name": l} for l in labels]},
            "assignees": {"nodes": [{"login": a} for a in assignees]}, "comments": {"nodes": []},
            "closedByPullRequestsReferences": {"totalCount": 0}}


NOW = datetime(2026, 11, 6, tzinfo=timezone.utc)


class Templates(unittest.TestCase):
    def test_template_match(self):
        self.assertEqual(d.template(issue("Help raise circuit-x's grade (now C)")), (2, "circuit-x"))
        self.assertEqual(d.template(issue("Help wanted: try to break circuit-x and review its code")), (1, "circuit-x"))
        self.assertEqual(d.template(issue("Writers wanted: make the circuit-x README clearer for someone new",
                                          labels=("writers wanted", "good first issue"))), (0, "circuit-x"))
        # The circuit in the title must be the repo the issue lives in.
        self.assertIsNone(d.template(issue("Help raise circuit-y's grade (now C)")))
        self.assertIsNone(d.template(issue("Check each sudoers drop-in with visudo")))

    def test_board_groups_templates_as_repo_links(self):
        body = d.help_board([
            issue("Writers wanted: make the circuit-a README clearer for someone new", "circuit-a", ("writers wanted", "good first issue")),
            issue("Writers wanted: make the circuit-b README clearer for someone new", "circuit-b", ("writers wanted",), ["dev"]),
            issue("Help raise circuit-a's grade (now C)", "circuit-a"),
            issue("Help raise circuit-c's grade (now C)", "circuit-c"),
            issue("Support state = absent", "conn3x", ("good first issue",)),
        ], {"circuit-a": "B", "circuit-c": "A"}, NOW)
        self.assertEqual(body.count("/issues/1)"), 1, "only the one-off issue gets an issue link")
        self.assertIn("[circuit-a](https://github.com/conn3xorg/circuit-a/issues?q=is%3Aopen+label%3A%22writers+wanted%22)", body)
        self.assertIn("README clearer (1 free)", body)
        self.assertIn("1 more already taken.", body)
        self.assertNotIn("circuit-c", body, "grade is already A, so that issue is done")
        self.assertIn("3 of 4 are free right now.", body)
        self.assertLess(body.index("Good first issues"), body.index("One per circuit"))


class Fitting(unittest.TestCase):
    def test_body_shrinks_under_limit(self):
        body = d.help_board([issue("x" * 400)] * 400, {}, NOW)
        self.assertLess(len(body), d.BODY_LIMIT)
        self.assertIn("more. [See them all]", body)


if __name__ == "__main__":
    unittest.main()


class Boards(unittest.TestCase):
    """Only a maintainer's or this workflow's issue can hold a board."""

    def board(self, n, login, role):
        return {"number": n, "body": "<!-- conn3x-dashboard:help-wanted -->\nx",
                "user": {"login": login}, "author_association": role}

    def lookup(self, issues):
        real, calls = d.gh, []
        d.gh = lambda *a, **k: calls.append(a) or issues
        try:
            return d.existing_boards(), calls
        finally:
            d.gh = real

    def test_a_strangers_issue_with_the_marker_is_ignored(self):
        # Newest first, as GitHub lists them: the stranger's comes first.
        found, _ = self.lookup([self.board(900, "stranger", "NONE"), self.board(383, "jamesconwaydev", "OWNER")])
        self.assertEqual(found, {"help-wanted": 383})

    def test_the_workflows_own_issue_counts(self):
        found, _ = self.lookup([self.board(900, "stranger", "CONTRIBUTOR"), self.board(383, "github-actions[bot]", "NONE")])
        self.assertEqual(found, {"help-wanted": 383})

    def test_a_strangers_board_alone_makes_a_new_one(self):
        found, _ = self.lookup([self.board(900, "stranger", "NONE")])
        self.assertEqual(found, {})


class Outside(unittest.TestCase):
    def test_another_maintainers_pr_is_not_outside(self):
        self.assertFalse(d.outside(pr(author={"__typename": "User", "login": "other"}, authorAssociation="COLLABORATOR")))
        self.assertTrue(d.outside(pr(authorAssociation="CONTRIBUTOR")))
        self.assertFalse(d.outside(pr(author={"__typename": "Bot", "login": "renovate"}, authorAssociation="NONE")))
