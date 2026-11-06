# Copyright (c) The Conn3x Authors
# SPDX-License-Identifier: MPL-2.0
"""Refresh the three community dashboards pinned in conn3xorg/conn3x.

Help wanted, community pull requests and circuit health, each gathered
across the whole org and written into one issue apiece. Each issue is found
by a hidden marker in its body, so a run edits the same issue every time and
only creates one when it is missing.

Needs the gh CLI, authenticated (GH_TOKEN in Actions). Read-only on every
repo except the dashboard repo, where it needs issues: write.

    python3 scripts/dashboards.py --dry-run [--out DIR]
"""

import argparse
import concurrent.futures
import json
import os
import re
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone

ORG = "conn3xorg"
DASHBOARD_REPO = "conn3xorg/conn3x"
CORE_TEAM = {"jamesconwaydev"}
MAINTAINER_ROLES = {"OWNER", "MEMBER", "COLLABORATOR"}
# First label that matches decides the section, so an issue shows up once.
KINDS = [
    ("good first issue", "🌱 Good first issues"),
    ("writers wanted", "✍️ Writers wanted"),
    ("help wanted", "🤝 Help wanted"),
]
# Issues opened from the same per-circuit template collapse into one line of
# repo links: a table row per circuit is a wall nobody reads, and repo links
# add no "mentioned this" entry to each issue's timeline.
TEMPLATES = [
    ("writers wanted", re.compile(r"Writers wanted: make the (circuit-[\w-]+) README clearer for someone new"),
     "✍️ Make a circuit README clearer",
     "Read a circuit's README the way someone deciding whether to use it would, and fix what "
     "loses you. No code needed, and you can edit it in the browser."),
    ("help wanted", re.compile(r"Help wanted: try to break (circuit-[\w-]+) and review its code"),
     "🔨 Try to break a circuit",
     "Run a circuit on a throwaway container or VM, try what its README doesn't mention, and "
     "read its code like a teammate's pull request. Finding a problem counts as much as fixing one."),
    ("help wanted", re.compile(r"Help raise (circuit-[\w-]+)'s grade \(now [A-F]\)"),
     "📈 Help raise a circuit's grade",
     "Each issue lists the checks a circuit is missing. Every one is a CI change you can make "
     "in one pull request, so pick one and say which in a comment."),
]
CONTRIBUTING = "https://github.com/conn3xorg/.github/blob/main/CONTRIBUTING.md"
BODY_LIMIT = 65000  # GitHub rejects issue bodies over 65536 characters.
CLAIM = re.compile(
    r"\b(i'?ll take|i will take|i'?d like to|i would like to|i'?d love to|"
    r"can i (take|work|pick|have)|may i (take|work)|assign (it |this )?(to )?me|"
    r"working on (this|it)|i'?m on (it|this)|claim(ing)?|dibs)\b",
    re.I,
)
EXPIRY = re.compile(r"\bkey\b.*\bexpir", re.I)

calls = 0


def gh(*args, payload=None):
    global calls
    for attempt in range(3):
        calls += 1
        out = subprocess.run(
            ["gh", "api", *args],
            input=None if payload is None else json.dumps(payload),
            capture_output=True, text=True, check=False,
        )
        # Big GraphQL searches sometimes get a 502; a second try usually works.
        if out.returncode == 0 or "HTTP 5" not in out.stderr or attempt == 2:
            break
        time.sleep(10)
    if out.returncode != 0:
        sys.exit(f"gh api {' '.join(args[:3])} failed: {out.stderr.strip()}")
    return json.loads(out.stdout) if out.stdout.strip() else None


def graphql(query, **variables):
    data = gh("graphql", "--input", "-", payload={"query": query, "variables": variables})
    if data.get("errors"):
        sys.exit(f"GraphQL error: {data['errors']}")
    return data["data"]


def search(query, fields):
    q = """query($q: String!, $after: String) {
      search(query: $q, type: ISSUE, first: 100, after: $after) {
        pageInfo { hasNextPage endCursor }
        nodes { %s }
      }
    }""" % fields
    nodes, after = [], None
    while True:
        page = graphql(q, q=query, after=after)["search"]
        nodes += [n for n in page["nodes"] if n]
        if not page["pageInfo"]["hasNextPage"]:
            return nodes
        after = page["pageInfo"]["endCursor"]


# ---- Formatting -----------------------------------------------------------

def esc(text):
    """Make text safe for a table cell that must never notify anyone."""
    text = " ".join(text.split()).replace("|", "\\|").replace("<", "&lt;")
    text = re.sub(r"(?<![\w`])@([A-Za-z0-9][\w-]*(?:/[\w.-]+)?)", r"`@\1`", text)
    # A bare #12 would link to an issue in the dashboard repo, not the one meant.
    return re.sub(r"(?<![\w`&])#(\d+)", r"`#\1`", text)


def handle(login):
    return f"`@{login}`"


def ts(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def age(since, now):
    hours = int((now - since).total_seconds() // 3600)
    if hours < 1:
        return "<1h"
    if hours < 48:
        return f"{hours}h"
    return f"{hours // 24}d"


def table(header, rows, empty="Nothing here right now."):
    if not rows:
        return empty + "\n"
    lines = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    lines += ["| " + " | ".join(r) + " |" for r in rows]
    return "\n".join(lines) + "\n"


def capped(rows, cap, more_url):
    if cap is None or len(rows) <= cap:
        return rows, ""
    return rows[:cap], f"\n…and {len(rows) - cap} more. [See them all]({more_url}).\n"


def fit(render):
    """Render, shrinking the per-section row cap until the body fits."""
    body, cap = render(None), 200
    while len(body) > BODY_LIMIT and cap > 5:
        body, cap = render(cap), cap // 2
    return body


def header(title, marker, now, intro):
    return (
        f"<!-- conn3x-dashboard:{marker} -->\n# {title}\n\n"
        f"_Snapshot taken {now:%Y-%m-%d %H:%M} UTC. This issue updates itself every hour, "
        "so please don't edit it by hand._\n\n" + intro.strip() + "\n"
    )


def search_url(q):
    return "https://github.com/search?type=issues&q=" + urllib.parse.quote(q)


# ---- Help wanted ----------------------------------------------------------

HELP_FIELDS = """... on Issue {
  number title url createdAt repository { name } author { login }
  labels(first: 20) { nodes { name } }
  assignees(first: 3) { nodes { login } }
  comments(last: 30) { nodes { author { login } body } }
  closedByPullRequestsReferences(first: 1, includeClosedPrs: false) { totalCount }
}"""


def claim(issue):
    """Who has this issue, as display text, or None if it is free."""
    assignees = [a["login"] for a in issue["assignees"]["nodes"]]
    if assignees:
        return "taken by " + ", ".join(map(handle, assignees))
    if issue["closedByPullRequestsReferences"]["totalCount"]:
        return "taken (PR open)"
    for c in reversed(issue["comments"]["nodes"]):
        who = (c["author"] or {}).get("login", "")
        if who and who not in CORE_TEAM and not who.endswith("[bot]") and CLAIM.search(c["body"]):
            return "taken by " + handle(who)
    return None


def kind(issue):
    names = {l["name"] for l in issue["labels"]["nodes"]}
    return next((label for label, _ in KINDS if label in names), None)


def template(issue):
    """Return (template index, circuit) for a templated issue, else None."""
    for n, (_, pattern, _, _) in enumerate(TEMPLATES):
        m = pattern.fullmatch(" ".join(issue["title"].split()))
        if m and m.group(1) == issue["repository"]["name"]:
            return n, m.group(1)
    return None


def help_board(issues, grades, now):
    intro = f"""
Every open issue across Conn3x where we'd love a hand, in one place. Find one
marked **free**, say on the issue that you're taking it, and it's yours. A
question first is fine too.

New here? The [contributing guide]({CONTRIBUTING}) covers setup, testing
against a real host and how review works. Writers wanted issues need no code
at all: if a README confused you, you're exactly who we want fixing it.

**Taken** means someone is assigned, has said they're on it, or has an open
pull request linked. If one has gone quiet for a few weeks, ask on the issue.
"""
    groups = {label: [] for label, _ in KINDS}
    templated = [[] for _ in TEMPLATES]  # free circuits per template
    taken = [0] * len(TEMPLATES)
    free = total = 0
    for i in sorted(issues, key=lambda i: i["createdAt"]):
        t = template(i)
        if t:
            n, circuit = t
            # A grade issue is done once the live badge says A, whatever its title says.
            if "grade" in TEMPLATES[n][1].pattern and grades.get(circuit) == "A":
                continue
            total += 1
            if claim(i):
                taken[n] += 1
            else:
                free += 1
                templated[n].append(circuit)
        elif kind(i):
            total += 1
            free += not claim(i)
            groups[kind(i)].append(i)

    def render(cap):
        out = [header("🙋 Help wanted across Conn3x", "help-wanted", now, intro)]
        out.append(f"\n{free} of {total} are free right now.\n")
        for label, title in KINDS:
            rows = [[
                f"[{esc(i['title'])}]({i['url']})",
                f"`{i['repository']['name']}`",
                age(ts(i["createdAt"]), now),
                claim(i) or "**free**",
            ] for i in groups[label]]
            rows, more = capped(rows, cap, search_url(f'org:{ORG} is:issue is:open label:"{label}"'))
            out.append(f"\n## {title} ({len(groups[label])})\n\n")
            out.append(table(["Issue", "Repo", "Age", "Status"], rows) + more)
        out.append("\n## One per circuit\n\nThe same job, open on lots of circuits. "
                   "Each link goes to that circuit's open issues.\n")
        for n, (label, _, title, blurb) in enumerate(TEMPLATES):
            q = urllib.parse.quote_plus(f'is:open label:"{label}"')
            links = [f"[{c}](https://github.com/{ORG}/{c}/issues?q={q})" for c in templated[n]]
            note = f" {taken[n]} more already taken." if taken[n] else ""
            out.append(f"\n### {title} ({len(links)} free)\n\n{blurb}{note}\n\n")
            out.append((", ".join(links) or "None free right now.") + "\n")
        return "".join(out)

    return fit(render)


# ---- Pull requests --------------------------------------------------------

PR_FIELDS = """... on PullRequest {
  number title url isDraft createdAt additions deletions changedFiles mergeable
  repository { name } author { __typename login }
  commits(last: 1) { nodes { commit { committedDate statusCheckRollup { state } } } }
  reviews(last: 30) { nodes { author { login } authorAssociation submittedAt } }
  comments(last: 30) { nodes { author { login } authorAssociation createdAt } }
}"""

BUCKETS = [
    ("maintainer", "Waiting on us", "We owe these a review or a reply."),
    ("author", "Waiting on the author", "We've left feedback, so the next move is yours."),
    ("ci", "Failing CI", "Checks are red. The logs usually say why; ask on the PR if they don't."),
    ("rebase", "Needs a rebase", "These conflict with the base branch."),
    ("draft", "Drafts", "Still in progress. Mark it ready when you want a review."),
]


def outside(pr):
    a = pr["author"]
    return bool(a) and a["__typename"] != "Bot" and a["login"] not in CORE_TEAM


def bucket(pr):
    """Return (bucket, waiting since) for one PR."""
    author = pr["author"]["login"]
    commit = pr["commits"]["nodes"][0]["commit"] if pr["commits"]["nodes"] else {}
    last_author = max([pr["createdAt"], commit.get("committedDate") or pr["createdAt"]])
    last_us = None
    for item in pr["reviews"]["nodes"] + pr["comments"]["nodes"]:
        who = (item["author"] or {}).get("login")
        when = item.get("submittedAt") or item.get("createdAt")
        if not who or not when:
            continue
        if who == author:
            last_author = max(last_author, when)
        elif item["authorAssociation"] in MAINTAINER_ROLES or who in CORE_TEAM:
            last_us = max(last_us or when, when)
    if pr["isDraft"]:
        return "draft", last_author
    if pr["mergeable"] == "CONFLICTING":
        return "rebase", last_author
    if (commit.get("statusCheckRollup") or {}).get("state") in ("FAILURE", "ERROR"):
        return "ci", last_author
    if last_us and last_us > last_author:
        return "author", last_us
    return "maintainer", last_author


def pr_board(prs, now):
    intro = f"""
Open pull requests from the community across every Conn3x repo. That's
everyone except {handle("jamesconwaydev")} and the bots. If yours is here,
thank you.

Each list is sorted by how long it has been waiting, longest first.
"""
    groups = {key: [] for key, _, _ in BUCKETS}
    for pr in prs:
        key, since = bucket(pr)
        groups[key].append((ts(since), pr))
    out = [header("🔀 Community pull requests", "pr-triage", now, intro)]
    for key, title, blurb in BUCKETS:
        rows = [[
            f"[{esc(pr['title'])}]({pr['url']})",
            f"`{pr['repository']['name']}`",
            handle(pr["author"]["login"]),
            f"+{pr['additions']} −{pr['deletions']}, {pr['changedFiles']} file{'s' * (pr['changedFiles'] != 1)}",
            age(since, now),
        ] for since, pr in sorted(groups[key], key=lambda x: x[0])]
        out.append(f"\n## {title} ({len(rows)})\n\n{blurb}\n\n")
        out.append(table(["Pull request", "Repo", "Author", "Size", "Waiting"], rows))
    return "".join(out)


# ---- Circuit health -------------------------------------------------------

REPOS = """query($after: String) {
  organization(login: "%s") {
    repositories(first: 100, after: $after, orderBy: {field: NAME, direction: ASC}) {
      pageInfo { hasNextPage endCursor }
      nodes {
        name isArchived
        issues(states: OPEN) { totalCount }
        refs(refPrefix: "refs/tags/", first: 1, orderBy: {field: TAG_COMMIT_DATE, direction: DESC}) { nodes { name } }
        defaultBranchRef { target { ... on Commit { statusCheckRollup { state } } } }
      }
    }
  }
}""" % ORG

CI = {"SUCCESS": "✅ passing", "FAILURE": "❌ failing", "ERROR": "❌ failing",
      "PENDING": "⏳ pending", "EXPECTED": "⏳ pending"}


def circuits():
    repos, after = [], None
    while True:
        page = graphql(REPOS, after=after)["organization"]["repositories"]
        repos += [r for r in page["nodes"] if r["name"].startswith("circuit-") and not r["isArchived"]]
        if not page["pageInfo"]["hasNextPage"]:
            return repos
        after = page["pageInfo"]["endCursor"]


def grade(name):
    url = f"https://conn3x.org/circuits/{name.removeprefix('circuit-')}/grade.svg"
    try:
        # The site's CDN turns away Python's default User-Agent.
        req = urllib.request.Request(url, headers={"User-Agent": f"conn3x-dashboards (+https://github.com/{DASHBOARD_REPO})"})
        with urllib.request.urlopen(req, timeout=15) as r:
            m = re.search(r'aria-label="Conn3x grade: ([^"]+)"', r.read(4096).decode("utf-8", "replace"))
    except OSError:
        return None
    return m.group(1) if m else None


def health_board(repos, grades, prs, expiring, now):
    intro = """
One row per circuit: its grade, latest tag, how CI looks on the main branch
and what's open. The grade comes from the badge on conn3x.org and reflects the
checks we run, not a security guarantee.
"""
    outside_prs = {}
    for pr in prs:
        outside_prs[pr["repository"]["name"]] = outside_prs.get(pr["repository"]["name"], 0) + 1
    rows, red = [], 0
    for r in repos:
        target = (r["defaultBranchRef"] or {}).get("target") or {}
        state = (target.get("statusCheckRollup") or {}).get("state")
        red += state in ("FAILURE", "ERROR")
        tag = r["refs"]["nodes"][0]["name"] if r["refs"]["nodes"] else None
        rows.append([
            f"[{r['name']}](https://github.com/{ORG}/{r['name']})",
            grades[r["name"]],
            f"`{esc(tag)}`" if tag else "none yet",
            CI.get(state, "no runs"),
            str(outside_prs.get(r["name"], 0)),
            str(r["issues"]["totalCount"]),
        ])
    out = [header("🩺 Circuit health", "circuit-health", now, intro)]
    out.append(f"\n{len(repos)} circuits, {red} with red CI on main.\n\n")
    out.append(table(["Circuit", "Grade", "Latest tag", "CI on main", "Outside PRs", "Open issues"], rows))
    out.append("\n## 🔑 Signing keys expiring\n\nOpen issues about an upstream key that's about to expire.\n\n")
    out.append(table(["Issue", "Repo", "Opened"], [[
        f"[{esc(i['title'])}]({i['url']})", f"`{i['repository']['name']}`", age(ts(i["createdAt"]), now),
    ] for i in expiring], empty="None open right now."))
    return "".join(out)


# ---- Publishing -----------------------------------------------------------

def publish(boards):
    existing = {}
    page = 1
    while True:
        issues = gh(f"repos/{DASHBOARD_REPO}/issues?state=open&per_page=100&page={page}")
        for i in issues:
            m = re.match(r"<!-- conn3x-dashboard:([\w-]+) -->", i.get("body") or "")
            if m and "pull_request" not in i:
                existing.setdefault(m.group(1), i["number"])
        if len(issues) < 100:
            break
        page += 1
    for marker, (title, body) in boards.items():
        if marker in existing:
            gh("-X", "PATCH", f"repos/{DASHBOARD_REPO}/issues/{existing[marker]}", "--input", "-", payload={"body": body})
            print(f"updated #{existing[marker]} ({marker})")
        else:
            made = gh("-X", "POST", f"repos/{DASHBOARD_REPO}/issues", "--input", "-", payload={"title": title, "body": body})
            print(f"created #{made['number']} ({marker})")


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--dry-run", action="store_true", help="print the Markdown, change nothing")
    p.add_argument("--out", help="also write each dashboard to DIR/<marker>.md")
    args = p.parse_args()
    now = datetime.now(timezone.utc)

    repos = circuits()
    with concurrent.futures.ThreadPoolExecutor(8) as pool:
        grades = dict(zip((r["name"] for r in repos), pool.map(grade, (r["name"] for r in repos))))
    # A circuit without a published page on conn3x.org isn't public yet, so it
    # stays off every board.
    unlisted = {name for name, g in grades.items() if g is None}
    if len(unlisted) > len(grades) // 2:
        sys.exit(f"{len(unlisted)} of {len(grades)} grades missing; is conn3x.org down? Leaving the boards as they are.")
    repos = [r for r in repos if r["name"] not in unlisted]

    def listed(item):
        return item["repository"]["name"] not in unlisted

    labels = ",".join(f'"{label}"' for label, _ in KINDS)
    issues = search(f"org:{ORG} is:issue is:open label:{labels}", HELP_FIELDS)
    prs = [pr for pr in search(f"org:{ORG} is:pr is:open -author:{' -author:'.join(sorted(CORE_TEAM))}", PR_FIELDS) if outside(pr)]
    expiring = [i for i in search(f"org:{ORG} is:issue is:open in:title expire", "... on Issue { title url createdAt repository { name } }")
                if EXPIRY.search(i["title"])]
    issues, prs, expiring = (list(filter(listed, x)) for x in (issues, prs, expiring))

    boards = {
        "help-wanted": ("🙋 Help wanted across Conn3x", help_board(issues, grades, now)),
        "pr-triage": ("🔀 Community pull requests", pr_board(prs, now)),
        "circuit-health": ("🩺 Circuit health", health_board(repos, grades, prs, expiring, now)),
    }
    if args.out:
        os.makedirs(args.out, exist_ok=True)
        for marker, (_, body) in boards.items():
            with open(os.path.join(args.out, f"{marker}.md"), "w", encoding="utf-8") as f:
                f.write(body)
    if args.dry_run:
        for _, body in boards.values():
            print(body, end="\n\n---\n\n")
    else:
        publish(boards)
    print(f"{calls} GitHub API calls, {len(grades)} grade fetches", file=sys.stderr)


if __name__ == "__main__":
    main()
