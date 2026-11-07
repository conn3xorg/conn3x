# Contributing to Conn3x

Thanks for helping out. Conn3x is early, so the most useful things right now
are bug reports, design feedback in
[Discussions](https://github.com/conn3xorg/conn3x/discussions), and small,
focused pull requests.

## If you came to write

You don't need to write Go, or build anything, to help with the docs.
Everything below works from the browser.

### Where the words live

- The docs at [docs.conn3x.org](https://docs.conn3x.org) and the website at
  [conn3x.org](https://conn3x.org) live in
  [conn3xorg/web](https://github.com/conn3xorg/web). Each docs page is a
  Markdown file under `apps/docs/src/content/docs/`.
- The module pages, such as [file](https://docs.conn3x.org/modules/file), are
  the exception. Their argument tables are generated from the code, and their
  introductions, examples and notes come from
  `internal/conn3x/provider/moddoc/pages/` in this repository. Change them
  here: the copies in `conn3xorg/web` are overwritten each time the pages are
  regenerated.
- This file, the [README](README.md) and [SECURITY.md](SECURITY.md) live in
  this repository.
- The [style guide](https://docs.conn3x.org/style) records how we write:
  sentence-case headings, contractions, backticks for commands and paths.

### Make a small change from the browser

1. On any docs page, click **Edit page** at the bottom. It opens the page's
   Markdown on GitHub. The first time, GitHub makes a copy of the repository
   (a fork) under your account for you.
2. Make your change, and check it with **Preview**.
3. Click **Commit changes**. Write a short message that says what was wrong,
   such as `docs: the install page skipped a step`. In the extended
   description, add your sign-off line at the end (see below).
4. Click **Propose changes**, then **Create pull request**.

### What a sign-off is, and why we ask for one

A sign-off is a line at the end of a commit message:

```
Signed-off-by: Your Name <you@example.com>
```

With it, you certify that you wrote the change, or have the right to submit
it, under the project's license. That's the
[Developer Certificate of Origin](https://developercertificate.org/). It lets
the project show where every change came from without asking you to sign an
agreement or hand over your copyright. Your name stays on your commit.

GitHub's editor doesn't add the line for you, so type it in yourself. The
email has to match the one GitHub puts on the commit, or the DCO check on your
pull request fails. If you keep your email private on GitHub, that's the
`@users.noreply.github.com` address shown in
[your email settings](https://github.com/settings/emails). From a terminal,
`git commit -s` adds the line for you.

### Where to start

Issues for writers carry the
[writers wanted](https://github.com/search?q=org%3Aconn3xorg+label%3A%22writers+wanted%22+state%3Aopen&type=issues)
label. If you're unsure of a fact, ask on the issue: we check every claim
before it goes out. To tell us what you'd like to write, post in
[Discussions](https://github.com/conn3xorg/conn3x/discussions).
[Get involved](https://docs.conn3x.org/contribute) lists other ways to help.

The rest of this file is about the code.

## Before you start

For anything bigger than a bug fix, open a discussion or an issue first.
It's much easier to agree on an approach before the code exists than to
rework a finished PR.

## Development setup

You need Go at the version named in `go.mod`. If your local Go is older,
the Go toolchain downloads the right version for you.

```sh
git clone https://github.com/conn3xorg/conn3x.git
cd conn3x
go build ./cmd/conn3x
./conn3x version
```

Run the checks CI runs:

```sh
go test ./internal/conn3x/... ./cmd/conn3x/... ./internal/dag/... ./internal/configs/... ./internal/addrs/...
go test -run Conn3x ./internal/tofu/
golangci-lint run ./internal/conn3x/... ./cmd/conn3x/... ./cmd/conn3x-agent/...
bash scripts/upstream/hook-budget.sh "$(cat internal/conn3x/version/UPSTREAM)" 5
bash scripts/upstream/sync_test.sh
bash scripts/upstream/commit_payload_test.sh
bash scripts/upstream/hook-budget_test.sh
bash scripts/dco-check_test.sh
bash scripts/build-agent_test.sh
```

The `dag`, `configs`, and `addrs` packages are upstream code that Conn3x
changes or leans on, so their tests run on every PR, along with the Conn3x
tests in `internal/tofu`. The hook budget caps how many upstream files carry
a Conn3x change at 5, and all 5 are taken:

- `internal/addrs/provider.go`: `conn3x` is a built-in provider
- `internal/configs/parser_config.go`: circuits lower to resources
- `internal/configs/parser_config_dir.go`: `*.circuit.hcl` files, and circuit
  names unique across files
- `internal/command/meta_providers.go`: the built-in providers are registered
- `internal/tofu/transform_reference.go`: a circuit with
  `strategy = "per_host"` chains its steps per host

A new hook has to free one of these slots first.

## How the code is laid out

Conn3x is built on [OpenTofu](https://github.com/opentofu/opentofu). The
upstream code is imported as-is and kept in sync with OpenTofu releases by
`scripts/upstream/sync.sh`. Conn3x's own code lives in:

- `cmd/conn3x/`, the CLI entry point
- `internal/conn3x/`, everything else that's ours

Keep changes to upstream files to a minimum, since every one of them has to
be carried through each sync. If you really need to touch one, mark the
change with a `// CONN3X:` comment that explains why.

## Commits

Every commit needs a [Developer Certificate of Origin](https://developercertificate.org/)
sign-off. Add it with `-s`:

```sh
git commit -s -m "fix: handle empty host list"
```

The sign-off certifies that you wrote the change, or otherwise have the
right to submit it under the project's license. Conn3x has no CLA and
never asks you to assign copyright.

Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/):
`feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `build:`, `ci:`, `chore:`.
Keep the subject under 72 characters and say what the problem was, not
just what you did.

## Pull requests

- Branch from `main` and open the PR against `main`. Nobody pushes to
  `main` directly, maintainers included.
- Keep each PR to one change. Two unrelated fixes are two PRs.
- Add or update tests. A bug fix starts with a test that fails without it.
- Update the docs in the same PR when you change behavior.
- CI has to pass: `lint`, `test`, `build`, and `DCO`.
- PRs are squash-merged, so the PR title becomes the commit subject.

## When a pull request goes quiet

Life happens, and nobody owes the project their evenings. A person, not a
bot, keeps an eye on open pull requests, and here's what to expect:

- We aim to reply to a new PR within a few days. While a PR is waiting on
  us, it never goes stale.
- Once we've asked for a change or a rebase, the PR is waiting on you, and
  there's still no rush. After 30 days without a reply we'll leave a
  comment to check in.
- After 60 days without a reply, we may close the PR, or finish the change
  ourselves if it's close. If we finish it, your commits stay in it or
  you're credited with a `Co-authored-by:` line, and you're thanked in the
  release notes either way.
- A closed PR can always be reopened. Come back whenever you like.

If you'd like to take an issue, say so on the issue and give a rough idea
of when you expect to open a PR. If you need longer, just say so and it
stays yours. If the time passes with no word, the issue is open for
someone else.

## License

By contributing, you agree that your contributions are licensed under the
[Mozilla Public License 2.0](LICENSE).
