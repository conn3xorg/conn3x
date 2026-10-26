# Contributing to Conn3x

Thanks for helping out. Conn3x is early, so the most useful things right now
are bug reports, design feedback in
[Discussions](https://github.com/conn3xorg/conn3x/discussions), and small,
focused pull requests.

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
go test ./internal/conn3x/... ./cmd/conn3x/...
golangci-lint run ./internal/conn3x/... ./cmd/conn3x/...
bash scripts/upstream/sync_test.sh
bash scripts/dco-check_test.sh
```

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

Life happens, and nobody owes the project their evenings. So you know what
to expect:

- We aim to reply to a new PR within a few days.
- If a PR is waiting on you, there's no deadline. After two weeks without
  activity we'll check in, just to see whether you still want to finish it.
- After a month with no reply, we may finish the change ourselves or close
  the PR. If we finish it, your commits stay in it, or you're credited with
  a `Co-authored-by:` line, and you're thanked in the release notes either
  way.
- A closed PR can always be reopened. Come back whenever you like.

The same goes for issues. If you've said you'll take one and two weeks pass
without a PR, it's open for someone else.

## License

By contributing, you agree that your contributions are licensed under the
[Mozilla Public License 2.0](LICENSE).
