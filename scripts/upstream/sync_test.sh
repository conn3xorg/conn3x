#!/usr/bin/env bash
# Copyright (c) The Conn3x Authors
# SPDX-License-Identifier: MPL-2.0
#
# Tests for sync.sh against a throwaway upstream repository.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }

git_q() { git -c user.name=t -c user.email=t@example.com -c commit.gpgsign=false -c tag.gpgsign=false "$@"; }

# Fake upstream: v1 has one file, v2 adds a kept file and two stripped ones.
up="$work/upstream"
git_q init -q "$up"
mkdir -p "$up/internal"
echo 'package foo // v1' > "$up/internal/foo.go"
mkdir -p "$up/cmd/tofu" && echo 'package main // v1' > "$up/cmd/tofu/x.go"
git_q -C "$up" add -A && git_q -C "$up" commit -qm v1 && git_q -C "$up" tag v1
echo 'package foo // v2' > "$up/internal/foo.go"
echo 'package bar' > "$up/internal/bar.go"
mkdir -p "$up/cmd/tofu" && echo 'package main // v2' > "$up/cmd/tofu/x.go"
echo 'agents' > "$up/AGENTS.md"
mkdir -p "$up/.github" && echo 'x: 1' > "$up/.github/x.yml"
git_q -C "$up" add -A && git_q -C "$up" commit -qm v2 && git_q -C "$up" tag v2

# Target: a snapshot of v1, laid out like this repository.
new_target() {
  local t="$1"
  git_q init -q "$t"
  mkdir -p "$t/internal/conn3x/version" "$t/scripts/upstream"
  git -C "$up" show v1:internal/foo.go > "$t/internal/foo.go"
  mkdir -p "$t/cmd/tofu" "$t/cmd/conn3x"
  git -C "$up" show v1:cmd/tofu/x.go > "$t/cmd/tofu/x.go"
  git -C "$up" show v1:cmd/tofu/x.go > "$t/cmd/conn3x/x.go"
  echo v1 > "$t/internal/conn3x/version/UPSTREAM"
  cp "$here/sync.sh" "$here/strip-paths.txt" "$t/scripts/upstream/"
  git_q -C "$t" add -A && git_q -C "$t" commit -qm snapshot
}

export UPSTREAM_REPO="$up"
export UPSTREAM_CACHE="$work/cache.git"

# Case 1: clean sync keeps code, drops stripped paths, bumps UPSTREAM.
t1="$work/t1"; new_target "$t1"
(cd "$t1" && bash scripts/upstream/sync.sh v1 v2) \
  || fail "clean sync exited non-zero"
grep -q 'v2' "$t1/internal/foo.go" || fail "foo.go not updated"
[ -f "$t1/internal/bar.go" ] || fail "bar.go not added"
[ ! -e "$t1/AGENTS.md" ] || fail "AGENTS.md was not stripped"
[ ! -e "$t1/.github/x.yml" ] || fail ".github/x.yml was not stripped"
[ "$(cat "$t1/internal/conn3x/version/UPSTREAM")" = v2 ] || fail "UPSTREAM not bumped"
grep -q 'v2' "$t1/cmd/tofu/x.go" || fail "cmd/tofu/x.go not updated"
grep -q 'v2' "$t1/cmd/conn3x/x.go" || fail "cmd/conn3x/x.go not updated"

# Case 2: a local edit to an upstream-owned line conflicts and fails loudly.
t2="$work/t2"; new_target "$t2"
echo 'package foo // local edit' > "$t2/internal/foo.go"
git_q -C "$t2" commit -qam local
set +e
err=$(cd "$t2" && bash scripts/upstream/sync.sh v1 v2 2>&1 >/dev/null)
code=$?
set -e
[ "$code" -ne 0 ] || fail "conflicting sync exited zero"
echo "$err" | grep -q 'CONFLICT' || fail "no CONFLICT message on stderr: $err"

echo "PASS: sync_test.sh"
