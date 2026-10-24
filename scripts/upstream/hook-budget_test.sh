#!/usr/bin/env bash
# Copyright (c) The Conn3x Authors
# SPDX-License-Identifier: MPL-2.0
#
# Tests for hook-budget.sh against a throwaway upstream repository.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
git_q() { git -c user.name=t -c user.email=t@example.com -c commit.gpgsign=false -c tag.gpgsign=false -c core.hooksPath=/dev/null "$@"; }

up="$work/upstream"
git_q init -q "$up"
mkdir -p "$up/internal/a" "$up/cmd/tofu"
for f in one two three four; do echo "package a // $f" > "$up/internal/a/$f.go"; done
echo "package main" > "$up/cmd/tofu/main.go"
ln -s one.go "$up/internal/a/link.go"
echo "upstream licence" > "$up/LICENSE"
git_q -C "$up" add -A && git_q -C "$up" commit -qm v1 && git_q -C "$up" tag v1

new_target() {
  local t="$1"
  git_q clone -q "$up" "$t"
  mkdir -p "$t/scripts/upstream"
  cp "$here/hook-budget.sh" "$t/scripts/upstream/"
  echo "LICENSE" > "$t/scripts/upstream/strip-paths.txt"
  echo "our licence" > "$t/LICENSE"
}
export UPSTREAM_REPO="$up"
export UPSTREAM_CACHE="$work/cache.git"
run() { (cd "$1" && bash scripts/upstream/hook-budget.sh v1 "$2" 2>&1); }

# Marked edits within budget pass; our own trees and new files never count.
t1="$work/t1"; new_target "$t1"
printf 'package a // one\n// CONN3X: hook\n' > "$t1/internal/a/one.go"
mkdir -p "$t1/internal/conn3x" "$t1/cmd/conn3x"
echo "package conn3x" > "$t1/internal/conn3x/x.go"
echo "package new" > "$t1/internal/a/new.go"
echo "package main // changed copy" > "$t1/cmd/conn3x/main.go"
out=$(run "$t1" 3) || fail "marked edit, symlink or stripped file rejected: $out"
echo "$out" | grep -q "1 of 3 upstream files changed" || fail "wrong count: $out"

# An unmarked edit fails and names the file.
t2="$work/t2"; new_target "$t2"
echo "package a // edited" > "$t2/internal/a/two.go"
if out=$(run "$t2" 3); then fail "unmarked edit accepted"; fi
echo "$out" | grep -q "missing CONN3X marker: internal/a/two.go" || fail "no marker message: $out"

# Too many touched upstream files fails.
t3="$work/t3"; new_target "$t3"
for f in one two three four; do printf 'package a // %s\n// CONN3X: hook\n' "$f" > "$t3/internal/a/$f.go"; done
if out=$(run "$t3" 3); then fail "budget overrun accepted"; fi
echo "$out" | grep -q "hook budget exceeded: 4 upstream files changed, limit 3" || fail "no budget message: $out"

echo "PASS: hook-budget_test.sh"
