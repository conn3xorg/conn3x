#!/usr/bin/env bash
# Copyright (c) The Conn3x Authors
# SPDX-License-Identifier: MPL-2.0
#
# Tests for build-agent.sh.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

# GOOS and GOARCH from a cross-compile must not leak into the agent.
GOOS=windows GOARCH=386 bash "$here/build-agent.sh" "$work/a" >/dev/null || fail "build failed"
for arch in amd64 arm64; do
  f="$work/a/conn3x-agent-linux-$arch.gz"
  [ -s "$f" ] || fail "no $f"
  [ "$(gzip -dc "$f" | head -c 4 | tail -c 3)" = ELF ] || fail "$f is not an ELF binary"
done
# Nothing from git goes in, so another commit doesn't change the agent.
gzip -dc "$work/a/conn3x-agent-linux-amd64.gz" >"$work/agent"
if go version -m "$work/agent" | grep -q vcs; then fail "the agent records git state"; fi
# The same source gives the same bytes.
bash "$here/build-agent.sh" "$work/b" >/dev/null || fail "second build failed"
cmp -s "$work/a/conn3x-agent-linux-amd64.gz" "$work/b/conn3x-agent-linux-amd64.gz" || fail "builds differ"

# Over budget fails and leaves nothing behind.
out=$(CONN3X_AGENT_GZ_LIMIT=1000 bash "$here/build-agent.sh" "$work/c" 2>&1) && fail "over-budget agent accepted"
echo "$out" | grep -q "budget is 1000" || fail "no budget message: $out"
[ -z "$(ls "$work/c" 2>/dev/null)" ] || fail "over-budget agent left in $work/c"

echo "PASS: build-agent_test.sh"
