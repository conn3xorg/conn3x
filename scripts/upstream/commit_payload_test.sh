#!/usr/bin/env bash
# Copyright (c) The Conn3x Authors
# SPDX-License-Identifier: MPL-2.0
#
# Tests for commit_payload.py: staged changes become GraphQL fileChanges.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
g() { git -C "$work" -c user.name=t -c user.email=t@example.com -c commit.gpgsign=false -c core.hooksPath=/dev/null "$@"; }

g init -q
mkdir -p "$work/dir"
printf 'keep\n' > "$work/keep.txt"
printf 'old\n' > "$work/change.txt"
printf 'gone\n' > "$work/dir/remove me.txt"
g add -A && g commit -qm base

printf 'new\n' > "$work/change.txt"
printf 'added' > "$work/dir/new file.txt"
printf '\x00\x01\xff' > "$work/bin.dat"
g rm -q "dir/remove me.txt"
g add -A

out=$(cd "$work" && python3 "$here/commit_payload.py")
echo "$out" | python3 -c '
import base64, json, sys
d = json.load(sys.stdin)
adds = {a["path"]: base64.b64decode(a["contents"]) for a in d["additions"]}
dels = [x["path"] for x in d["deletions"]]
assert adds == {"change.txt": b"new\n", "dir/new file.txt": b"added", "bin.dat": b"\x00\x01\xff"}, adds
assert dels == ["dir/remove me.txt"], dels
' || fail "unexpected payload: $out"

# Nothing staged is an error, not an empty commit.
g commit -qm staged
if (cd "$work" && python3 "$here/commit_payload.py" >/dev/null 2>&1); then fail "empty change accepted"; fi

echo "PASS: commit_payload_test.sh"
