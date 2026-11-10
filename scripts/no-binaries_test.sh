#!/usr/bin/env bash
# Copyright (c) The Conn3x Authors
# SPDX-License-Identifier: MPL-2.0
#
# Tests for no-binaries.sh.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
g() { git -C "$work" -c user.name=Dev -c user.email=dev@example.com -c commit.gpgsign=false -c core.hooksPath=/dev/null "$@"; }
check() { bash "$work/scripts/no-binaries.sh" "$base" HEAD; }

g init -q
mkdir "$work/scripts"
cp "$here/no-binaries.sh" "$work/scripts/"
: > "$work/scripts/no-binaries-allow.txt"
# An executable that is already in the tree is not this change's business.
printf '\177ELF old' > "$work/old"
g add -A && g commit -q -m base
base=$(g rev-parse HEAD)

echo 'package main' > "$work/main.go"
echo 'more' >> "$work/old"
g add -A && g commit -q -m "source and an edit"
(cd "$work" && check >/dev/null) || fail "source file rejected"

printf '\317\372\355\376\014\000\000\001' > "$work/provider"
g add -A && g commit -q -m "mach-o"
out=$(cd "$work" && check) && fail "Mach-O executable accepted"
echo "$out" | grep -q "compiled executable: provider" || fail "Mach-O not named: $out"

printf '%s\n' provider > "$work/scripts/no-binaries-allow.txt"
(cd "$work" && check >/dev/null) || fail "allow-listed file rejected"

printf 'MZ\220\000' > "$work/tool.exe"
printf '\177ELF\002' > "$work/tool"
head -c 1048577 /dev/zero > "$work/big.json"
g add -A && g commit -q -m "more"
out=$(cd "$work" && check) && fail "PE, ELF and oversized files accepted"
for want in "compiled executable: tool.exe" "compiled executable: tool" "over 1 MiB (1048577 bytes): big.json"; do
  echo "$out" | grep -Fq "$want" || fail "missing '$want': $out"
done

echo "PASS: no-binaries_test.sh"
