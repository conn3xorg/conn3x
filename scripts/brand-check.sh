#!/usr/bin/env bash
# Copyright (c) The Conn3x Authors
# SPDX-License-Identifier: MPL-2.0
#
# Fail if a conn3x binary still names OpenTofu while it runs.
#
#   scripts/brand-check.sh <path-to-conn3x>
set -euo pipefail

bin=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"
printf 'resource "terraform_data" "x" {\n  input = "hi"\n}\n' > main.tf

out=$( { "$bin" -help; "$bin" version; "$bin" init -no-color; "$bin" plan -no-color; "$bin" nope || true; } 2>&1 )
leaks=$(grep -n 'OpenTofu' <<<"$out" | grep -v 'built on OpenTofu' || true)
if [ -n "$leaks" ]; then
  echo "conn3x output still names OpenTofu:" >&2
  echo "$leaks" >&2
  exit 1
fi
grep -q 'Conn3x will perform the following actions' <<<"$out" || { echo "plan output is not branded" >&2; exit 1; }
echo "brand check passed"
