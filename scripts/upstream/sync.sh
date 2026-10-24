#!/usr/bin/env bash
# Copyright (c) The Conn3x Authors
# SPDX-License-Identifier: MPL-2.0
#
# Apply upstream OpenTofu changes between two release tags to this tree.
#
#   scripts/upstream/sync.sh <from-tag> <to-tag>
#
# Paths listed in strip-paths.txt are never brought in. The result is
# staged; conflicts leave markers in place and exit non-zero.
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $0 <from-tag> <to-tag>" >&2
  exit 2
fi
from=$1
to=$2

here=$(cd "$(dirname "$0")" && pwd)
root=$(git -C "$here" rev-parse --show-toplevel)
repo=${UPSTREAM_REPO:-https://github.com/opentofu/opentofu.git}
cache=${UPSTREAM_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/conn3x/upstream.git}

[ -d "$cache" ] || git init -q --bare "$cache"
git -C "$cache" fetch -q --force "$repo" \
  "refs/tags/$from:refs/tags/$from" "refs/tags/$to:refs/tags/$to"

excludes=()
while IFS= read -r path; do
  [ -n "$path" ] && excludes+=(":(top,exclude)$path")
done < "$here/strip-paths.txt"

patch=$(mktemp)
trap 'rm -f "$patch"' EXIT
git -C "$cache" diff --binary "$from" "$to" -- ':(top)' "${excludes[@]}" > "$patch"
# cmd/conn3x is a copy of cmd/tofu; carry the same upstream changes into it.
git -C "$cache" diff --binary "$from" "$to" -- ':(top)cmd/tofu' \
  | sed -E 's#^(diff --git a/|--- a/|\+\+\+ b/)cmd/tofu/#\1cmd/conn3x/#; s#^(diff --git a/cmd/conn3x/[^ ]* b/)cmd/tofu/#\1cmd/conn3x/#; s#^(rename|copy) (from|to) cmd/tofu/#\1 \2 cmd/conn3x/#' \
  >> "$patch"

cd "$root"
if ! git diff --quiet HEAD --; then
  echo "sync: working tree not clean; commit or stash local changes first" >&2
  exit 1
fi
if [ -s "$patch" ]; then
  # The cache holds the preimage blobs that a three-way merge needs.
  if ! GIT_ALTERNATE_OBJECT_DIRECTORIES="$cache/objects" git apply --3way --index "$patch"; then
    echo "CONFLICT: upstream sync $from..$to needs manual resolution" >&2
    exit 1
  fi
fi

echo "$to" > internal/conn3x/version/UPSTREAM
git add internal/conn3x/version/UPSTREAM
echo "synced upstream $from..$to"
