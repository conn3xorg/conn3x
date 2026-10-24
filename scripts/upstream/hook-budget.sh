#!/usr/bin/env bash
# Copyright (c) The Conn3x Authors
# SPDX-License-Identifier: MPL-2.0
#
# Keep edits to upstream-owned files few and visible.
#
#   scripts/upstream/hook-budget.sh <upstream-tag> <max-files>
#
# Every file that came from OpenTofu and now differs from <upstream-tag>
# must carry a "CONN3X:" comment explaining the change, and no more than
# <max-files> of them may differ. Conn3x's own trees don't count.
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $0 <upstream-tag> <max-files>" >&2
  exit 2
fi
tag=$1
max=$2

here=$(cd "$(dirname "$0")" && pwd)
root=$(git -C "$here" rev-parse --show-toplevel)
repo=${UPSTREAM_REPO:-https://github.com/opentofu/opentofu.git}
cache=${UPSTREAM_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/conn3x/upstream.git}

[ -d "$cache" ] || git init -q --bare "$cache"
git -C "$cache" rev-parse -q --verify "refs/tags/$tag" >/dev/null \
  || git -C "$cache" fetch -q --force "$repo" "refs/tags/$tag:refs/tags/$tag"

cd "$root"
# Upstream mode, blob id and path, minus the trees Conn3x owns, the paths
# the sync strips (Conn3x replaces those wholesale), and go.mod/go.sum,
# which change with every dependency update and can't all carry markers.
strip=$(sed -e 's#[.]#\\.#g' -e 's#^#^#' "$here/strip-paths.txt" | paste -sd'|' -)
upstream=$(git -C "$cache" ls-tree -r "$tag" \
  | awk -F'\t' '{split($1, m, " "); print m[1] "\t" m[3] "\t" $2}' \
  | grep -Ev $'\t(cmd/conn3x/|internal/conn3x/|scripts/|\\.github/|[^/]*\\.md$|NOTICE$|go\\.(mod|sum)$)' \
  | awk -F'\t' -v strip="${strip:-^$}" '$3 !~ strip' || true)

# Keep only files still present locally, then compare blob ids. Regular
# files are hashed in one batch; a symlink's blob is its target path.
regular=$(mktemp) links=$(mktemp)
trap 'rm -f "$regular" "$links"' EXIT
while IFS=$'\t' read -r mode blob path; do
  if [ "$mode" = 120000 ]; then
    [ -L "$path" ] && printf '%s\t%s\t%s\n' "$blob" "$(printf '%s' "$(readlink "$path")" | git hash-object --stdin)" "$path" >> "$links"
  elif [ -f "$path" ] && [ ! -L "$path" ]; then
    printf '%s\t%s\n' "$blob" "$path" >> "$regular"
  fi
done <<<"$upstream"
[ -s "$regular" ] || { echo "hook budget: no upstream files found" >&2; exit 1; }

changed=()
while IFS=$'\t' read -r want have path; do
  [ "$want" = "$have" ] || changed+=("$path")
done < <(paste <(cut -f1 "$regular") <(cut -f2 "$regular" | git hash-object --stdin-paths) <(cut -f2 "$regular"); cat "$links")

status=0
for path in ${changed[@]+"${changed[@]}"}; do
  if ! grep -q 'CONN3X:' "$path"; then
    echo "missing CONN3X marker: $path" >&2
    status=1
  fi
done
if [ "${#changed[@]}" -gt "$max" ]; then
  echo "hook budget exceeded: ${#changed[@]} upstream files changed, limit $max" >&2
  printf '  %s\n' ${changed[@]+"${changed[@]}"} >&2
  status=1
fi
[ "$status" -eq 0 ] && echo "hook budget: ${#changed[@]} of $max upstream files changed, all marked"
exit "$status"
