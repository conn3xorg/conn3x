#!/usr/bin/env bash
# Copyright (c) The Conn3x Authors
# SPDX-License-Identifier: MPL-2.0
#
# Print the nightly agent benchmark from the last N scheduled runs of
# droplets.yml on main, and check the gate for defaultAgent = true: the
# last 7 runs clean, each with refresh_plan at least 2x faster with the
# agent on. Needs gh and jq.
#
#   scripts/agent-bench-results.sh [N]    (default 7)
set -euo pipefail

n=${1:-7}
repo=${REPO:-conn3xorg/conn3x}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

printf '%-12s %-10s %-9s %-14s %-14s %-14s\n' run date job cold_apply refresh_plan second_plan
pass=0
total=0
for id in $(gh run list -R "$repo" -w droplets.yml -b main -e schedule -L "$n" --json databaseId -q '.[].databaseId'); do
  total=$((total + 1))
  date=$(gh run view "$id" -R "$repo" --json createdAt -q '.createdAt[:10]')
  job=$(gh run view "$id" -R "$repo" --json jobs -q '.jobs[] | select(.name == "agent-bench") | .conclusion')
  cols=(- - -)
  if gh run download "$id" -R "$repo" -n agent-bench -D "$work/$id" >/dev/null 2>&1; then
    # off/on seconds and the speedup, per phase.
    cols=()
    while IFS= read -r col; do cols+=("$col"); done < <(jq -rs '
      def s(m; p): (map(select(.mode == m and .phase == p)) | .[0].seconds);
      ["cold_apply", "refresh_plan", "second_plan"][] as $p
      | if s("off"; $p) and s("on"; $p)
        then "\(s("off"; $p) | floor)/\(s("on"; $p) | floor)s \(s("off"; $p) / s("on"; $p) * 100 | round / 100)x"
        else "-" end' "$work/$id/agent-bench.jsonl")
  fi
  printf '%-12s %-10s %-9s %-14s %-14s %-14s\n' "$id" "$date" "${job:-none}" "${cols[0]}" "${cols[1]}" "${cols[2]}"
  speedup=${cols[1]##* }
  if [[ $job == success && $speedup != - ]] && awk -v x="${speedup%x}" 'BEGIN { exit !(x >= 2) }'; then
    pass=$((pass + 1))
  fi
done

echo
echo "$pass of $total runs clean with refresh_plan at least 2x (columns are off/on seconds)."
if ((total >= 7 && pass == total)); then
  echo "Gate met: defaultAgent can be flipped."
else
  echo "Gate not met: defaultAgent stays false."
fi
