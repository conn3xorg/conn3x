#!/usr/bin/env bash
# Copyright (c) The Conn3x Authors
# SPDX-License-Identifier: MPL-2.0
#
# Point the stable channel at a release: the image tag "stable" and the
# Homebrew cask conn3x@stable. Nothing is built. The image is the release's
# own, by digest, so its signature still verifies, and the cask is the one
# the release published, under another name.
#
#   scripts/stable-channel.sh            the newest release that qualifies
#   scripts/stable-channel.sh 0.12.0     that release, for a fix that can't wait
#   DRY_RUN=1 scripts/stable-channel.sh  say what would happen and change nothing
#
# A release qualifies when it has been out for seven days and no published
# advisory for this repository was patched in a later one. A version named
# by hand skips the seven days, never the advisories.
#
# Needs gh, jq and docker buildx, GH_TOKEN to read this repository, and
# TAP_TOKEN to write the tap.
set -euo pipefail

repo=${REPO:-conn3xorg/conn3x}
tap=${TAP:-conn3xorg/homebrew-tap}
image=${IMAGE:-ghcr.io/conn3xorg/conn3x}
min_age=$((7 * 24 * 3600))

# at_least A B: is version A the same as B or newer?
at_least() { [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -1)" = "$2" ]; }

releases=$(gh api --paginate "repos/$repo/releases" \
  --jq '.[] | select(.draft or .prerelease | not) | [.tag_name[1:], .published_at] | @tsv')

# The newest version any published advisory names as its fix. Releases are
# one line, so everything from there on has every fix. An advisory with no
# fix yet names no release to wait for, and doesn't hold stable back.
fixes=$(gh api --paginate "repos/$repo/security-advisories?state=published" \
  --jq '.[].vulnerabilities[].patched_versions // empty' | tr -d ' ' | tr ',' '\n' | sed -E 's/^(>=)?v?//')
# Anything but a plain version would sort above every release and stop
# stable for good, without a word.
if bad=$(printf '%s\n' "$fixes" | grep -Evx '([0-9]+(\.[0-9]+)*)?'); then
  echo "an advisory's patched version isn't a plain version: $bad" >&2
  exit 1
fi
floor=$(printf '%s\n' "$fixes" | sort -V | tail -1)
floor=${floor:-0}

if [ $# -gt 0 ]; then
  version=${1#v}
  printf '%s\n' "$releases" | cut -f1 | grep -qxF "$version" \
    || { echo "v$version is not a published release" >&2; exit 1; }
  at_least "$version" "$floor" \
    || { echo "v$version is older than v$floor, which fixes a published advisory" >&2; exit 1; }
else
  cutoff=$(($(date +%s) - min_age))
  version=$(printf '%s\n' "$releases" | while IFS=$'\t' read -r v published; do
    [ "$(jq -n --arg t "$published" '$t | fromdateiso8601')" -le "$cutoff" ] || continue
    if at_least "$v" "$floor"; then echo "$v"; fi
  done | sort -V | tail -1)
  if [ -z "$version" ]; then
    echo "No release has been out for seven days with every published fix in it. Stable stays where it is."
    exit 0
  fi
fi
echo "stable: v$version"

# The cask as the release published it: the tap commit GoReleaser made.
sha=$(gh api "repos/$tap/commits?path=Casks/conn3x.rb&per_page=100" \
  --jq "[.[] | select(.commit.message | endswith(\"version v$version\"))][0].sha // empty")
[ -n "$sha" ] || { echo "the tap has no cask commit for v$version" >&2; exit 1; }
cask=$(gh api "repos/$tap/contents/Casks/conn3x.rb?ref=$sha" --jq .content | base64 -d |
  awk 'NR == 1 { print "# Made by scripts/stable-channel.sh in conn3xorg/conn3x from the cask of this release. DO NOT EDIT."; next }
       $0 == "cask \"conn3x\" do" { print "cask \"conn3x@stable\" do"; next }
       $0 == "  binary \"conn3x\"" { print "  conflicts_with cask: \"conn3x\"\n" }
       { print }')
if ! printf '%s\n' "$cask" | grep -q '^cask "conn3x@stable" do$' ||
   ! printf '%s\n' "$cask" | grep -q "^  version \"$version\"$"; then
  echo "the cask for v$version doesn't look the way this script expects" >&2
  exit 1
fi

if [ -n "${DRY_RUN:-}" ]; then
  echo "would tag $image:v$version as $image:stable and write Casks/conn3x@stable.rb:"
  printf '%s\n' "$cask"
  exit 0
fi

docker buildx imagetools create -t "$image:stable" "$image:v$version"

path="repos/$tap/contents/Casks/conn3x%40stable.rb"
old=$(GH_TOKEN=$TAP_TOKEN gh api "$path" 2>/dev/null || true)
if [ "$(printf '%s' "$old" | jq -r '.content // empty' | base64 -d 2>/dev/null)" = "$cask" ]; then
  echo "the cask is already v$version"
  exit 0
fi
args=(-f "message=Stable cask update for conn3x version v$version" -f "content=$(printf '%s\n' "$cask" | base64 | tr -d '\n')")
old_sha=$(printf '%s' "$old" | jq -r '.sha // empty' 2>/dev/null || true)
[ -z "$old_sha" ] || args+=(-f "sha=$old_sha")
GH_TOKEN=$TAP_TOKEN gh api -X PUT "$path" "${args[@]}" --jq .commit.sha
