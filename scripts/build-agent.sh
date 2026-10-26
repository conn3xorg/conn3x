#!/usr/bin/env bash
# Copyright (c) The Conn3x Authors
# SPDX-License-Identifier: MPL-2.0
#
# Build the host agent for linux/amd64 and linux/arm64, gzipped, for conn3x
# to embed.
#
#   scripts/build-agent.sh [output-dir]
#
# The output dir defaults to internal/conn3x/agent/payload. The bytes depend
# only on the source, not on the commit, so an unchanged agent keeps its
# checksum. Each agent must stay within 2,000,000 bytes gzipped, or the
# build fails.
#
# GOFLAGS, GOAMD64, GOARM64 and GOEXPERIMENT from the environment are
# ignored: the agent must run on any amd64 or arm64 host and build the same
# everywhere.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
out=${1:-"$root/internal/conn3x/agent/payload"}
limit=${CONN3X_AGENT_GZ_LIMIT:-2000000}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

cd "$root"
for arch in amd64 arm64; do
  name=conn3x-agent-linux-$arch
  env -u GOFLAGS -u GOAMD64 -u GOARM64 -u GOEXPERIMENT GOOS=linux GOARCH=$arch CGO_ENABLED=0 \
    go build -trimpath -buildvcs=false -ldflags='-s -w -buildid=' -o "$work/$name" ./cmd/conn3x-agent
  gzip -9n "$work/$name"
  size=$(wc -c <"$work/$name.gz" | tr -d ' ')
  if [ "$size" -gt "$limit" ]; then
    echo "linux/$arch agent is $size bytes gzipped; the budget is $limit" >&2
    exit 1
  fi
  echo "linux/$arch agent: $size bytes gzipped"
done
mkdir -p "$out"
mv -f "$work"/*.gz "$out/"
