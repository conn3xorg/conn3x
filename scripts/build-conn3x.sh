#!/usr/bin/env bash
# Copyright (c) The Conn3x Authors
# SPDX-License-Identifier: MPL-2.0
#
# Build the conn3x binary with its user-facing text branded as Conn3x.
#
#   scripts/build-conn3x.sh [output-path] [extra go build flags...]
#
# The upstream sources are never edited: their string literals are rewritten
# into a temporary directory and swapped in with go build -overlay.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
out=${1:-"$root/conn3x"}
shift || true

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

cd "$root"
# brandgen runs here, so it is built for this machine even when GOOS or
# GOARCH asks for another target.
overlay=$(env -u GOOS -u GOARCH go run ./internal/conn3x/brand/brandgen -root "$root" -out "$work")
go build -overlay "$overlay" -trimpath "$@" -o "$out" ./cmd/conn3x
