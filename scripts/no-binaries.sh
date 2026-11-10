#!/usr/bin/env bash
# Copyright (c) The Conn3x Authors
# SPDX-License-Identifier: MPL-2.0
#
# Fail when <base>..<head> adds a compiled executable or a file over 1 MiB.
# Nobody can review either, and every clone carries them for good.
#
#   scripts/no-binaries.sh <base> <head>
#
# A file that has to be an exception goes in scripts/no-binaries-allow.txt,
# one path per line, in the same pull request, where a reviewer sees it.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
limit=1048576
bad=0
while IFS= read -r -d '' path; do
  grep -Fxq -- "$path" "$here/no-binaries-allow.txt" && continue
  size=$(git cat-file -s "$2:$path")
  # ELF, Mach-O (thin, either byte order, and universal) and PE.
  # head closes the pipe early on a large file; that isn't a failure.
  magic=$(git cat-file blob "$2:$path" | head -c 4 | od -An -tx1 | tr -d ' \n') || true
  case "$magic" in
    7f454c46|feedface|feedfacf|cefaedfe|cffaedfe|cafebabe|4d5a*)
      echo "compiled executable: $path"
      bad=1
      ;;
  esac
  if [ "$size" -gt "$limit" ]; then
    echo "over 1 MiB ($size bytes): $path"
    bad=1
  fi
done < <(git diff -z --name-only --diff-filter=A "$1" "$2")

if [ "$bad" -ne 0 ]; then
  echo
  echo "Remove the file, or list it in scripts/no-binaries-allow.txt with the reason in the pull request."
  exit 1
fi
echo "No executables or oversized files added."
