#!/usr/bin/env bash
# Deletes test resource groups a failed run left behind. A group goes only if
# all of this holds: its name starts with the prefix, it carries the tag
# conn3x-ci=true, its created_at tag parses and is older than the limit, and it
# isn't Azure's own NetworkWatcherRG. Anything else is never touched.
#
#   sweep.sh [-n] [max age in hours, default 4]
#
# -n only prints. SWEEP_PREFIX narrows the prefix; it can't widen it.
set -u
dry=
if [ "${1:-}" = -n ]; then dry=1; shift; fi
hours=${1:-4}
case "$hours" in ''|*[!0-9]*) echo "max age must be a number of hours" >&2; exit 2 ;; esac
prefix=${SWEEP_PREFIX:-conn3x-ci-}
case "$prefix" in conn3x-ci-*) ;; *) echo "SWEEP_PREFIX must start with conn3x-ci-" >&2; exit 2 ;; esac
now=$(date -u +%s)

# Format and parse without GNU or BSD date differences.
epoch() { python3 -c 'import sys,datetime as d
try: print(int(d.datetime.strptime(sys.argv[1],"%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=d.timezone.utc).timestamp()))
except ValueError: sys.exit(1)' "$1"; }

groups=$(az group list --query '[].[name, tags."conn3x-ci", tags.created_at]' -o tsv) || { echo "listing groups failed" >&2; exit 1; }
status=0
while IFS=$'\t' read -r name tag created; do
  [ -n "$name" ] || continue
  [ "$name" != NetworkWatcherRG ] || continue
  case "$name" in "$prefix"*) ;; *) continue ;; esac
  [ "$tag" = true ] || { echo "skip $name: no conn3x-ci tag"; continue; }
  born=$(epoch "$created") || { echo "skip $name: created_at is not a time"; continue; }
  age=$((now - born))
  [ "$age" -ge $((hours * 3600)) ] || { echo "keep $name: $((age / 60)) minutes old"; continue; }
  if [ -n "$dry" ]; then echo "would delete $name"; continue; fi
  echo "deleting $name"
  az group delete -n "$name" -y --no-wait || status=1
done <<<"$groups"
exit $status
