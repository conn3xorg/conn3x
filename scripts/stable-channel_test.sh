#!/usr/bin/env bash
# Copyright (c) The Conn3x Authors
# SPDX-License-Identifier: MPL-2.0
#
# Tests for stable-channel.sh, as dry runs against a gh that answers from
# files.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

# Three releases: 30 days, 10 days and 1 day old.
jq -n '[["v1.0.0", 30], ["v1.1.0", 10], ["v1.2.0", 1]]
  | map({tag_name: .[0], draft: false, prerelease: false, published_at: (now - .[1] * 86400 | todate)})' >"$work/releases"
jq -n '[{sha: "c2", commit: {message: "Brew cask update for conn3x version v1.2.0"}},
        {sha: "c1", commit: {message: "Brew cask update for conn3x version v1.1.0"}}]' >"$work/commits"
for v in 1.1.0 1.2.0; do
  printf '# header\ncask "conn3x" do\n  version "%s"\n\n  binary "conn3x"\nend\n' "$v" | base64 | tr -d '\n' |
    jq -Rn '{content: input}' >"$work/cask-$v"
done
advisory() { jq -n --arg v "$1" '[{vulnerabilities: [{patched_versions: $v}]}]' >"$work/advisories"; }

mkdir "$work/bin"
cat >"$work/bin/gh" <<EOF
#!/usr/bin/env bash
# gh api [--paginate] <path> --jq <filter>
for a in "\$@"; do
  case \$a in
    *security-advisories*) f=advisories ;;
    */releases) f=releases ;;
    *commits\?*) f=commits ;;
    *ref=c1) f=cask-1.1.0 ;;
    *ref=c2) f=cask-1.2.0 ;;
  esac
done
exec jq -r "\${!#}" "$work/\$f"
EOF
chmod +x "$work/bin/gh"
run() { PATH="$work/bin:$PATH" DRY_RUN=1 bash "$here/stable-channel.sh" "$@"; }

# The newest release a week old wins over a newer one that is a day old.
advisory 1.1.0
out=$(run) || fail "the automatic pick failed: $out"
echo "$out" | grep -qx "stable: v1.1.0" || fail "expected v1.1.0: $out"
echo "$out" | grep -qx 'cask "conn3x@stable" do' || fail "the cask kept its name: $out"
echo "$out" | grep -qx '  conflicts_with cask: "conn3x"' || fail "the cask doesn't conflict with conn3x: $out"

# A fix that is a day old leaves nothing to pick: older releases lack it.
advisory 1.2.0
out=$(run) || fail "nothing to pick should not be an error"
echo "$out" | grep -q "Stable stays where it is" || fail "expected no pick: $out"

# By hand, the day-old fix can be promoted, and a release without it can't.
out=$(run v1.2.0) || fail "the fix release was refused: $out"
echo "$out" | grep -qx "stable: v1.2.0" || fail "expected v1.2.0: $out"
if out=$(run 1.1.0 2>&1); then fail "a release older than the fix was accepted"; fi
echo "$out" | grep -q "older than v1.2.0" || fail "no reason given: $out"
if run 3.0.0 >/dev/null 2>&1; then fail "a version that was never released was accepted"; fi

# A fix written as "v1.1.0" or ">= 1.1.0" is read as 1.1.0.
for v in v1.1.0 ">= 1.1.0"; do
  advisory "$v"
  out=$(run) || fail "patched version '$v' failed: $out"
  echo "$out" | grep -qx "stable: v1.1.0" || fail "patched version '$v': expected v1.1.0: $out"
done

# A range can't be read as one version: say so, don't quietly stop moving.
advisory ">= 1.1.0, < 1.2.0"
if out=$(run 2>&1); then fail "a range as the patched version was accepted: $out"; fi
echo "$out" | grep -q "isn't a plain version: <1.2.0" || fail "no reason given: $out"

# An advisory with no fix yet doesn't hold stable back.
jq -n '[{vulnerabilities: [{patched_versions: null}]}]' >"$work/advisories"
out=$(run) || fail "an unfixed advisory failed the run: $out"
echo "$out" | grep -qx "stable: v1.1.0" || fail "an unfixed advisory: expected v1.1.0: $out"

echo "PASS: stable-channel_test.sh"
