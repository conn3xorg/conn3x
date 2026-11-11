// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package fsobj

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/opentofu/opentofu/internal/conn3x/modules"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// WantMode is the mode the directory, or a path under it, should have
// given the one it has: d.Mode itself, or what a symbolic mode makes of it.
func (d Directory) WantMode(current string, dir bool) string {
	if !IsSymbolic(d.Mode) {
		return normalizeMode(d.Mode)
	}
	perm, err := strconv.ParseUint(current, 8, 32)
	if err != nil {
		return d.Mode
	}
	return fmt.Sprintf("%04o", applySymbolic(d.Mode, uint32(perm), dir))
}

// chmodMode is what chmod is given for the directory itself.
func (d Directory) chmodMode() string {
	if IsSymbolic(d.Mode) {
		return d.Mode
	}
	return normalizeMode(d.Mode)
}

// Tree is what's under a recursive directory: how many paths would change,
// and how many files with more than one link are left as they are.
type Tree struct {
	Changes, Skipped int
}

// treeRecord is one line of the listing: a count of paths alike in every
// way the step looks at.
type treeRecord struct {
	n                    int
	kind, mode, user, gr string
	links                int
}

// treeFind defines tree_find, which runs find on everything under $p but
// what's mounted there. -xdev alone isn't enough: a bind mount from the
// same filesystem has the same device, so every mount point under $p is
// pruned by name, from /proc/self/mountinfo, where the kernel lists them
// all, binds too, by their real paths.
const treeFind = `rp=$(cd -- "$p" && pwd -P)
prune=
set -f
while IFS= read -r line; do
  set -- $line
  m=$(printf '%s' "$5" | sed 's/\\\([0-7][0-7][0-7]\)/\\0\1/g')
  m=$(printf '%b' "$m")
  case $m in "$rp"/*) ;; *) continue ;; esac
  m=$p${m#"$rp"}
  m=$(printf '%s' "$m" | sed -e 's/[][*?\\]/\\&/g' -e "s/'/'\\\\''/g")
  prune="$prune -path '$m' -prune -o"
done </proc/self/mountinfo
set +f
tree_find() {
  eval "set -- $prune \"\$@\""
  find -P "$p" -xdev -mindepth 1 "$@"
}
`

// ReadTree counts the paths under d.Path whose owner, group or mode differ
// from the step's, without listing them: one find, summed with uniq. A
// mount point under the path, and everything on it, isn't counted.
func ReadTree(ctx context.Context, r modules.Runner, d Directory, owner string) (Tree, error) {
	script := "p=" + ssh.Quote(d.Path) + `
[ -d "$p" ] && [ ! -L "$p" ] || exit 0
` + treeFind + `tree_find -printf '%y %m %u %g %n\n' | LC_ALL=C sort | uniq -c`
	res, err := r.Run(ctx, modules.Guard(script, modules.Follow(d.Path)), nil)
	if err != nil {
		return Tree{}, err
	}
	if res.ExitCode != 0 {
		return Tree{}, fmt.Errorf("reading what's under %s: %s", d.Path, strings.TrimSpace(string(res.Stderr)))
	}
	var recs []treeRecord
	for _, l := range strings.Split(strings.TrimSpace(string(res.Stdout)), "\n") {
		if l == "" {
			continue
		}
		f := strings.Fields(l)
		if len(f) != 6 {
			return Tree{}, fmt.Errorf("reading what's under %s: unexpected line %q", d.Path, l)
		}
		n, err1 := strconv.Atoi(f[0])
		links, err2 := strconv.Atoi(f[5])
		if err1 != nil || err2 != nil {
			return Tree{}, fmt.Errorf("reading what's under %s: unexpected line %q", d.Path, l)
		}
		recs = append(recs, treeRecord{n: n, kind: f[1], mode: f[2], user: f[3], gr: f[4], links: links})
	}
	return d.count(owner, recs), nil
}

// count sums what would change. owner is who the tree ends up belonging
// to. A regular file with more than one link that isn't already theirs is
// skipped, since the other link may be anywhere.
func (d Directory) count(owner string, recs []treeRecord) Tree {
	var t Tree
	for _, r := range recs {
		if r.kind == "f" && r.links > 1 && r.user != owner {
			t.Skipped += r.n
			continue
		}
		change := d.Owner != "" && r.user != d.Owner || d.Group != "" && r.gr != d.Group
		if IsSymbolic(d.Mode) && r.kind != "l" && d.WantMode(r.mode, r.kind == "d") != normalizeMode(r.mode) {
			change = true
		}
		if change {
			t.Changes += r.n
		}
	}
	return t
}

func normalizeMode(m string) string {
	m = strings.TrimLeft(m, "0")
	return fmt.Sprintf("%04s", m)
}

// treeBatch is run by find -execdir in each directory, with ./name for
// each path, so no component but the last is looked up again. As root,
// chmod only runs in a directory nobody else can change, since chmod
// follows a link that might have taken a name's place since find looked.
const treeBatch = `cmd=$1 arg=$2; shift 2
if [ "$cmd" = chmod ] && [ "$(id -u)" = 0 ]; then
  # The mode bits don't show who a POSIX ACL names, which can let someone
  # else write here too; ls marks one with a + after the mode, as route_acl
  # in route.go reads it.
  case $(ls -ld . 2>/dev/null) in ??????????+*) echo "refusing to change modes in $(pwd) as root: it has an ACL, which may let someone else change what's in it" >&2; exit 1 ;; esac
  s=$(stat -c '%u %a' .)
  m=$((0${s#* }))
  [ "${s%% *}" = 0 ] && [ $((m & 022)) -eq 0 ] || { echo "refusing to change modes in $(pwd) as root: someone else can change what's in it" >&2; exit 1; }
fi
exec $cmd -- "$arg" "$@"`

// absolutePath drops relative and empty entries from PATH. find refuses
// -execdir with them, since the command would then be looked up in each
// directory of the tree. Conn3x doesn't set PATH, the login and sudo do,
// so it's made safe here, and runuser passes it on.
const absolutePath = `tree_path=
tree_ifs=$IFS; IFS=:; set -f
for tree_d in $PATH; do case $tree_d in /*) tree_path=${tree_path:+$tree_path:}$tree_d ;; esac; done
IFS=$tree_ifs; set +f
PATH=$tree_path; export PATH
`

// treeErr is the exit code for a host without fs.protected_hardlinks.
const treeErr = 4

// treeWalk is a tree_find that runs cmd with arg on each path that passes
// test, leaving out a file with another link that isn't the owner's.
func treeWalk(cmd, arg, test string) string {
	return fmt.Sprintf(`tree_find %s ! \( -type f -links +1 ! -user "$final" \) -execdir sh -c "$batch" sh %s %s {} +`, test, cmd, arg) + "\n"
}

// ApplyTree sets owner, group and mode on everything under d.Path. Root
// changes owner and group, with -h, never through a link; chmod runs as
// the owner the tree then has, so the kernel stops it at anything that
// isn't theirs. Root only does what it must: with no owner to set, and a
// group the owner is in, the whole walk runs as the owner.
func ApplyTree(ctx context.Context, r modules.Runner, d Directory) error {
	mode := ""
	if IsSymbolic(d.Mode) {
		mode = d.Mode
	}
	chown := treeWalk(`"chown -h"`, `"$own"`, `! -user "$own"`)
	chgrp := treeWalk(`"chgrp -h"`, `"$grp"`, `! -group "$grp"`)
	chmod := treeWalk("chmod", `"$mode"`, "! -type l")
	// What runs as the owner: the group too, unless root has done it.
	asOwner := "set -e\n" + treeFind + `[ -n "$root" ] || [ -z "$grp" ] || ` + chgrp + `[ -z "$mode" ] || ` + chmod
	script := "set -e\n" + absolutePath + "p=" + ssh.Quote(d.Path) + " own=" + ssh.Quote(d.Owner) + " grp=" + ssh.Quote(d.Group) +
		" mode=" + ssh.Quote(mode) + " batch=" + ssh.Quote(treeBatch) + " as_owner=" + ssh.Quote(asOwner) + `
[ -d "$p" ] && [ ! -L "$p" ] || exit 0
final=${own:-$(stat -c %U -- "$p")}
root=
if [ "$(id -u)" = 0 ]; then
  if [ -n "$own" ]; then root=1
  elif [ -n "$grp" ]; then
    case " $(id -Gn -- "$final") " in *" $grp "*) ;; *) root=1 ;; esac
  fi
  [ -z "$root" ] && [ "$final" != root ] || [ "$(cat /proc/sys/fs/protected_hardlinks 2>/dev/null)" = 1 ] || {
    echo "fs.protected_hardlinks is off, so a user could link a file of root's into $p and have it handed to them; set it to 1 (sysctl fs.protected_hardlinks=1)" >&2
    exit ` + strconv.Itoa(treeErr) + `
  }
fi
export p own grp mode batch final root
if [ -n "$root" ]; then
` + treeFind + `[ -z "$own" ] || ` + chown + `[ -z "$grp" ] || ` + chgrp + `fi
if [ "$(id -u)" != 0 ] || [ "$final" = root ]; then sh -c "$as_owner"
elif command -v runuser >/dev/null 2>&1; then cd / && runuser -u "$final" -- sh -c "$as_owner"
else cd / && su "$final" -c "$as_owner"; fi`
	res, err := r.Run(ctx, modules.Guard(script, modules.Follow(d.Path)), nil)
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("setting owner, group and mode under %s: %s", d.Path, strings.TrimSpace(string(res.Stderr)))
	}
	return nil
}
