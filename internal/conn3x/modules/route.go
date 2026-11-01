// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package modules

import (
	"path"
	"strings"

	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// A Route is a path a script is about to act on, and how much of it counts.
type Route struct {
	path, mode string
}

// Parent is for a script that replaces or removes the last component and never
// follows it: everything up to it has to be safe.
func Parent(p string) Route { return Route{p, "parent"} }

// Follow is for a script that goes through the last component too, as a read
// does. A link there is checked and followed, but a real file or directory
// with another owner is fine where nobody but root can swap it.
func Follow(p string) Route { return Route{p, "follow"} }

// Whole is Follow where the content of the path decides what runs, so its last
// component has to be safe too.
func Whole(p string) Route { return Route{p, "whole"} }

// Write is what a script is going to make of the file it writes, so that a
// run as the user who owns the way there can say up front why it can't.
type Write struct {
	Owner, Group string
}

// Guard wraps a script so that, as root, it can't be led somewhere else by a
// path someone else can change. See routeWalk for what it checks. The result
// is one of three: the script runs as root, because no user but root can
// change anything on the way; or it runs as the user who owns the way there,
// so the kernel checks their permissions on every step; or it doesn't run.
//
// None of the three leaves a window between the check and the act. The walk
// only ever trusts what nobody else can change, so what it found stays true,
// and it stops at the first thing someone else could change. From there on
// the script has that user's rights, whatever they do to the path.
//
// When Conn3x isn't root, nothing is checked: it has no rights to misuse.
func Guard(script string, routes ...Route) string {
	return guard(script, Write{}, false, routes)
}

// GuardWrite is Guard for a script that sets an owner and group, either of
// which may be empty. Group becomes the script's primary group when it runs
// as a user, so it can give a file a group that user isn't in, as a package
// does with a service's directory and a root group.
func GuardWrite(script string, w Write, routes ...Route) string {
	return guard(script, w, false, routes)
}

// GuardRoot is Guard for a script only root can run, such as a mount: it
// refuses rather than running as the user.
func GuardRoot(script string, routes ...Route) string {
	return guard(script, Write{}, true, routes)
}

func guard(script string, w Write, rootOnly bool, routes []Route) string {
	var b strings.Builder
	b.WriteString("route_as=\nif [ \"$(id -u)\" = 0 ]; then\n" + routeWalk)
	for _, r := range routes {
		b.WriteString("[ -n \"$route_as\" ] || route_walk " + r.mode + " " + ssh.Quote(path.Clean(r.path)) + "\n")
	}
	if rootOnly {
		b.WriteString(`[ -z "$route_as" ] || route_stop "$route_dir belongs to $route_as, and this has to run as root"` + "\n")
	}
	if w.Owner != "" {
		b.WriteString("route_owner=" + ssh.Quote(w.Owner) + "\n")
		b.WriteString(`[ -z "$route_as" ] || [ "$(id -u -- "$route_owner" 2>/dev/null)" = "$route_uid" ] || route_stop "$route_dir belongs to $route_as, who can change anything in it, so Conn3x works there as $route_as, not root, and $route_as can't give a file to $route_owner; use owner = \"$route_as\" or a path outside it"` + "\n")
	}
	b.WriteString("fi\n")
	inner := ssh.Quote(script)
	asGroup := ""
	if w.Group != "" {
		asGroup = " -g " + ssh.Quote(w.Group)
	}
	b.WriteString(`if [ -z "$route_as" ]; then
  sh -c ` + inner + `
  exit $?
fi
cd /
CONN3X_ROUTE_USER=$route_as; export CONN3X_ROUTE_USER
HOME=$(getent passwd "$route_as" | cut -d: -f6); export HOME
if command -v runuser >/dev/null 2>&1; then
  runuser -u "$route_as"` + asGroup + ` -- sh -c ` + inner + `
else
  su "$route_as" -c ` + inner + `
fi
route_rc=$?
[ "$route_rc" = 0 ] || echo "Conn3x ran this as $route_as, because $route_dir belongs to $route_as" >&2
exit "$route_rc"
`)
	return b.String()
}

// routeWalk defines the walk down a path. Every component it looks at sits in
// a directory it has already found nobody else can change, so what it reads
// about that component can't change under it either.
//
//   - A symlink is followed only if root or the user Conn3x logged in as owns
//     it. Those are the two who can already do anything here.
//   - A directory on the way owned by anyone else ends the walk: the script
//     runs as them.
//   - A directory on the way that others can write to, without the sticky bit
//     to stop them swapping what's in it, is refused: there's no one user to
//     run as. A distro's own service groups are let through, such as
//     root:syslog on /var/log on Ubuntu, if no person's account is in the
//     group.
//   - Under a sticky directory, like /tmp, anyone can make what isn't there
//     yet, so a path with more to come below a missing component is refused.
const routeWalk = `route_stop() { printf 'refusing %s: %s\n' "$route_path" "$1" >&2; exit 125; }
route_user() {
  route_as=$(stat -c %U -- "$1"); route_uid=$(stat -c %u -- "$1"); route_dir=$1
  [ -n "$route_as" ] && [ -n "$route_uid" ] || route_stop "can't tell who owns $1"
  [ "$route_as" != UNKNOWN ] || route_stop "$1 belongs to uid $route_uid, which has no name"
}
route_quiet_group() {
  [ "$1" -lt 1000 ] || return 1
  command -v getent >/dev/null 2>&1 || return 1
  getent passwd | awk -F: -v g="$1" -v m=",$(getent group "$1" | cut -d: -f4)," '($4 == g || index(m, "," $1 ",")) && $3 >= 1000 && $3 != 65534 { f = 1 } END { exit f }'
}
route_walk() {
  route_path=$2
  route_mode=$1; rest=${2#/}; cur=/; sticky=; hops=0
  case ${SUDO_UID:-} in '' | *[!0-9]*) route_login=0 ;; *) route_login=$SUDO_UID ;; esac
  while [ -n "$rest" ]; do
    c=${rest%%/*}
    case $rest in */*) rest=${rest#*/} ;; *) rest= ;; esac
    case $c in
    '' | .) continue ;;
    ..) cur=$(dirname -- "$cur"); sticky=; [ ! -k "$cur" ] || sticky=1; continue ;;
    esac
    [ "$route_mode" != parent ] || [ -n "$rest" ] || return 0
    next=${cur%/}/$c
    info=$(stat -c '%u %g %a' -- "$next" 2>/dev/null) || {
      [ -z "$sticky" ] || [ -z "$rest" ] || route_stop "anyone can create $next, in $cur"
      return 0
    }
    set -- $info
    if [ "$1" = 0 ] || [ "$1" = "$route_login" ]; then ours=1; else ours=; fi
    if [ -L "$next" ]; then
      [ -n "$ours" ] || { route_user "$next"; return 0; }
      hops=$((hops + 1))
      [ "$hops" -le 40 ] || route_stop "too many symlinks"
      t=$(readlink -- "$next")
      case $t in /*) cur=/; sticky= ;; esac
      rest=${t#/}${rest:+/$rest}
      continue
    fi
    if [ -z "$ours" ]; then
      if [ -n "$rest" ] || [ -n "$sticky" ] || [ "$route_mode" = whole ]; then route_user "$next"; fi
      return 0
    fi
    sticky=
    if [ -n "$rest" ] && [ -d "$next" ]; then
      m=$((0$3))
      if [ $((m & 022)) -ne 0 ]; then
        if [ $((m & 01000)) -ne 0 ]; then sticky=1
        elif [ $((m & 02)) -ne 0 ]; then route_stop "$next can be written by anyone"
        elif ! route_quiet_group "$2"; then route_stop "$next can be written by its group, gid $2"
        fi
      fi
    fi
    cur=$next
  done
}
`
