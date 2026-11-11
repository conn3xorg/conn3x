// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package modules

import (
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

// Write is what a script is going to make of the file or directory it
// writes, so that a run as the user who owns the way there can say up front
// why it can't. Path is what the script leaves behind, for the owner and group
// that only root can give it.
type Write struct {
	Owner, Group, Path string
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
// the script has that user's rights, whatever they do to the path. The one
// thing the walk can't settle is a last component that isn't there yet in a
// sticky directory, which anyone may create a moment later: a script that
// root may run there takes Settled.
//
// When Conn3x isn't root, nothing is checked: it has no rights to misuse.
func Guard(script string, routes ...Route) string {
	return guard(script, Write{}, false, routes)
}

// GuardWrite is Guard for a script that sets an owner and group, either of
// which may be empty. A script that runs as a user can't give its file a
// group that user isn't in, and lending the process the group would lend it
// to the user, who can read and steer their own process. So the script is
// told to leave owner and group alone (CONN3X_ROUTE_OWN is set), and root
// sets them afterwards on the file itself, not on its name: it opens what is
// at Path, checks through the descriptor that it is a regular file with one
// link, or a directory, and still the user's, and changes that. A path
// swapped in the meantime then only gets the user a group on a file of their
// own, and the kernel clears setuid and setgid when the owner or group of a
// file changes.
//
// An owner other than the user is refused in a directory that is theirs. It
// is set the same way where the script runs as a service account only
// because that account's group can write to a directory of root's.
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
	b.WriteString("route_as=\nroute_lent=\nif [ \"$(id -u)\" = 0 ]; then\n" + routeWalk)
	for _, r := range routes {
		b.WriteString("[ -n \"$route_as\" ] || route_walk " + r.mode + " " + ssh.Quote(r.path) + "\n")
	}
	if rootOnly {
		b.WriteString(`[ -z "$route_as" ] || route_stop "$route_dir belongs to $route_as, and this has to run as root"` + "\n")
	}
	b.WriteString("route_later=\n")
	if w.Owner != "" {
		b.WriteString("route_owner=" + ssh.Quote(w.Owner) + "\n")
		b.WriteString(`[ -z "$route_as" ] || [ "$(id -u -- "$route_owner" 2>/dev/null)" = "$route_uid" ] || { [ -n "$route_lent" ] && route_later=1; } || route_stop "$route_dir belongs to $route_as, who can change anything in it, so Conn3x works there as $route_as, not root, and $route_as can't give a file to $route_owner; use owner = \"$route_as\" or a path outside it"` + "\n")
	}
	if w.Group != "" {
		b.WriteString("route_group=" + ssh.Quote(w.Group) + "\n")
		b.WriteString(`[ -z "$route_as" ] || case " $(id -G -- "$route_as") " in *" $(getent group "$route_group" | cut -d: -f3 | grep . || echo none) "*) ;; *) route_later=1 ;; esac` + "\n")
	}
	b.WriteString("route_target=" + ssh.Quote(w.Path) + "\n")
	b.WriteString(`[ -z "$route_later" ] || [ -n "$route_target" ] || route_stop "$route_dir belongs to $route_as, and this step can't set an owner or group there"` + "\n")
	b.WriteString("fi\n")
	inner := ssh.Quote(script)
	b.WriteString(`if [ -z "$route_as" ]; then
  sh -c ` + inner + `
  exit $?
fi
cd /
CONN3X_ROUTE_USER=$route_as; export CONN3X_ROUTE_USER
[ -z "$route_later" ] || { CONN3X_ROUTE_OWN=later; export CONN3X_ROUTE_OWN; }
HOME=$(getent passwd "$route_as" | cut -d: -f6); export HOME
if command -v runuser >/dev/null 2>&1; then
  runuser -u "$route_as" -- sh -c ` + inner + `
else
  su "$route_as" -c ` + inner + `
fi
route_rc=$?
[ "$route_rc" = 0 ] || echo "Conn3x ran this as $route_as, because $route_dir belongs to $route_as" >&2
`)
	// Only a step that names an owner or group can leave one for root to set.
	if w.Owner != "" || w.Group != "" {
		b.WriteString(`if [ "$route_rc" = 0 ] && [ -n "$route_later" ]; then
  route_path=$route_target
  route_own=${route_owner:-}${route_group:+:$route_group}
  # What counts is checked on an open descriptor, not on the name. The open
  # itself mustn't follow a link the user put there since, to a device
  # whose open has an effect, or wait on a FIFO. sh can't open that way and
  # dd can: it opens the path as its input, then waits to open its output,
  # a FIFO of root's own that nobody reads, with the path still open.
  if route_hold=$(mktemp -d) && mkfifo "$route_hold/w" && dd iflag=nofollow,nonblock if=/dev/null of=/dev/null count=0 2>/dev/null; then
    dd iflag=nofollow,nonblock if="$route_target" of="$route_hold/w" count=0 </dev/null 2>/dev/null &
    route_dd=$!
    route_null=$(stat -L -c %d:%i /dev/null)
    route_n=0
    # Until dd has opened the path its input is still /dev/null. A dd that
    # couldn't open it has gone, and stat fails.
    while route_fd=$(stat -L -c '%d:%i %u %h %F' "/proc/$route_dd/fd/0" 2>/dev/null) && [ "${route_fd%% *}" = "$route_null" ] && [ "$route_n" -lt 500 ]; do
      route_n=$((route_n + 1))
      sleep 0.01
    done
    # A dd that failed is gone, and its process id may by now be someone
    # else's, with a file of theirs as its input. The answer above counts
    # only if that process is still this shell's child: then it was dd all
    # along, and with the path open it stays until it is killed below.
    route_st=$(cat "/proc/$route_dd/stat" 2>/dev/null) || route_st=
    set -- ${route_st##*) }
    [ "${2:-}" = "$$" ] || route_fd=
    set -- $route_fd
    case "${1:-$route_null} ${2:-} ${3:-} ${4:-}" in
      "$route_null "*) route_own_rc=125 ;;
      *" $route_uid 1 regular" | *" $route_uid "*" directory") chown -- "$route_own" "/proc/$route_dd/fd/0"; route_own_rc=$? ;;
      *) route_own_rc=125 ;;
    esac
    kill "$route_dd" 2>/dev/null
    wait "$route_dd" 2>/dev/null
  else
    # Without such a dd the path is looked at by name first, and the open
    # has ten seconds, in case a FIFO took its place in between.
    timeout 10 sh -c '
      { [ -f "$1" ] || [ -d "$1" ]; } && [ ! -L "$1" ] && exec 3<"$1" || exit 125
      set -- "$2" "$3" $(stat -L -c "%u %h %F" /proc/self/fd/3 2>/dev/null)
      case "${3:-} ${4:-} ${5:-}" in "$1 1 regular" | "$1 "*" directory") ;; *) exit 125 ;; esac
      chown -- "$2" /proc/self/fd/3' sh "$route_target" "$route_uid" "$route_own"
    route_own_rc=$?
  fi
  [ -z "${route_hold:-}" ] || rm -rf -- "$route_hold"
  case $route_own_rc in 0) ;; 124 | 125) route_stop "it isn't the file or directory $route_as wrote any more" ;; *) exit 1 ;; esac
fi
`)
	}
	b.WriteString(`exit "$route_rc"
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
//     run as. A system group is another matter. If nobody but root has it,
//     such as root:staff on /var/local on Debian, the directory passes. If
//     exactly one account has it, as a member or as its primary group, the
//     directory is that account's in all but name, as a package makes
//     /var/lib/bind root:bind for named: the script runs as that account.
//     /var/log passes by name. Ubuntu gives it to the syslog group, and
//     running as syslog there would fail in every log directory of root's
//     below it; what's left is that rsyslog's own account could lead root
//     astray there. An ACL is refused with the group: its mask shows as the
//     group's bits, and who it names isn't looked at.
//   - With Whole, the last component is held to the same rule, and a sticky
//     one is refused: what's in it decides what runs.
//   - Under a sticky directory, like /tmp, anyone can make what isn't there
//     yet, so a path with more to come below a missing component is refused.
const routeWalk = `route_stop() { printf 'refusing %s: %s\n' "$route_path" "$1" >&2; exit 125; }
route_user() {
  route_as=$(stat -c %U -- "$1"); route_uid=$(stat -c %u -- "$1"); route_dir=$1
  [ -n "$route_as" ] && [ -n "$route_uid" ] || route_stop "can't tell who owns $1"
  [ "$route_as" != UNKNOWN ] || route_stop "$1 belongs to uid $route_uid, which has no name"
}
route_quiet_group() {
  route_lone=
  [ "$1" -lt 1000 ] || return 1
  command -v getent >/dev/null 2>&1 || return 1
  set -- $({ getent group "$1" | cut -d: -f4 | tr , '\n'; getent passwd | awk -F: -v g="$1" '$4 == g && $3 != 0 { print $1 }'; } | grep -vx root | sort -u)
  [ $# -le 1 ] || return 1
  route_lone=${1:-}
}
# shortcut: BusyBox ls shows no ACL mark, so an ACL passes there; use getfacl if such hosts turn up with ACLs.
route_acl() { case $(ls -ld -- "$1" 2>/dev/null) in ??????????+*) return 0 ;; esac; return 1; }
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
    if [ -n "$rest" ] && [ -d "$next" ] || [ "$route_mode" = whole ]; then
      m=$((0$3))
      if [ $((m & 022)) -ne 0 ]; then
        if [ $((m & 01000)) -ne 0 ] && [ -n "$rest" ]; then sticky=1
        elif [ $((m & 02)) -ne 0 ]; then route_stop "$next can be written by anyone"
        elif route_acl "$next"; then route_stop "$next has an ACL that lets others write to it"
        elif [ "$next" = /var/log ] && [ "$2" -lt 1000 ]; then :
        elif ! route_quiet_group "$2"; then route_stop "$next can be written by its group, gid $2, which more than one account has"
        elif [ -n "$route_lone" ]; then
          route_as=$route_lone; route_dir=$next; route_lent=1
          route_uid=$(id -u -- "$route_as" 2>/dev/null) || route_stop "$next can be written by $route_as, who has no uid"
          return 0
        fi
      fi
    fi
    cur=$next
  done
}
`

// Settled is shell for a script the walk may leave to root on a path that
// wasn't there yet. In a sticky directory, like /tmp, anyone can create what
// is missing, between the walk and the script or between two lines of the
// script, and point it anywhere. Only what root or the login user owns there
// stays put, since nobody else can rename or remove it.
//
// route_settled is true when the path can be acted on by name. It is false
// when the path is missing in such a directory: the script then has to answer
// "missing" without looking again, or make it with route_mkdir. Anyone else's
// file there stops the script. Elsewhere, and for a script that isn't root,
// it is always true; route_strict=1 applies it to any user, for a script that
// runs what it finds.
//
// route_mkdir makes a directory, with its parents. In a sticky directory the
// directory is one it made, or one that was settled already.
const Settled = `route_settled() {
  [ "$(id -u)" = 0 ] || [ -n "${route_strict:-}" ] || return 0
  [ -k "$(dirname -- "$1")" ] || return 0
  route_o=$(stat -c %u -- "$1" 2>/dev/null) || return 1
  case ${SUDO_UID:-} in '' | *[!0-9]*) route_l=0 ;; *) route_l=$SUDO_UID ;; esac
  [ "$route_o" = 0 ] || [ "$route_o" = "$route_l" ] || [ "$route_o" = "$(id -u)" ] || {
    echo "refusing $1: it belongs to uid $route_o, in a directory anyone can create files in${route_hint:-}" >&2; exit 125
  }
}
route_mkdir() {
  mkdir -p -- "$(dirname -- "$1")"
  if route_settled "$1"; then mkdir -p -- "$1"
  else mkdir -- "$1" 2>/dev/null || route_settled "$1" || { echo "can't create $1" >&2; exit 1; }
  fi
}
`
