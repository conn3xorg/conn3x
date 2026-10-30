// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package sshkey manages one public key in a user's authorized_keys.
package sshkey

import (
	"context"
	"fmt"
	"strings"

	gossh "golang.org/x/crypto/ssh"

	"github.com/opentofu/opentofu/internal/conn3x/modules"
	"github.com/opentofu/opentofu/internal/conn3x/modules/account"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// parse returns a key's identity: its type and key data, without comment
// or options.
func parse(line string) (string, error) {
	if strings.ContainsAny(line, "\r\n") {
		return "", fmt.Errorf("key must be a single line")
	}
	pub, _, _, _, err := gossh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return "", fmt.Errorf("not a valid public key: %w", err)
	}
	return string(gossh.MarshalAuthorizedKey(pub)), nil
}

// Edit returns authorized_keys content with key present or absent. Keys are
// compared by type and data, so comments and options don't matter.
func Edit(content, key string, present bool) (string, error) {
	want, err := parse(strings.TrimSpace(key))
	if err != nil {
		return "", err
	}
	lines := strings.Split(strings.TrimSuffix(content, "\n"), "\n")
	if content == "" {
		lines = nil
	}
	var kept []string
	found := false
	for _, l := range lines {
		if id, err := parse(l); err == nil && id == want {
			found = true
			if !present {
				continue
			}
		}
		kept = append(kept, l)
	}
	if present && !found {
		kept = append(kept, strings.TrimSpace(key))
	}
	if len(kept) == 0 {
		return "", nil
	}
	return strings.Join(kept, "\n") + "\n", nil
}

// Location is where a user's authorized_keys lives and who owns it.
type Location struct {
	Dir, File, Owner, Group string
}

// Locate finds a user's ~/.ssh from the user database.
func Locate(ctx context.Context, r modules.Runner, user string) (Location, error) {
	u, err := account.ReadUser(ctx, r, user)
	if err != nil {
		return Location{}, err
	}
	if !u.Exists {
		return Location{}, fmt.Errorf("user %s does not exist", user)
	}
	dir := strings.TrimSuffix(u.Home, "/") + "/.ssh"
	return Location{Dir: dir, File: dir + "/authorized_keys", Owner: user, Group: u.Group}, nil
}

// asUser wraps a shell script so it runs as user rather than as whoever is
// connected. The path work below is under the user's own home, which the
// user controls, so doing it as root would let the user redirect it with a
// symlink and have root read or take ownership of a file elsewhere. Running
// as the user instead means the kernel checks the user's own permissions on
// every path, so following a link the user planted grants nothing they
// couldn't already reach, and no root-owned path is ever touched. The whole
// script runs in one drop, so there is no root-then-user window to race.
//
// runuser is in util-linux on every supported distro and runs the command
// directly, so it works even for an account whose shell is nologin; su,
// which goes through the login shell, is only a fallback. When Conn3x is
// already connected as the user, neither is needed or available without
// root, so the script runs as is.
func asUser(user, script string) string {
	q := ssh.Quote(user)
	inner := ssh.Quote(script)
	return fmt.Sprintf(`if [ "$(id -u)" = "$(id -u -- %[1]s 2>/dev/null)" ]; then
  sh -c %[2]s
elif command -v runuser >/dev/null 2>&1; then
  runuser -u %[1]s -- sh -c %[2]s
else
  su %[1]s -c %[2]s
fi`, q, inner)
}

// Read returns the current authorized_keys content, read as the user so a
// symlink in their ~/.ssh can't make a privileged read return a file they
// couldn't read themselves. A missing file reads as empty; a file that
// can't be read is an error, so an unexpected link is refused, not treated
// as absent.
func Read(ctx context.Context, r modules.Runner, loc Location) (string, error) {
	script := fmt.Sprintf(`f=%s
[ -e "$f" ] || exit 0
cat -- "$f"`, ssh.Quote(loc.File))
	res, err := r.Run(ctx, asUser(loc.Owner, script), nil)
	if err != nil {
		return "", err
	}
	if res.ExitCode != 0 {
		return "", fmt.Errorf("reading %s as %s: %s", loc.File, loc.Owner, strings.TrimSpace(string(res.Stderr)))
	}
	return string(res.Stdout), nil
}

// Apply makes the key present or absent, creating ~/.ssh (0700) and
// authorized_keys (0600), the modes sshd insists on. Everything runs as the
// user, so the files it creates are owned by the user without a chown, and a
// symlink pointing out of what the user owns makes mkdir or chmod fail
// rather than letting root act on another path.
func Apply(ctx context.Context, r modules.Runner, loc Location, key string, present bool) error {
	current, err := Read(ctx, r, loc)
	if err != nil {
		return err
	}
	edited, err := Edit(current, key, present)
	if err != nil {
		return err
	}
	script := fmt.Sprintf(`set -e
d=%[1]s
f=%[2]s
mkdir -p -- "$d"
chmod 0700 "$d"
tmp=$(mktemp "$d/.conn3x.XXXXXX")
trap 'rm -f -- "$tmp"' EXIT
cat > "$tmp"
chmod 0600 "$tmp"
mv -f -- "$tmp" "$f"
trap - EXIT
if command -v restorecon >/dev/null 2>&1; then restorecon -- "$d" "$f" 2>/dev/null || true; fi`,
		ssh.Quote(loc.Dir), ssh.Quote(loc.File))
	res, err := r.Run(ctx, asUser(loc.Owner, script), []byte(edited))
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("writing %s as %s: %s", loc.File, loc.Owner, strings.TrimSpace(string(res.Stderr)))
	}
	return nil
}
