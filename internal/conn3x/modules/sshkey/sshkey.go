// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package sshkey manages one public key in a user's authorized_keys, and one
// host's keys in a known_hosts file.
package sshkey

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
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

// Keys reads the keys an exclusive step lists, one per line; blank lines
// are skipped. It returns each key's line, as written, and its identity.
func Keys(key string) (lines, ids []string, err error) {
	for i, l := range strings.Split(key, "\n") {
		if l = strings.TrimSpace(l); l == "" {
			continue
		}
		id, err := parse(l)
		if err != nil {
			return nil, nil, fmt.Errorf("line %d: %w", i+1, err)
		}
		lines, ids = append(lines, l), append(ids, id)
	}
	if len(lines) == 0 {
		return nil, nil, fmt.Errorf("key lists no keys")
	}
	return lines, ids, nil
}

// Unlisted is a key in authorized_keys that an exclusive step doesn't list.
type Unlisted struct {
	Type, Fingerprint string // such as ssh-ed25519 and SHA256:...
	Comment           string // what follows the key, often an address: never kept in state
}

// String is the type and fingerprint, what state keeps of the key.
func (u Unlisted) String() string { return u.Type + " " + u.Fingerprint }

// EditExclusive returns authorized_keys content holding exactly the keys an
// exclusive step lists: listed keys already there stay as written, with
// their options and comments, missing ones are added, and every other key is
// taken out and returned. Blank and comment lines stay. A line that isn't a
// key Conn3x can read goes too, since sshd might still take it.
func EditExclusive(content, key string) (string, []Unlisted, error) {
	lines, ids, err := Keys(key)
	if err != nil {
		return "", nil, err
	}
	want := map[string]bool{}
	for _, id := range ids {
		want[id] = true
	}
	var kept []string
	var gone []Unlisted
	have := map[string]bool{}
	if content != "" {
		for _, l := range strings.Split(strings.TrimSuffix(content, "\n"), "\n") {
			if t := strings.TrimSpace(l); t == "" || strings.HasPrefix(t, "#") {
				kept = append(kept, l)
				continue
			}
			pub, comment, _, _, err := gossh.ParseAuthorizedKey([]byte(l))
			if err != nil {
				sum := sha256.Sum256([]byte(l))
				gone = append(gone, Unlisted{Type: "unreadable", Fingerprint: "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])})
				continue
			}
			id := string(gossh.MarshalAuthorizedKey(pub))
			if !want[id] || have[id] {
				if !want[id] {
					gone = append(gone, Unlisted{Type: pub.Type(), Fingerprint: gossh.FingerprintSHA256(pub), Comment: comment})
				}
				continue
			}
			have[id] = true
			kept = append(kept, l)
		}
	}
	for i, id := range ids {
		if !have[id] {
			have[id] = true
			kept = append(kept, lines[i])
		}
	}
	return strings.Join(kept, "\n") + "\n", gone, nil
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

// MaxRead is the largest authorized_keys or known_hosts file Read returns.
// The user owns the file, and one that's huge or sparse would otherwise
// fill the controller's memory.
var MaxRead = 1 << 20

// Read returns the current authorized_keys content, read as the user so a
// symlink in their ~/.ssh can't make a privileged read return a file they
// couldn't read themselves. A missing file reads as empty; a file that
// can't be read is an error, so an unexpected link is refused, not treated
// as absent.
func Read(ctx context.Context, r modules.Runner, loc Location) (string, error) {
	script := fmt.Sprintf(`f=%s
[ -e "$f" ] || exit 0
head -c %d < "$f"`, ssh.Quote(loc.File), MaxRead+1)
	res, err := r.Run(ctx, modules.AsUser(loc.Owner, script), nil)
	if err != nil {
		return "", err
	}
	if res.ExitCode != 0 {
		return "", fmt.Errorf("reading %s as %s: %s", loc.File, loc.Owner, strings.TrimSpace(string(res.Stderr)))
	}
	if len(res.Stdout) > MaxRead {
		return "", fmt.Errorf("%s is over %d MiB, the most Conn3x reads of it", loc.File, MaxRead>>20)
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
	return Write(ctx, r, loc, edited)
}

// Write replaces authorized_keys with content, creating ~/.ssh (0700) and
// the file (0600) as Apply does, as the user.
func Write(ctx context.Context, r modules.Runner, loc Location, content string) error {
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
	res, err := r.Run(ctx, modules.AsUser(loc.Owner, script), []byte(content))
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("writing %s as %s: %s", loc.File, loc.Owner, strings.TrimSpace(string(res.Stderr)))
	}
	return nil
}
