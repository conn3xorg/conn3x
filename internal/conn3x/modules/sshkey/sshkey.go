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
	"github.com/opentofu/opentofu/internal/conn3x/modules/file"
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

// Read returns the current authorized_keys content.
func Read(ctx context.Context, r modules.Runner, loc Location) (string, error) {
	a, err := file.Read(ctx, r, loc.File)
	return a.Content, err
}

// Apply makes the key present or absent, creating ~/.ssh (0700) and
// authorized_keys (0600) owned by the user, the modes sshd insists on.
func Apply(ctx context.Context, r modules.Runner, loc Location, key string, present bool) error {
	current, err := Read(ctx, r, loc)
	if err != nil {
		return err
	}
	edited, err := Edit(current, key, present)
	if err != nil {
		return err
	}
	q := ssh.Quote(loc.Dir)
	res, err := r.Run(ctx, fmt.Sprintf(`set -e
mkdir -p -- %[1]s
chmod 0700 %[1]s
chown -- %[2]s %[1]s
if command -v restorecon >/dev/null 2>&1; then restorecon -- %[1]s 2>/dev/null || true; fi`, q, ssh.Quote(loc.Owner+":"+loc.Group)), nil)
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("preparing %s: %s", loc.Dir, strings.TrimSpace(string(res.Stderr)))
	}
	return file.Apply(ctx, r, file.Desired{Path: loc.File, Content: edited, Mode: "0600", Owner: loc.Owner, Group: loc.Group})
}
