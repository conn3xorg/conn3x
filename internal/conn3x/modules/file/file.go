// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package file manages the content, mode and ownership of a regular file.
package file

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/opentofu/opentofu/internal/conn3x/modules"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// Desired is the file as it should be. An empty Owner or Group leaves it as is.
type Desired struct {
	Path    string
	Content string
	Mode    string // octal, like "0644"
	Owner   string
	Group   string
}

// Actual is the file as it is.
type Actual struct {
	Exists  bool
	Content string
	Mode    string // four-digit octal
	Owner   string
	Group   string
}

var modePattern = regexp.MustCompile(`^[0-7]{4}$`)

// Validate checks a Desired before anything runs on a host.
func (d Desired) Validate() error {
	if d.Path == "" || !path.IsAbs(d.Path) {
		return fmt.Errorf("path %q must be absolute", d.Path)
	}
	if !modePattern.MatchString(d.Mode) {
		return fmt.Errorf("mode %q must be four octal digits, like \"0644\"", d.Mode)
	}
	return nil
}

// NormalizeMode returns mode as four octal digits.
func NormalizeMode(mode string) string {
	m := strings.TrimLeft(mode, "0")
	return fmt.Sprintf("%04s", m)
}

const notRegular = 3

// Read reports the file's current state. A missing file is not an error.
func Read(ctx context.Context, r modules.Runner, p string) (Actual, error) {
	q := ssh.Quote(p)
	script := fmt.Sprintf(`p=%s
[ -e "$p" ] || [ -L "$p" ] || { echo missing; exit 0; }
[ -f "$p" ] || exit %d
echo present
stat -c '%%a %%U %%G' -- "$p" 2>/dev/null || stat -f '%%Lp %%Su %%Sg' "$p"
base64 < "$p" | tr -d '\n'`, q, notRegular)
	res, err := run(ctx, r, script, nil)
	if err != nil {
		if res.ExitCode == notRegular {
			return Actual{}, fmt.Errorf("%s exists but is not a regular file", p)
		}
		return Actual{}, err
	}
	lines := strings.SplitN(string(res.Stdout), "\n", 3)
	if lines[0] == "missing" {
		return Actual{}, nil
	}
	if len(lines) < 2 {
		return Actual{}, fmt.Errorf("reading %s: unexpected output %q", p, res.Stdout)
	}
	meta := strings.Fields(lines[1])
	if len(meta) != 3 {
		return Actual{}, fmt.Errorf("reading %s: unexpected stat output %q", p, lines[1])
	}
	var encoded string
	if len(lines) == 3 {
		encoded = lines[2]
	}
	content, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return Actual{}, fmt.Errorf("reading %s: %w", p, err)
	}
	return Actual{
		Exists:  true,
		Content: string(content),
		Mode:    NormalizeMode(meta[0]),
		Owner:   meta[1],
		Group:   meta[2],
	}, nil
}

// NeedsChange reports whether Apply would change anything.
func NeedsChange(d Desired, a Actual) bool {
	return !a.Exists ||
		a.Content != d.Content ||
		NormalizeMode(d.Mode) != a.Mode ||
		(d.Owner != "" && d.Owner != a.Owner) ||
		(d.Group != "" && d.Group != a.Group)
}

// Apply writes the file atomically: a temporary file in the same directory
// gets the content, mode and ownership, then replaces the target in one
// rename. On SELinux hosts the result is relabelled for its final path.
func Apply(ctx context.Context, r modules.Runner, d Desired) error {
	if err := d.Validate(); err != nil {
		return err
	}
	var owner strings.Builder
	if d.Owner != "" {
		fmt.Fprintf(&owner, "chown -- %s \"$tmp\"\n", ssh.Quote(d.Owner))
	}
	if d.Group != "" {
		fmt.Fprintf(&owner, "chgrp -- %s \"$tmp\"\n", ssh.Quote(d.Group))
	}
	script := fmt.Sprintf(`set -e
p=%s
tmp=$(mktemp "$(dirname -- "$p")/.conn3x.XXXXXX")
trap 'rm -f -- "$tmp"' EXIT
cat > "$tmp"
chmod %s "$tmp"
%smv -f -- "$tmp" "$p"
trap - EXIT
if command -v restorecon >/dev/null 2>&1; then restorecon -- "$p" 2>/dev/null || true; fi`,
		ssh.Quote(d.Path), NormalizeMode(d.Mode), owner.String())
	_, err := run(ctx, r, script, []byte(d.Content))
	return err
}

// Delete removes the file. Deleting a missing file succeeds.
func Delete(ctx context.Context, r modules.Runner, p string) error {
	_, err := run(ctx, r, "rm -f -- "+ssh.Quote(p), nil)
	return err
}

func run(ctx context.Context, r modules.Runner, script string, stdin []byte) (ssh.Result, error) {
	res, err := r.Run(ctx, script, stdin)
	if err != nil {
		return res, err
	}
	if res.ExitCode != 0 {
		msg := strings.TrimSpace(string(res.Stderr))
		if msg == "" {
			msg = fmt.Sprintf("exit status %d", res.ExitCode)
		}
		return res, errors.New(msg)
	}
	return res, nil
}
