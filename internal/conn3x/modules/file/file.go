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

// unreadable is the exit code for a file the login user can't read. Without
// it, base64's failure is lost in the pipe and the file reads as empty.
const unreadable = 4

// Read reports the file's current state. A missing file is not an error.
// A runner that is a modules.FileReader answers natively when it can.
func Read(ctx context.Context, r modules.Runner, p string) (Actual, error) {
	if fr, ok := r.(modules.FileReader); ok {
		st, err := fr.ReadFile(ctx, p)
		switch {
		case err == nil && !st.Exists:
			return Actual{}, nil
		case err == nil && !st.Regular:
			return Actual{}, notRegularError(p)
		case err == nil:
			return Actual{Exists: true, Content: string(st.Content), Mode: fmt.Sprintf("%04o", st.Mode), Owner: st.Owner, Group: st.Group}, nil
		case !errors.Is(err, errors.ErrUnsupported):
			return Actual{}, err
		}
	}
	q := ssh.Quote(p)
	script := fmt.Sprintf(`p=%s
[ -e "$p" ] || [ -L "$p" ] || { echo missing; exit 0; }
[ -f "$p" ] || exit %d
[ -r "$p" ] || { id -un; exit %d; }
echo present
stat -c '%%a %%U %%G' -- "$p" 2>/dev/null || stat -f '%%Lp %%Su %%Sg' "$p"
base64 < "$p" | tr -d '\n'`, q, notRegular, unreadable)
	res, err := run(ctx, r, script, nil)
	if err != nil {
		if res.ExitCode == notRegular {
			return Actual{}, notRegularError(p)
		}
		if res.ExitCode == unreadable {
			return Actual{}, fmt.Errorf("%s exists but can't be read by %s", p, strings.TrimSpace(string(res.Stdout)))
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

// Exists reports whether a regular file is at p, without reading it, so a
// file the login user can't read still counts. Something else at the path
// is an error, as it is for Read.
func Exists(ctx context.Context, r modules.Runner, p string) (bool, error) {
	res, err := run(ctx, r, fmt.Sprintf(`p=%s
[ -e "$p" ] || [ -L "$p" ] || { echo missing; exit 0; }
[ -f "$p" ] || exit %d
echo present`, ssh.Quote(p), notRegular), nil)
	if err != nil {
		if res.ExitCode == notRegular {
			return false, notRegularError(p)
		}
		return false, err
	}
	return strings.TrimSpace(string(res.Stdout)) == "present", nil
}

func notRegularError(p string) error {
	return fmt.Errorf("%s exists but is not a regular file", p)
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
// rename. The content is flushed to disk before the rename and the directory
// after it, so a power cut leaves the old file or the new one, never an
// empty one. On SELinux hosts the result is relabelled for its final path.
func Apply(ctx context.Context, r modules.Runner, d Desired) error {
	if err := d.Validate(); err != nil {
		return err
	}
	script := fmt.Sprintf(`set -e
p=%s
mkdir -p -- "$(dirname -- "$p")"
tmp=$(mktemp "$(dirname -- "$p")/.conn3x.XXXXXX")
trap 'rm -f -- "$tmp"' EXIT
cat > "$tmp"
chmod %s "$tmp"
%s`+SyncFile+`
mv -f -- "$tmp" "$p"
trap - EXIT
`+SyncDir+`
if command -v restorecon >/dev/null 2>&1; then restorecon -- "$p" 2>/dev/null || true; fi`,
		ssh.Quote(d.Path), NormalizeMode(d.Mode), Ownership(d.Owner, d.Group))
	_, err := run(ctx, r, script, []byte(d.Content))
	return err
}

// Ownership is the script that gives "$tmp" its owner and group before it
// replaces "$p". An empty owner or group keeps the one "$p" has now, since
// "$tmp" belongs to whoever ran mktemp, often root through become. Keeping
// it is best effort: a login user can't give a file to someone else.
func Ownership(owner, group string) string {
	var b strings.Builder
	if owner == "" || group == "" {
		b.WriteString(`if [ -e "$p" ]; then
  ids=$(stat -c '%u %g' -- "$p" 2>/dev/null || stat -f '%u %g' "$p")
`)
		if owner == "" {
			b.WriteString("  chown -- \"${ids% *}\" \"$tmp\" 2>/dev/null || true\n")
		}
		if group == "" {
			b.WriteString("  chgrp -- \"${ids#* }\" \"$tmp\" 2>/dev/null || true\n")
		}
		b.WriteString("fi\n")
	}
	if owner != "" {
		fmt.Fprintf(&b, "chown -- %s \"$tmp\"\n", ssh.Quote(owner))
	}
	if group != "" {
		fmt.Fprintf(&b, "chgrp -- %s \"$tmp\"\n", ssh.Quote(group))
	}
	return b.String()
}

// SyncFile and SyncDir flush "$tmp" and the directory holding "$p" to disk.
// GNU sync takes paths; where sync doesn't, everything is flushed instead.
const (
	SyncFile = `sync -- "$tmp" 2>/dev/null || sync`
	SyncDir  = `sync -- "$(dirname -- "$p")" 2>/dev/null || sync`
)

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
