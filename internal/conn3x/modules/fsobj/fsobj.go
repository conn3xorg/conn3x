// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package fsobj manages directories and symbolic links.
package fsobj

import (
	"context"
	"errors"
	"fmt"
	"path"
	"strings"

	"github.com/opentofu/opentofu/internal/conn3x/modules"
	"github.com/opentofu/opentofu/internal/conn3x/modules/file"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// Directory is a directory as it should be. Empty Owner and Group leave them.
type Directory struct {
	Path, Mode, Owner, Group string
}

// DirectoryState is a directory as it is.
type DirectoryState struct {
	Exists             bool
	Mode, Owner, Group string
}

// Validate checks a Directory before anything runs on a host.
func (d Directory) Validate() error {
	return (file.Desired{Path: d.Path, Mode: d.Mode}).Validate()
}

const notDirectory = 3

// ReadDirectory reports the directory's state. Something else at the path
// is an error, never silently replaced.
func ReadDirectory(ctx context.Context, r modules.Runner, p string) (DirectoryState, error) {
	script := fmt.Sprintf(`p=%s
[ -e "$p" ] || [ -L "$p" ] || { echo missing; exit 0; }
[ -d "$p" ] && [ ! -L "$p" ] || exit %d
stat -c '%%a %%U %%G' -- "$p" 2>/dev/null || stat -f '%%Lp %%Su %%Sg' "$p"`, ssh.Quote(p), notDirectory)
	res, err := r.Run(ctx, script, nil)
	if err != nil {
		return DirectoryState{}, err
	}
	switch res.ExitCode {
	case 0:
	case notDirectory:
		return DirectoryState{}, fmt.Errorf("%s exists but is not a directory", p)
	default:
		return DirectoryState{}, fmt.Errorf("reading %s: %s", p, strings.TrimSpace(string(res.Stderr)))
	}
	out := strings.TrimSpace(string(res.Stdout))
	if out == "missing" {
		return DirectoryState{}, nil
	}
	f := strings.Fields(out)
	if len(f) != 3 {
		return DirectoryState{}, fmt.Errorf("reading %s: unexpected output %q", p, out)
	}
	return DirectoryState{Exists: true, Mode: file.NormalizeMode(f[0]), Owner: f[1], Group: f[2]}, nil
}

// DirectoryNeedsChange reports whether ApplyDirectory would change anything.
func DirectoryNeedsChange(d Directory, s DirectoryState) bool {
	return !s.Exists || file.NormalizeMode(d.Mode) != s.Mode ||
		d.Owner != "" && d.Owner != s.Owner || d.Group != "" && d.Group != s.Group
}

// ApplyDirectory creates the directory, with its parents, and sets its
// mode and ownership.
func ApplyDirectory(ctx context.Context, r modules.Runner, d Directory) error {
	if err := d.Validate(); err != nil {
		return err
	}
	q := ssh.Quote(d.Path)
	cmds := []string{"mkdir -p -- " + q, "chmod -- " + file.NormalizeMode(d.Mode) + " " + q}
	if d.Owner != "" {
		cmds = append(cmds, "chown -- "+ssh.Quote(d.Owner)+" "+q)
	}
	if d.Group != "" {
		cmds = append(cmds, "chgrp -- "+ssh.Quote(d.Group)+" "+q)
	}
	cmds = append(cmds, "if command -v restorecon >/dev/null 2>&1; then restorecon -- "+q+" 2>/dev/null || true; fi")
	return run(ctx, r, "set -e\n"+strings.Join(cmds, "\n"))
}

// DeleteDirectory removes the directory only when it is empty, so removing
// a resource never deletes content.
func DeleteDirectory(ctx context.Context, r modules.Runner, p string) error {
	q := ssh.Quote(p)
	res, err := r.Run(ctx, fmt.Sprintf(`[ -d %[1]s ] || exit 0
[ -z "$(ls -A -- %[1]s)" ] || { echo "not empty" >&2; exit 3; }
rmdir -- %[1]s`, q), nil)
	if err != nil {
		return err
	}
	if res.ExitCode == 3 {
		return fmt.Errorf("%s is not empty, so it was left in place", p)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("removing %s: %s", p, strings.TrimSpace(string(res.Stderr)))
	}
	return nil
}

// Link is a symbolic link as it should be.
type Link struct {
	Path, Target string
}

// LinkState is a symbolic link as it is.
type LinkState struct {
	Exists bool
	Target string
}

// Validate checks a Link before anything runs on a host.
func (l Link) Validate() error {
	if !path.IsAbs(l.Path) {
		return fmt.Errorf("path %q must be absolute", l.Path)
	}
	if l.Target == "" {
		return errors.New("target must not be empty")
	}
	return nil
}

const notLink = 3

// ReadLink reports where the link points. A real file at the path is an error.
func ReadLink(ctx context.Context, r modules.Runner, p string) (LinkState, error) {
	res, err := r.Run(ctx, fmt.Sprintf(`p=%s
if [ -L "$p" ]; then printf 'link\n'; readlink -- "$p"; exit 0; fi
[ -e "$p" ] && exit %d
echo missing`, ssh.Quote(p), notLink), nil)
	if err != nil {
		return LinkState{}, err
	}
	if res.ExitCode == notLink {
		return LinkState{}, fmt.Errorf("%s exists but is not a symlink", p)
	}
	lines := strings.SplitN(string(res.Stdout), "\n", 2)
	if lines[0] != "link" || len(lines) < 2 {
		return LinkState{}, nil
	}
	return LinkState{Exists: true, Target: strings.TrimSuffix(lines[1], "\n")}, nil
}

// LinkNeedsChange reports whether ApplyLink would change anything.
func LinkNeedsChange(l Link, s LinkState) bool { return !s.Exists || s.Target != l.Target }

// ApplyLink points the link at its target, replacing an existing link in
// one rename so it is never missing in between.
func ApplyLink(ctx context.Context, r modules.Runner, l Link) error {
	if err := l.Validate(); err != nil {
		return err
	}
	if _, err := ReadLink(ctx, r, l.Path); err != nil {
		return err
	}
	q := ssh.Quote(l.Path)
	return run(ctx, r, fmt.Sprintf(`set -e
tmp=$(dirname -- %[1]s)/.conn3x-link.$$
ln -s -- %[2]s "$tmp"
# -T replaces the old link itself instead of following it into a directory.
if ! mv -fT -- "$tmp" %[1]s 2>/dev/null; then
  rm -f -- "$tmp"
  ln -sfn -- %[2]s %[1]s
fi`, q, ssh.Quote(l.Target)))
}

// DeleteLink removes the link, and refuses to remove anything that isn't one.
func DeleteLink(ctx context.Context, r modules.Runner, p string) error {
	s, err := ReadLink(ctx, r, p)
	if err != nil || !s.Exists {
		return err
	}
	return run(ctx, r, "rm -f -- "+ssh.Quote(p))
}

func run(ctx context.Context, r modules.Runner, script string) error {
	res, err := r.Run(ctx, script, nil)
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("%s", strings.TrimSpace(string(res.Stderr)))
	}
	return nil
}
