// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package mount keeps a file system in /etc/fstab and mounted.
package mount

import (
	"context"
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/opentofu/opentofu/internal/conn3x/modules"
	"github.com/opentofu/opentofu/internal/conn3x/modules/edit"
	"github.com/opentofu/opentofu/internal/conn3x/modules/file"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

const fstab = "/etc/fstab"

var fstabWord = regexp.MustCompile(`^[^\s#]+$`)

// Mount is one file system: its fstab entry and the live mount.
type Mount struct {
	Path, Src, FSType string
	Opts              string // defaults to "defaults"
}

// Validate checks a Mount before anything reaches the host.
func (m Mount) Validate() error {
	if !path.IsAbs(m.Path) || path.Clean(m.Path) == "/" || !fstabWord.MatchString(m.Path) {
		return fmt.Errorf("path %q must be an absolute path other than /, without spaces", m.Path)
	}
	for label, v := range map[string]string{"src": m.Src, "fstype": m.FSType, "opts": m.opts()} {
		if !fstabWord.MatchString(v) {
			return fmt.Errorf("%s %q must be one word without spaces", label, v)
		}
	}
	return nil
}

func (m Mount) opts() string {
	if m.Opts == "" {
		return "defaults"
	}
	return m.Opts
}

// Line is the entry Conn3x writes to /etc/fstab.
func (m Mount) Line() string {
	return fmt.Sprintf("%s %s %s %s 0 0", m.Src, m.Path, m.FSType, m.opts())
}

// fstabLine returns the entry for mountpoint, with its fields single-spaced.
func fstabLine(content, mountpoint string) string {
	for _, line := range strings.Split(content, "\n") {
		if f := strings.Fields(line); len(f) >= 2 && !strings.HasPrefix(f[0], "#") && f[1] == mountpoint {
			return strings.Join(f, " ")
		}
	}
	return ""
}

// Actual is what the host has for a mount point.
type Actual struct {
	Entry              string // the fstab entry, or ""
	Mounted            bool
	Source, LiveFSType string
}

// Read returns the fstab entry and the live mount at m.Path.
func Read(ctx context.Context, r modules.Runner, m Mount) (Actual, error) {
	f, err := file.Read(ctx, r, fstab)
	if err != nil {
		return Actual{}, err
	}
	a := Actual{Entry: fstabLine(f.Content, m.Path)}
	res, err := r.Run(ctx, "findmnt -n -M "+ssh.Quote(m.Path)+" -o SOURCE,FSTYPE", nil)
	if err != nil {
		return a, err
	}
	if fields := strings.Fields(string(res.Stdout)); res.ExitCode == 0 && len(fields) == 2 {
		a.Mounted, a.Source, a.LiveFSType = true, fields[0], fields[1]
	}
	return a, nil
}

// InSync reports whether the entry is as wanted and the right file system is
// mounted. A UUID= or LABEL= source shows as its device once mounted, so
// only a plain source is compared.
func (m Mount) InSync(a Actual) bool {
	return a.Entry == m.Line() && a.Mounted && a.LiveFSType == m.FSType && (strings.Contains(m.Src, "=") || a.Source == m.Src)
}

func (m Mount) entryRegexp() string { return `^\s*\S+\s+` + regexp.QuoteMeta(m.Path) + `\s` }

func writeFstab(ctx context.Context, r modules.Runner, l edit.Line) error {
	f, err := file.Read(ctx, r, fstab)
	if err != nil {
		return err
	}
	content, err := edit.ApplyLine(f.Content, l)
	if err != nil || content == f.Content {
		return err
	}
	if err := file.Apply(ctx, r, file.Desired{Path: fstab, Content: content, Mode: "0644", Owner: "root", Group: "root"}); err != nil {
		return err
	}
	// systemd generates mount units from fstab and warns until reloaded.
	_, err = r.Run(ctx, "if command -v systemctl >/dev/null 2>&1; then systemctl daemon-reload; fi", nil)
	return err
}

// Apply writes the fstab entry and mounts it: a remount for new options, or
// an unmount and mount when a different file system is mounted there.
func Apply(ctx context.Context, r modules.Runner, m Mount) error {
	if err := m.Validate(); err != nil {
		return err
	}
	if err := writeFstab(ctx, r, edit.Line{Line: m.Line(), Regexp: m.entryRegexp()}); err != nil {
		return err
	}
	a, err := Read(ctx, r, m)
	if err != nil {
		return err
	}
	p := ssh.Quote(m.Path)
	script := "mkdir -p -- " + p + " && mount " + p
	switch {
	case a.Mounted && a.LiveFSType == m.FSType && (strings.Contains(m.Src, "=") || a.Source == m.Src):
		script = "mount -o remount " + p
	case a.Mounted:
		script = "umount " + p + " && mount " + p
	}
	return check(r.Run(ctx, script, nil))
}

// Delete unmounts the file system and removes its fstab entry.
func Delete(ctx context.Context, r modules.Runner, m Mount) error {
	p := ssh.Quote(m.Path)
	if err := check(r.Run(ctx, "if findmnt -M "+p+" >/dev/null 2>&1; then umount "+p+"; fi", nil)); err != nil {
		return err
	}
	return writeFstab(ctx, r, edit.Line{Regexp: m.entryRegexp(), State: edit.Absent})
}

func check(res ssh.Result, err error) error {
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return errors.New(strings.TrimSpace(string(res.Stderr) + string(res.Stdout)))
	}
	return nil
}
