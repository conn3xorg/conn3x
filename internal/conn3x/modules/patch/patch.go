// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package patch applies a unified diff on a host with GNU patch, or takes
// it out again, and tells which of the two the host has.
package patch

import (
	"context"
	"errors"
	"fmt"
	"path"
	"strconv"
	"strings"

	"github.com/opentofu/opentofu/internal/conn3x/modules"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// State is whether a Patch should be in.
type State string

const (
	Present State = "present"
	Absent  State = "absent"
)

// Status is what a dry run found on the host.
type Status string

const (
	Applied    Status = "applied"     // the patch reverses cleanly, so it's in
	NotApplied Status = "not_applied" // the patch applies cleanly
	Conflict   Status = "conflict"    // neither: the file has moved on
)

// Patch is a patch and where it goes. The patch itself is Content, sent on
// stdin, or Src, a file on the host. Dest names one file; Basedir is the
// directory the patch's own file names are taken from, after Strip.
type Patch struct {
	Content, Src, Dest, Basedir string
	Strip                       int
	IgnoreWhitespace, Binary    bool
	State                       State
}

// Validate checks a Patch before anything reaches the host.
func (p Patch) Validate() error {
	if (p.Content == "") == (p.Src == "") {
		return errors.New("set one of content (the patch itself) or src (a patch file on the host)")
	}
	if (p.Dest == "") == (p.Basedir == "") {
		return errors.New("set one of dest (the file to patch) or basedir (the directory the patch's file names start from)")
	}
	for what, v := range map[string]string{"src": p.Src, "dest": p.Dest, "basedir": p.Basedir} {
		if v != "" && (!path.IsAbs(v) || strings.ContainsAny(v, "\r\n\x00")) {
			return fmt.Errorf("%s %q must be an absolute path", what, v)
		}
	}
	if p.Strip < 0 {
		return fmt.Errorf("strip must be 0 or more, not %d", p.Strip)
	}
	if p.State != Present && p.State != Absent {
		return fmt.Errorf(`state must be "present" or "absent", not %q`, p.State)
	}
	return nil
}

// command is patch with p's options, then extra, every value quoted.
// --batch and --forward keep it from asking anything or guessing that a
// patch is reversed; rejects and backups are thrown away, so a failed
// apply leaves no .rej or .orig beside the file.
func (p Patch) command(extra ...string) string {
	parts := []string{"patch", "--batch", "--forward", "--reject-file=-", "--no-backup-if-mismatch", "-p" + strconv.Itoa(p.Strip)}
	if p.IgnoreWhitespace {
		parts = append(parts, "--ignore-whitespace")
	}
	if p.Binary {
		parts = append(parts, "--binary")
	}
	if p.Basedir != "" {
		parts = append(parts, "-d", ssh.Quote(p.Basedir))
	}
	if p.Src != "" {
		parts = append(parts, "-i", ssh.Quote(p.Src))
	}
	parts = append(parts, extra...)
	if p.Dest != "" {
		parts = append(parts, ssh.Quote(p.Dest))
	}
	return strings.Join(parts, " ")
}

const missingHint = "patch isn't on this host: install the patch package, for example with a package step before this one"

// run runs patch with extra, the patch on stdin when it's Content.
func (p Patch) run(ctx context.Context, r modules.Runner, extra ...string) (int, string, error) {
	var stdin []byte
	if p.Content != "" {
		stdin = []byte(p.Content)
	}
	res, err := r.Run(ctx, p.command(extra...), stdin)
	if err != nil {
		return 0, "", err
	}
	if res.ExitCode == 127 {
		return 0, "", errors.New(missingHint)
	}
	return res.ExitCode, strings.TrimSpace(string(res.Stdout) + string(res.Stderr)), nil
}

// classify reads the exit statuses of a reverse and a forward dry run.
// Reverse first: an applied patch reverses cleanly.
func classify(reverse, forward int) Status {
	switch {
	case reverse == 0:
		return Applied
	case forward == 0:
		return NotApplied
	}
	return Conflict
}

// Check dry-runs p both ways. With Conflict it also returns what the
// forward dry run printed, which names the hunks that failed.
func Check(ctx context.Context, r modules.Runner, p Patch) (Status, string, error) {
	rev, _, err := p.run(ctx, r, "--dry-run", "--reverse")
	if err != nil {
		return "", "", err
	}
	if rev == 0 {
		return Applied, "", nil
	}
	fwd, out, err := p.run(ctx, r, "--dry-run")
	if err != nil {
		return "", "", err
	}
	return classify(rev, fwd), out, nil
}

// InSync reports whether status is what state asks for.
func InSync(state State, status Status) bool {
	return state == Present && status == Applied || state == Absent && status == NotApplied
}

// Apply brings p to its state. A patch that neither applies nor reverses
// cleanly is an error, never a guess.
func Apply(ctx context.Context, r modules.Runner, p Patch) error {
	if err := p.Validate(); err != nil {
		return err
	}
	st, out, err := Check(ctx, r, p)
	if err != nil {
		return err
	}
	if st == Conflict {
		return fmt.Errorf("the patch neither applies nor reverses cleanly, so %s has moved on since it was written; patch says: %s", p.target(), out)
	}
	if InSync(p.State, st) {
		return nil
	}
	var extra []string
	if p.State == Absent {
		extra = append(extra, "--reverse")
	}
	code, out, err := p.run(ctx, r, extra...)
	if err == nil && code != 0 {
		err = fmt.Errorf("patch exited %d: %s", code, out)
	}
	return err
}

func (p Patch) target() string {
	if p.Dest != "" {
		return p.Dest
	}
	return p.Basedir
}
