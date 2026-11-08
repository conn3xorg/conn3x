// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package confirm guards a change that could lock Conn3x out of a host,
// such as a new sshd_config or a firewall rule, the way an EOS switch's
// commit timer does: before the change, the host keeps a copy of what was
// there and schedules its own revert; after it, Conn3x logs in again over a
// new connection and cancels the revert. If that login never comes, the
// host puts the old state back by itself, whatever happened to Conn3x.
package confirm

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/opentofu/opentofu/internal/conn3x/modules"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// Dir holds the copies and revert scripts. It's root's only: a copy is as
// often a secret as not.
const Dir = "/var/lib/conn3x/revert"

// Guard is one guarded change.
type Guard struct {
	// ID names the revert: its directory and its systemd unit.
	ID string
	// Files are put back as they were: restored from a copy, or removed
	// when they didn't exist.
	Files []string
	// Undo are commands the revert runs after restoring the files, such as
	// deleting a firewall rule the change added.
	Undo []string
	// Reload runs after the change, and again after a revert.
	Reload string
	// After is how long the host waits for the confirm before reverting.
	After time.Duration
}

func (g Guard) dir() string  { return Dir + "/" + g.ID }
func (g Guard) unit() string { return "conn3x-revert-" + g.ID }

// Script is the revert, as the host runs it.
func (g Guard) Script() string {
	q := ssh.Quote
	var b strings.Builder
	b.WriteString("#!/bin/sh\n# Written by Conn3x: puts back what a change replaced, if Conn3x never confirmed it.\nset -u\n")
	fmt.Fprintf(&b, "d=%s\n", q(g.dir()))
	for i, f := range g.Files {
		fmt.Fprintf(&b, "if [ -e \"$d/%d.absent\" ]; then rm -f -- %s; else cp -a -- \"$d/%d\" %s; fi\n", i, q(f), i, q(f))
	}
	for _, u := range g.Undo {
		fmt.Fprintf(&b, "%s || true\n", u)
	}
	if g.Reload != "" {
		fmt.Fprintf(&b, "%s || true\n", g.Reload)
	}
	b.WriteString("rm -rf -- \"$d\"\n")
	return b.String()
}

func run(ctx context.Context, r modules.Runner, cmd string, stdin []byte) (string, error) {
	res, err := r.Run(ctx, cmd, stdin)
	if err != nil {
		return "", err
	}
	if res.ExitCode != 0 {
		msg := strings.TrimSpace(string(res.Stderr))
		if msg == "" {
			msg = strings.TrimSpace(string(res.Stdout))
		}
		return "", fmt.Errorf("exit status %d: %s", res.ExitCode, msg)
	}
	return string(res.Stdout), nil
}

// Arm keeps copies of the files and schedules the revert. It refuses a
// host without systemd-run rather than change it unguarded.
func Arm(ctx context.Context, r modules.Runner, g Guard) error {
	if g.ID == "" || g.After <= 0 {
		return errors.New("a guard needs an ID and a time to wait")
	}
	if _, err := run(ctx, r, "command -v systemd-run >/dev/null 2>&1", nil); err != nil {
		return errors.New("confirm_after needs systemd on the host, to revert the change by itself if Conn3x can't log in again; this host has no systemd-run")
	}
	q := ssh.Quote
	var b strings.Builder
	fmt.Fprintf(&b, "set -e\numask 077\nmkdir -p -m 0700 %s\nchmod 0700 %s\nrm -rf -- %s\nmkdir -m 0700 %s\n", q(Dir), q(Dir), q(g.dir()), q(g.dir()))
	for i, f := range g.Files {
		fmt.Fprintf(&b, "if [ -e %s ]; then cp -a -- %s %s/%d; else : > %s/%d.absent; fi\n", q(f), q(f), q(g.dir()), i, q(g.dir()), i)
	}
	fmt.Fprintf(&b, "cat > %s/revert.sh\n", q(g.dir()))
	secs := int(g.After.Round(time.Second) / time.Second)
	fmt.Fprintf(&b, "systemd-run --quiet --collect --unit=%s --on-active=%ds --timer-property=AccuracySec=1s /bin/sh %s/revert.sh\n", q(g.unit()), secs, q(g.dir()))
	if _, err := run(ctx, r, b.String(), []byte(g.Script())); err != nil {
		return fmt.Errorf("scheduling the revert: %w", err)
	}
	return nil
}

// RevertNow puts the old state back at once, for a change or reload that
// failed: a failed reload can leave a service down, and waiting out the
// timer would only keep it down longer.
func RevertNow(ctx context.Context, r modules.Runner, g Guard) error {
	cmd := fmt.Sprintf("systemctl stop %s.timer 2>/dev/null; if [ -f %s/revert.sh ]; then /bin/sh %s/revert.sh; fi", ssh.Quote(g.unit()), ssh.Quote(g.dir()), ssh.Quote(g.dir()))
	if _, err := run(ctx, r, cmd, nil); err != nil {
		return fmt.Errorf("reverting: %w", err)
	}
	return nil
}

// ErrAlreadyReverted is Confirm's error when the timer had already fired.
var ErrAlreadyReverted = errors.New("the host had already put the old state back")

// Confirm cancels the revert. Run it over a new connection: that the login
// still works is what it confirms.
func Confirm(ctx context.Context, r modules.Runner, g Guard) error {
	cmd := fmt.Sprintf("systemctl is-active --quiet %s.timer || exit 3\nsystemctl stop %s.timer\nrm -rf -- %s", ssh.Quote(g.unit()), ssh.Quote(g.unit()), ssh.Quote(g.dir()))
	res, err := r.Run(ctx, cmd, nil)
	if err != nil {
		return err
	}
	switch res.ExitCode {
	case 0:
		return nil
	case 3:
		return ErrAlreadyReverted
	}
	return fmt.Errorf("cancelling the revert: exit status %d: %s", res.ExitCode, strings.TrimSpace(string(res.Stderr)))
}
