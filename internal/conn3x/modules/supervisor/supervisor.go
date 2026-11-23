// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package supervisor keeps a supervisord program or group loaded, running
// or stopped, with supervisorctl.
package supervisor

import (
	"context"
	"errors"
	"fmt"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/opentofu/opentofu/internal/conn3x/modules"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// State is what a Program should be.
type State string

const (
	Present State = "present" // loaded, left running or stopped as it is
	Started State = "started"
	Stopped State = "stopped"
	Absent  State = "absent"
)

// Conn is how supervisorctl reaches supervisord. Empty fields are left to
// supervisorctl's own defaults. There's no username or password: those
// belong in the [supervisorctl] section of Config, so they stay out of
// state and off the command line.
type Conn struct {
	Config, ServerURL, Path string
}

// Program is a program, or a group when Name ends in a colon, and the
// state it should be in.
type Program struct {
	Name  string
	State State
	Conn
}

// Process is one line of supervisorctl status: a name such as "app" or
// "web:web_00" and a state such as "RUNNING".
type Process struct{ Name, State string }

var (
	nameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.@+-]*:?$`)
	// supervisord's process states.
	states = []string{"STOPPED", "STARTING", "RUNNING", "BACKOFF", "STOPPING", "EXITED", "FATAL", "UNKNOWN"}
)

// Validate checks a Program before anything reaches the host.
func (p Program) Validate() error {
	if !nameRe.MatchString(p.Name) {
		return fmt.Errorf("name %q must be a program, such as app, or a group with a trailing colon, such as web:: letters, digits and _.@+-", p.Name)
	}
	if g := group(p.Name); g == "all" {
		return errors.New(`name "all" means every program to supervisorctl; give each its own step`)
	}
	if !slices.Contains([]State{Present, Started, Stopped, Absent}, p.State) {
		return fmt.Errorf(`state must be "present", "started", "stopped" or "absent", not %q`, p.State)
	}
	for what, v := range map[string]string{"config": p.Config, "supervisorctl_path": p.Path} {
		if v != "" && (!path.IsAbs(v) || strings.ContainsAny(v, "\r\n\x00")) {
			return fmt.Errorf("%s %q must be an absolute path", what, v)
		}
	}
	if strings.ContainsAny(p.ServerURL, "\r\n\x00") {
		return errors.New("server_url can't hold a line break or NUL")
	}
	if strings.Contains(p.ServerURL, "@") {
		return errors.New("server_url can't hold a login; put username and password in the [supervisorctl] section of the config file and point config at it")
	}
	return nil
}

// group is the name add, remove and update take: a program's own group
// has its name.
func group(name string) string { return strings.TrimSuffix(name, ":") }

// command is supervisorctl with c's options, then args, every value quoted.
func (c Conn) command(args ...string) string {
	parts := []string{"supervisorctl"}
	if c.Path != "" {
		parts[0] = ssh.Quote(c.Path)
	}
	for _, f := range [][2]string{{"-c", c.Config}, {"-s", c.ServerURL}} {
		if f[1] != "" {
			parts = append(parts, f[0], ssh.Quote(f[1]))
		}
	}
	for _, a := range args {
		parts = append(parts, ssh.Quote(a))
	}
	return strings.Join(parts, " ")
}

const missingHint = "supervisorctl isn't on this host: install the supervisor package, for example with a package step before this one, or set supervisorctl_path"

// Read returns the processes supervisorctl status lists for p.Name, none
// when supervisord doesn't know it.
func Read(ctx context.Context, r modules.Runner, p Program) ([]Process, error) {
	res, err := r.Run(ctx, p.command("status", p.Name), nil)
	if err != nil {
		return nil, err
	}
	if res.ExitCode == 127 {
		return nil, errors.New(missingHint)
	}
	// status exits 3 when one isn't running and 4 when there's no such
	// process, so the output says what happened, not the exit status.
	return parseStatus(string(res.Stdout)+string(res.Stderr), p.Name)
}

// parseStatus reads supervisorctl status output for name. Anything it
// doesn't recognise, such as "unix:///var/run/supervisor.sock no such
// file" when supervisord isn't running, is an error.
func parseStatus(out, name string) ([]Process, error) {
	var procs []Process
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		switch {
		case len(f) == 0:
		case len(f) >= 2 && slices.Contains(states, f[1]):
			if f[0] == name || strings.HasSuffix(name, ":") && strings.HasPrefix(f[0], name) {
				procs = append(procs, Process{Name: f[0], State: f[1]})
			}
		case strings.HasSuffix(line, "ERROR (no such process)"), strings.HasSuffix(line, "ERROR (no such group)"):
		default:
			return nil, fmt.Errorf("supervisorctl status %s: %s", name, strings.TrimSpace(out))
		}
	}
	return procs, nil
}

// active is what Ansible's supervisorctl counts as running.
func active(state string) bool {
	return state == "RUNNING" || state == "STARTING" || state == "BACKOFF"
}

func anyActive(procs []Process) bool {
	return slices.ContainsFunc(procs, func(p Process) bool { return active(p.State) })
}

func allActive(procs []Process) bool {
	return !slices.ContainsFunc(procs, func(p Process) bool { return !active(p.State) })
}

// InSync reports whether procs, from Read, are what state asks for.
func InSync(state State, procs []Process) bool {
	switch state {
	case Absent:
		return len(procs) == 0
	case Started:
		return len(procs) > 0 && allActive(procs)
	case Stopped:
		return len(procs) > 0 && !anyActive(procs)
	}
	return len(procs) > 0
}

// Apply brings p to its state. update runs supervisorctl update for its
// group first, which rereads its file and restarts it if that changed.
func Apply(ctx context.Context, r modules.Runner, p Program, update bool) error {
	if err := p.Validate(); err != nil {
		return err
	}
	g := group(p.Name)
	if update && p.State != Absent {
		if err := p.run(ctx, r, "update", g); err != nil {
			return err
		}
	}
	procs, err := Read(ctx, r, p)
	if err != nil {
		return err
	}
	if p.State == Absent {
		if len(procs) == 0 {
			return nil
		}
		// remove refuses a running program.
		if anyActive(procs) {
			if err := p.run(ctx, r, "stop", p.Name); err != nil {
				return err
			}
		}
		if err := p.run(ctx, r, "reread"); err != nil {
			return err
		}
		return p.run(ctx, r, "remove", g)
	}
	if len(procs) == 0 {
		if err := p.run(ctx, r, "reread"); err != nil {
			return err
		}
		if err := p.run(ctx, r, "add", g); err != nil {
			return err
		}
		// add starts a program with autostart, so look again.
		if procs, err = Read(ctx, r, p); err != nil {
			return err
		}
	}
	switch {
	case p.State == Started && !allActive(procs):
		return p.run(ctx, r, "start", p.Name)
	case p.State == Stopped && anyActive(procs):
		return p.run(ctx, r, "stop", p.Name)
	}
	return nil
}

// run runs one supervisorctl action. supervisorctl reports some failures,
// such as "app: ERROR (spawn error)", with exit status 0. The error names
// the action, never the whole command.
func (p Program) run(ctx context.Context, r modules.Runner, args ...string) error {
	res, err := r.Run(ctx, p.command(args...), nil)
	if err != nil {
		return err
	}
	if res.ExitCode == 127 {
		return errors.New(missingHint)
	}
	out := strings.TrimSpace(string(res.Stdout) + string(res.Stderr))
	if res.ExitCode != 0 || strings.Contains(out, "ERROR") {
		return fmt.Errorf("supervisorctl %s: %s", strings.Join(args, " "), out)
	}
	return nil
}
