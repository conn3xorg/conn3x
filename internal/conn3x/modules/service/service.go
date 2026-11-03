// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package service starts, stops, enables and disables systemd units.
package service

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/opentofu/opentofu/internal/conn3x/modules"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// State is whether the unit should be running.
type State string

const (
	Started State = "started"
	Stopped State = "stopped"
)

// Desired is the unit as it should be. An empty State or nil Enabled
// leaves that aspect alone.
type Desired struct {
	Name    string
	State   State
	Enabled *bool
}

// Actual is the unit as it is.
type Actual struct {
	Exists      bool
	Running     bool
	Enabled     bool
	NeedsReload bool // its unit file changed since systemd last loaded it
}

var unitPattern = regexp.MustCompile(`^[A-Za-z0-9:_.@\\-]+$`)

// Unit returns the full unit name, adding ".service" when there is no suffix.
func Unit(name string) string {
	if strings.Contains(name, ".") {
		return name
	}
	return name + ".service"
}

// Validate checks a Desired before anything runs on a host.
func (d Desired) Validate() error {
	if !unitPattern.MatchString(d.Name) {
		return fmt.Errorf("unit name %q is not valid", d.Name)
	}
	switch d.State {
	case "", Started, Stopped:
		return nil
	}
	return fmt.Errorf("state must be %q or %q, not %q", Started, Stopped, d.State)
}

// Read asks systemd for the unit's state. A runner that is a
// modules.UnitReader answers natively when it can.
func Read(ctx context.Context, r modules.Runner, name string) (Actual, error) {
	if !unitPattern.MatchString(name) {
		return Actual{}, fmt.Errorf("unit name %q is not valid", name)
	}
	if ur, ok := r.(modules.UnitReader); ok {
		props, err := ur.ReadUnit(ctx, Unit(name))
		if err == nil {
			return actual(props), nil
		}
		if !errors.Is(err, errors.ErrUnsupported) {
			return Actual{}, err
		}
	}
	res, err := systemctl(ctx, r, "systemctl show -p LoadState,ActiveState,UnitFileState,NeedDaemonReload -- "+ssh.Quote(Unit(name)))
	if err != nil {
		return Actual{}, err
	}
	if res.ExitCode != 0 {
		return Actual{}, fmt.Errorf("systemctl show %s: %s", Unit(name), strings.TrimSpace(string(res.Stderr)))
	}
	props := map[string]string{}
	for _, line := range strings.Split(string(res.Stdout), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			props[k] = v
		}
	}
	return actual(props), nil
}

// actual reads the properties "systemctl show" prints.
func actual(props map[string]string) Actual {
	if props["LoadState"] == "not-found" {
		return Actual{}
	}
	return Actual{
		Exists:      true,
		Running:     props["ActiveState"] == "active" || props["ActiveState"] == "activating" || props["ActiveState"] == "reloading",
		Enabled:     strings.HasPrefix(props["UnitFileState"], "enabled"),
		NeedsReload: props["NeedDaemonReload"] == "yes",
	}
}

// NeedsChange reports whether Apply would change anything.
func NeedsChange(d Desired, a Actual) bool {
	if !a.Exists || a.NeedsReload {
		return true
	}
	if d.State == Started && !a.Running || d.State == Stopped && a.Running {
		return true
	}
	return d.Enabled != nil && *d.Enabled != a.Enabled
}

// Apply brings the unit to the desired state, reloading systemd first when
// its unit file changed.
func Apply(ctx context.Context, r modules.Runner, d Desired) error {
	if err := d.Validate(); err != nil {
		return err
	}
	a, err := Read(ctx, r, d.Name)
	if err != nil {
		return err
	}
	unit := ssh.Quote(Unit(d.Name))
	if a.NeedsReload || !a.Exists {
		if err := run(ctx, r, "systemctl daemon-reload"); err != nil {
			return err
		}
		if a, err = Read(ctx, r, d.Name); err != nil {
			return err
		}
	}
	if !a.Exists {
		return fmt.Errorf("systemd unit %s not found", Unit(d.Name))
	}
	if d.Enabled != nil && *d.Enabled != a.Enabled {
		verb := "disable"
		if *d.Enabled {
			verb = "enable"
		}
		if err := run(ctx, r, "systemctl "+verb+" -- "+unit); err != nil {
			return err
		}
	}
	switch {
	case d.State == Started && !a.Running:
		return run(ctx, r, "systemctl start -- "+unit)
	case d.State == Stopped && a.Running:
		return run(ctx, r, "systemctl stop -- "+unit)
	}
	return nil
}

// Restart restarts the unit; handlers use it.
func Restart(ctx context.Context, r modules.Runner, name string) error {
	return act(ctx, r, name, "restart")
}

// Reload asks the unit to reload its configuration.
func Reload(ctx context.Context, r modules.Runner, name string) error {
	return act(ctx, r, name, "reload")
}

// act runs a handler's systemctl verb, reloading systemd first when the
// unit file changed. A handler is notified by the step that changed it,
// after the service step planned against the old file, so that step
// can't be relied on to have reloaded.
func act(ctx context.Context, r modules.Runner, name, verb string) error {
	a, err := Read(ctx, r, name)
	if err != nil {
		return err
	}
	if a.NeedsReload {
		if err := run(ctx, r, "systemctl daemon-reload"); err != nil {
			return err
		}
	}
	return run(ctx, r, "systemctl "+verb+" -- "+ssh.Quote(Unit(name)))
}

// While systemd re-executes itself, which systemd's own package triggers
// can do in the middle of an apply, systemctl can't reach it for a moment.
// "Failed to connect to ... bus" means the request never got there. A reset
// or a dropped connection can come after systemd took it, and every call
// here is safe to repeat: show, start, stop, enable and daemon-reload end in
// the same state however often they run. restart and reload could run twice,
// which for a service is a second restart or reload, not a different result.
var (
	busError   = regexp.MustCompile(`Failed to connect to .*bus|Transport endpoint is not connected|Connection reset by peer`)
	busRetries = 30
	busWait    = time.Second
)

// systemctl runs cmd, a systemctl command, trying again while systemd can't
// be reached. Any other failure is returned straight away.
func systemctl(ctx context.Context, r modules.Runner, cmd string) (ssh.Result, error) {
	for try := 0; ; try++ {
		res, err := r.Run(ctx, cmd, nil)
		if err != nil || res.ExitCode == 0 || try == busRetries || !busError.Match(res.Stderr) {
			return res, err
		}
		select {
		case <-ctx.Done():
			return res, ctx.Err()
		case <-time.After(busWait):
		}
	}
}

func run(ctx context.Context, r modules.Runner, cmd string) error {
	res, err := systemctl(ctx, r, cmd)
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		msg := strings.TrimSpace(string(res.Stderr))
		if msg == "" {
			msg = fmt.Sprintf("exit status %d", res.ExitCode)
		}
		return fmt.Errorf("%s: %s", cmd, msg)
	}
	return nil
}
