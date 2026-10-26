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
	res, err := r.Run(ctx, "systemctl show -p LoadState,ActiveState,UnitFileState,NeedDaemonReload -- "+ssh.Quote(Unit(name)), nil)
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
	if !unitPattern.MatchString(name) {
		return fmt.Errorf("unit name %q is not valid", name)
	}
	return run(ctx, r, "systemctl restart -- "+ssh.Quote(Unit(name)))
}

// Reload asks the unit to reload its configuration.
func Reload(ctx context.Context, r modules.Runner, name string) error {
	if !unitPattern.MatchString(name) {
		return fmt.Errorf("unit name %q is not valid", name)
	}
	return run(ctx, r, "systemctl reload -- "+ssh.Quote(Unit(name)))
}

func run(ctx context.Context, r modules.Runner, cmd string) error {
	res, err := r.Run(ctx, cmd, nil)
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
