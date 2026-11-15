// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package flatpak installs applications and runtimes from a Flatpak remote
// such as Flathub, into the system installation or the connecting user's.
package flatpak

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/opentofu/opentofu/internal/conn3x/modules"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// State is what should be true of the app.
type State string

const (
	Present State = "present"
	Absent  State = "absent"
	Latest  State = "latest"
)

// Method is which installation holds the app.
type Method string

const (
	System Method = "system"
	User   Method = "user"
)

// Desired describes the app as it should be.
type Desired struct {
	Name   string // application ID, such as org.gnome.Calculator
	Remote string // where to install it from
	Method Method
	State  State
}

// Actual describes the app as it is.
type Actual struct {
	Installed bool
	Origin    string // the remote it came from
	Outdated  bool   // the remote has a newer build, only read for Latest
}

var (
	// An application ID is reverse-DNS with at least three parts, each a
	// word that doesn't start with a digit; flatpak refuses anything else.
	namePattern   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]*(\.[A-Za-z_][A-Za-z0-9_-]*){2,}$`)
	remotePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
)

// Validate checks a Desired before anything runs on a host.
func (d Desired) Validate() error {
	if !namePattern.MatchString(d.Name) {
		return fmt.Errorf("name %q must be an application ID such as org.gnome.Calculator, with no branch, arch or URL", d.Name)
	}
	if !remotePattern.MatchString(d.Remote) {
		return fmt.Errorf("remote %q must be a remote's name, such as flathub", d.Remote)
	}
	switch d.Method {
	case System, User:
	default:
		return fmt.Errorf("method must be %q or %q, not %q", System, User, d.Method)
	}
	switch d.State {
	case Present, Latest, Absent:
	default:
		return fmt.Errorf("state must be %q, %q or %q, not %q", Present, Absent, Latest, d.State)
	}
	return nil
}

// InSync reports whether the host matches. Present accepts the app from any
// remote, as Ansible does; remote only says where to install it from.
func (d Desired) InSync(a Actual) bool {
	switch d.State {
	case Absent:
		return !a.Installed
	case Latest:
		return a.Installed && !a.Outdated
	}
	return a.Installed
}

// flags names the installation for every command. Only the ones that change
// it take -y --noninteractive, which skip prompts nobody is there to answer.
func (d Desired) flags() string {
	return "--" + string(d.Method)
}

const quiet = "-y --noninteractive"

func run(ctx context.Context, r modules.Runner, cmd string) (string, error) {
	res, err := r.Run(ctx, cmd, nil)
	if err != nil {
		return "", err
	}
	if res.ExitCode != 0 {
		return "", errors.New(strings.TrimSpace(string(res.Stderr) + string(res.Stdout)))
	}
	return string(res.Stdout), nil
}

// Read reports whether d.Name is installed, and with Latest whether the
// remote has a newer build, which asks the remote over the network.
func Read(ctx context.Context, r modules.Runner, d Desired) (Actual, error) {
	if err := d.Validate(); err != nil {
		return Actual{}, err
	}
	var a Actual
	out, err := run(ctx, r, fmt.Sprintf("flatpak list %s --columns=application,origin", d.flags()))
	if err != nil {
		return a, err
	}
	for _, line := range strings.Split(out, "\n") {
		if f := strings.Split(line, "\t"); len(f) >= 2 && f[0] == d.Name {
			a.Installed, a.Origin = true, f[1]
		}
	}
	if d.State == Latest && a.Installed {
		out, err = run(ctx, r, fmt.Sprintf("flatpak remote-ls --updates %s --columns=application", d.flags()))
		if err != nil {
			return a, fmt.Errorf("asking the remote for updates: %w", err)
		}
		for _, line := range strings.Split(out, "\n") {
			if strings.TrimSpace(line) == d.Name {
				a.Outdated = true
			}
		}
	}
	return a, nil
}

// Apply makes the host match: installs from d.Remote, updates, or uninstalls,
// and nothing when it already matches.
func Apply(ctx context.Context, r modules.Runner, d Desired) error {
	if err := d.Validate(); err != nil {
		return err
	}
	a, err := Read(ctx, r, d)
	if err != nil {
		return err
	}
	if d.InSync(a) {
		return nil
	}
	var cmd string
	switch {
	case d.State == Absent:
		cmd = fmt.Sprintf("flatpak uninstall %s %s %s", quiet, d.flags(), ssh.Quote(d.Name))
	case a.Installed:
		cmd = fmt.Sprintf("flatpak update %s %s %s", quiet, d.flags(), ssh.Quote(d.Name))
	default:
		cmd = fmt.Sprintf("flatpak install %s %s %s %s", quiet, d.flags(), ssh.Quote(d.Remote), ssh.Quote(d.Name))
	}
	_, err = run(ctx, r, cmd)
	return err
}
