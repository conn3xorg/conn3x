// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package snap installs snaps and keeps them on a channel, through the snap
// command that snapd ships.
package snap

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/opentofu/opentofu/internal/conn3x/modules"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// Snap is one snap as it should be on the host.
type Snap struct {
	Name    string
	Channel string // such as stable, 5.21/stable or latest/edge; "" keeps whatever the host tracks
	Classic bool   // allow classic confinement, as snap install --classic does
}

// Actual is what the host has for a snap.
type Actual struct {
	Installed bool
	Tracking  string // the channel it follows, such as latest/stable; "-" for a snap installed from a file
	Classic   bool
}

var (
	// The store's rule for a name: lowercase letters and digits, with single
	// hyphens between. It also keeps a name from being read as a flag.
	snapName = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	// track, track/risk or track/risk/branch, a risk alone, or risk/branch.
	channelName = regexp.MustCompile(`^[A-Za-z0-9.][A-Za-z0-9._-]*(/[A-Za-z0-9.][A-Za-z0-9._-]*){0,2}$`)
	risks       = map[string]bool{"stable": true, "candidate": true, "beta": true, "edge": true}
)

// Validate checks a Snap before anything reaches the host.
func (s Snap) Validate() error {
	if !snapName.MatchString(s.Name) {
		return fmt.Errorf("name %q must be lowercase letters, digits and single hyphens, such as lxd or hello-world", s.Name)
	}
	if s.Channel != "" && !channelName.MatchString(s.Channel) {
		return fmt.Errorf("channel %q must be a channel such as stable, 5.21/stable or latest/edge", s.Channel)
	}
	return nil
}

// fullChannel spells a channel the way snap list prints what it tracks:
// stable is latest/stable, and a track alone is its stable risk.
func fullChannel(c string) string {
	parts := strings.Split(c, "/")
	switch {
	case len(parts) == 1 && risks[parts[0]]:
		return "latest/" + c
	case len(parts) == 1:
		return c + "/stable"
	case len(parts) == 2 && risks[parts[0]]:
		return "latest/" + c
	}
	return c
}

// InSync reports whether an installed snap is what s asks for. Confinement
// is only checked one way: a snap installed as classic stays classic, since
// snapd has no refresh back to strict.
func (s Snap) InSync(a Actual) bool {
	return a.Installed && (s.Channel == "" || a.Tracking == fullChannel(s.Channel)) && (!s.Classic || a.Classic)
}

// findSnap names the command, or says what to install. snapd isn't in a
// minimal Ubuntu or any Red Hat family image.
const findSnap = `command -v snap >/dev/null 2>&1 || { echo "snapd isn't installed on this host; install the snapd package (apt install snapd, or dnf install snapd and enable snapd.socket)" >&2; exit 3; }
`

// listFlags keeps snap list to plain text: the publisher's verified mark is
// printed as ** rather than a check mark, and nothing is coloured. snapd has
// no machine-readable listing on the command line, so the columns are parsed.
const listFlags = "--unicode=never --color=never"

// Read returns what the host has for name.
func Read(ctx context.Context, r modules.Runner, name string) (Actual, error) {
	if !snapName.MatchString(name) {
		return Actual{}, fmt.Errorf("name %q must be lowercase letters, digits and single hyphens", name)
	}
	res, err := r.Run(ctx, findSnap+"snap list "+listFlags+" "+ssh.Quote(name), nil)
	if err != nil {
		return Actual{}, err
	}
	stderr := strings.TrimSpace(string(res.Stderr))
	if res.ExitCode != 0 {
		if res.ExitCode == 1 && strings.Contains(stderr, "no matching snaps installed") {
			return Actual{}, nil
		}
		return Actual{}, errors.New(stderr)
	}
	return parseList(string(res.Stdout), name)
}

// parseList reads one snap's row out of snap list. The six columns, Name
// Version Rev Tracking Publisher Notes, never hold spaces, and an empty one
// is printed as -.
func parseList(out, name string) (Actual, error) {
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || f[0] != name {
			continue
		}
		if len(f) < 6 {
			return Actual{}, fmt.Errorf("snap list printed %q, which isn't the six columns this version of Conn3x reads", line)
		}
		a := Actual{Installed: true, Tracking: f[3]}
		for _, note := range strings.Split(f[5], ",") {
			if note == "classic" {
				a.Classic = true
			}
		}
		return a, nil
	}
	return Actual{}, nil
}

// Apply installs s when it's missing, or refreshes it onto Channel, or to
// classic confinement, when it isn't there yet. snap exits 0 on a refresh
// that changed nothing, so the host is read back to prove the change took.
func Apply(ctx context.Context, r modules.Runner, s Snap) error {
	if err := s.Validate(); err != nil {
		return err
	}
	act, err := Read(ctx, r, s.Name)
	if err != nil {
		return err
	}
	if s.InSync(act) {
		return nil
	}
	verb := "install"
	if act.Installed {
		verb = "refresh"
	}
	cmd := "snap " + verb
	if s.Classic {
		cmd += " --classic"
	}
	if s.Channel != "" {
		cmd += " --channel=" + ssh.Quote(s.Channel)
	}
	if err := check(r.Run(ctx, findSnap+cmd+" "+ssh.Quote(s.Name), nil)); err != nil {
		return err
	}
	act, err = Read(ctx, r, s.Name)
	if err != nil {
		return err
	}
	if !s.InSync(act) {
		return fmt.Errorf("snap %s %s exited 0, but snap list still shows it tracking %s, classic %v", verb, s.Name, act.Tracking, act.Classic)
	}
	return nil
}

// Remove takes name off the host. A snap that isn't there is left alone.
func Remove(ctx context.Context, r modules.Runner, name string) error {
	act, err := Read(ctx, r, name)
	if err != nil || !act.Installed {
		return err
	}
	return check(r.Run(ctx, findSnap+"snap remove "+ssh.Quote(name), nil))
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
