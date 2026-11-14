// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package pkg

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/opentofu/opentofu/internal/conn3x/modules"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// Hold is whether a package's updates are held back: apt-mark hold on the
// Debian family, dnf versionlock on the Red Hat family.
type Hold struct {
	Name string
	Held bool
}

// Validate checks a Hold before anything runs on a host.
func (h Hold) Validate() error {
	if !namePattern.MatchString(h.Name) {
		return fmt.Errorf("package name %q is not valid", h.Name)
	}
	return nil
}

// versionlockHint is for dnf 4 without its plugin, which says "No such
// command: versionlock".
const versionlockHint = "dnf versionlock isn't on this host: install python3-dnf-plugin-versionlock, for example with a package step before this one"

// dnf 4 lists a lock as name-epoch:version-release.*, dnf 5 as
// "Package name: name".
var (
	dnf4Lock = regexp.MustCompile(`^(.+)-[0-9]+:[^-]+-[^-]+\.\*$`)
	dnf5Lock = regexp.MustCompile(`^Package name: (\S+)$`)
)

// ReadHold reports whether the package is held.
func ReadHold(ctx context.Context, r modules.Runner, family Family, name string) (bool, error) {
	cmd := "apt-mark showhold"
	if family == RPM {
		cmd = "dnf -q versionlock list"
	}
	res, err := r.Run(ctx, cmd, nil)
	if err != nil {
		return false, err
	}
	if res.ExitCode != 0 {
		return false, holdError(family, string(res.Stderr)+string(res.Stdout), res.ExitCode)
	}
	return heldIn(family, string(res.Stdout), name), nil
}

func heldIn(family Family, out, name string) bool {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if family == Deb {
			if line == name {
				return true
			}
			continue
		}
		for _, re := range []*regexp.Regexp{dnf4Lock, dnf5Lock} {
			if m := re.FindStringSubmatch(line); m != nil && m[1] == name {
				return true
			}
		}
	}
	return false
}

func holdError(family Family, out string, code int) error {
	if family == RPM && strings.Contains(out, "No such command") {
		return fmt.Errorf("%s", versionlockHint)
	}
	return fmt.Errorf("%s (exit status %d)", strings.TrimSpace(out), code)
}

// ApplyHold holds or releases the package.
func ApplyHold(ctx context.Context, r modules.Runner, family Family, h Hold) error {
	if err := h.Validate(); err != nil {
		return err
	}
	var cmd string
	switch {
	case family == Deb && h.Held:
		cmd = "apt-mark hold "
	case family == Deb:
		cmd = "apt-mark unhold "
	case h.Held:
		cmd = "dnf -q versionlock add "
	default:
		cmd = "dnf -q versionlock delete "
	}
	err := Run(ctx, r, cmd+ssh.Quote(h.Name))
	if err != nil && family == RPM && strings.Contains(err.Error(), "No such command") {
		return fmt.Errorf("%s", versionlockHint)
	}
	return err
}
