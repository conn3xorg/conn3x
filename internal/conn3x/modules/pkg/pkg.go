// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package pkg installs, upgrades and removes OS packages with dnf on the
// Red Hat family and apt on Debian and Ubuntu.
package pkg

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/opentofu/opentofu/internal/conn3x/modules"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// Family is a package manager family.
type Family string

const (
	RPM Family = "rpm"
	Deb Family = "deb"
)

// State is what should be true of the package.
type State string

const (
	Present State = "present"
	Absent  State = "absent"
	Latest  State = "latest"
)

// Desired describes the package as it should be.
type Desired struct {
	Name    string
	State   State
	Version string // optional, with Present
}

// Actual describes the package as it is.
type Actual struct {
	Installed bool
	Version   string // as the package manager reports it
	Candidate string // newest available, only read for Latest
}

var (
	namePattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+_:@-]*$`)
	versionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+~:_-]*$`)
)

// Validate checks a Desired before anything runs on a host.
func (d Desired) Validate() error {
	if !namePattern.MatchString(d.Name) {
		return fmt.Errorf("package name %q is not valid", d.Name)
	}
	switch d.State {
	case Present, Latest:
	case Absent:
		if d.Version != "" {
			return errors.New("version only applies when state is \"present\"")
		}
	default:
		return fmt.Errorf("state must be %q, %q or %q, not %q", Present, Absent, Latest, d.State)
	}
	if d.Version != "" {
		if d.State == Latest {
			return errors.New("version only applies when state is \"present\"")
		}
		if !versionPattern.MatchString(d.Version) {
			return fmt.Errorf("version %q is not valid", d.Version)
		}
	}
	return nil
}

// DetectFamily reads /etc/os-release to choose the package manager.
func DetectFamily(ctx context.Context, r modules.Runner) (Family, error) {
	res, err := r.Run(ctx, "cat /etc/os-release", nil)
	if err != nil {
		return "", err
	}
	if res.ExitCode != 0 {
		return "", fmt.Errorf("reading /etc/os-release: %s", strings.TrimSpace(string(res.Stderr)))
	}
	fields := map[string]string{}
	for _, line := range strings.Split(string(res.Stdout), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			fields[k] = strings.Trim(v, `"'`)
		}
	}
	ids := append([]string{fields["ID"]}, strings.Fields(fields["ID_LIKE"])...)
	for _, id := range ids {
		switch id {
		case "rhel", "fedora", "centos", "rocky", "almalinux":
			return RPM, nil
		case "debian", "ubuntu":
			return Deb, nil
		}
	}
	return "", fmt.Errorf("%s is not supported yet; Conn3x manages packages on the Red Hat family and on Debian and Ubuntu", fields["ID"])
}

// Read reports whether the package is installed. With candidate set it also
// asks the package manager for the newest available version.
func Read(ctx context.Context, r modules.Runner, family Family, name string, candidate bool) (Actual, error) {
	if !namePattern.MatchString(name) {
		return Actual{}, fmt.Errorf("package name %q is not valid", name)
	}
	q := ssh.Quote(name)
	var a Actual
	switch family {
	case RPM:
		res, err := r.Run(ctx, "rpm -q --qf '%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\\n' -- "+q, nil)
		if err != nil {
			return a, err
		}
		if res.ExitCode == 0 {
			lines := strings.Fields(string(res.Stdout))
			if len(lines) > 0 {
				last := lines[len(lines)-1]
				if i := strings.LastIndex(last, "."); i > 0 {
					last = last[:i]
				}
				a = Actual{Installed: true, Version: last}
			}
		}
		if candidate {
			res, err := r.Run(ctx, "dnf -q repoquery --latest-limit 1 --qf '%{epoch}:%{version}-%{release}' -- "+q, nil)
			if err != nil {
				return a, err
			}
			if res.ExitCode != 0 {
				return a, fmt.Errorf("finding the newest %s: %s", name, strings.TrimSpace(string(res.Stderr)))
			}
			a.Candidate = strings.TrimSpace(string(res.Stdout))
		}
	case Deb:
		res, err := r.Run(ctx, "dpkg-query -W -f '${db:Status-Abbrev} ${Version}\\n' -- "+q, nil)
		if err != nil {
			return a, err
		}
		if res.ExitCode == 0 {
			fields := strings.Fields(string(res.Stdout))
			if len(fields) >= 2 && fields[0] == "ii" {
				a = Actual{Installed: true, Version: fields[1]}
			}
		}
		if candidate {
			res, err := r.Run(ctx, "apt-cache policy -- "+q, nil)
			if err != nil {
				return a, err
			}
			for _, line := range strings.Split(string(res.Stdout), "\n") {
				if v, ok := strings.CutPrefix(strings.TrimSpace(line), "Candidate:"); ok {
					if v = strings.TrimSpace(v); v != "(none)" {
						a.Candidate = v
					}
				}
			}
		}
	default:
		return a, fmt.Errorf("unknown package family %q", family)
	}
	return a, nil
}

// NeedsChange reports whether Apply would change anything.
func NeedsChange(d Desired, a Actual) bool {
	switch d.State {
	case Absent:
		return a.Installed
	case Latest:
		return !a.Installed || (a.Candidate != "" && a.Candidate != a.Version)
	default:
		return !a.Installed || (d.Version != "" && !versionMatches(a.Version, d.Version))
	}
}

// versionMatches accepts an exact match, or want as the leading part of a
// full version: "1.26.3" matches "1:1.26.3-2.el10".
func versionMatches(actual, want string) bool {
	if !strings.Contains(want, ":") {
		if _, rest, ok := strings.Cut(actual, ":"); ok {
			actual = rest
		}
	}
	return actual == want || strings.HasPrefix(actual, want+"-")
}

const aptGet = "DEBIAN_FRONTEND=noninteractive apt-get -y -q -o DPkg::Lock::Timeout=300 -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold"

// Apply installs, upgrades or removes the package.
func Apply(ctx context.Context, r modules.Runner, family Family, d Desired) error {
	if err := d.Validate(); err != nil {
		return err
	}
	switch family {
	case RPM:
		spec := d.Name
		if d.Version != "" {
			spec += "-" + d.Version
		}
		switch d.State {
		case Absent:
			return run(ctx, r, "dnf -y remove "+ssh.Quote(d.Name))
		case Latest:
			if err := run(ctx, r, "dnf -y install "+ssh.Quote(d.Name)); err != nil {
				return err
			}
			return run(ctx, r, "dnf -y upgrade "+ssh.Quote(d.Name))
		default:
			return run(ctx, r, "dnf -y install "+ssh.Quote(spec))
		}
	case Deb:
		spec := d.Name
		if d.Version != "" {
			spec += "=" + d.Version
		}
		if d.State == Absent {
			return run(ctx, r, aptGet+" remove "+ssh.Quote(d.Name))
		}
		err := run(ctx, r, aptGet+" install "+ssh.Quote(spec))
		if err != nil && (strings.Contains(err.Error(), "Unable to locate package") || strings.Contains(err.Error(), "has no installation candidate")) {
			// Fresh hosts often have no package lists yet.
			if err := run(ctx, r, "apt-get -q -o DPkg::Lock::Timeout=300 update"); err != nil {
				return err
			}
			err = run(ctx, r, aptGet+" install "+ssh.Quote(spec))
		}
		return err
	}
	return fmt.Errorf("unknown package family %q", family)
}

func run(ctx context.Context, r modules.Runner, cmd string) error {
	res, err := r.Run(ctx, cmd, nil)
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		msg := strings.TrimSpace(string(res.Stderr))
		if msg == "" {
			msg = strings.TrimSpace(string(res.Stdout))
		}
		return fmt.Errorf("%s (exit status %d)", msg, res.ExitCode)
	}
	return nil
}
