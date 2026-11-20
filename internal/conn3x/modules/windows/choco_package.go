// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package windows

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/opentofu/opentofu/internal/conn3x/modules/windows/ps"
)

var (
	// A NuGet package ID, as Chocolatey's are.
	chocoID = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,99}$`)
	// A NuGet version: up to four numbers, and a pre-release label.
	chocoVersion = regexp.MustCompile(`^[0-9]+(\.[0-9]+){0,3}(-[0-9A-Za-z.-]+)?$`)
)

// ChocoPackage is a Chocolatey package that must be installed, at Version
// when it's set, or absent. Pinned nil leaves the pin as it is.
type ChocoPackage struct {
	Name    string
	Version string
	Absent  bool
	Source  string
	Pinned  *bool
}

// Validate checks a package before anything reaches a host.
func (p ChocoPackage) Validate() error {
	if !chocoID.MatchString(p.Name) || strings.Contains(p.Name, "..") {
		return fmt.Errorf("%q isn't a Chocolatey package ID", p.Name)
	}
	if p.Version != "" && !chocoVersion.MatchString(p.Version) {
		return fmt.Errorf("version %q isn't an exact version, such as 1.2.0", p.Version)
	}
	if p.Absent && (p.Version != "" || p.Pinned != nil || p.Source != "") {
		return errors.New(`version, source and pinned are for state "present"`)
	}
	if p.Source != "" {
		if err := validChocoSource(p.Source); err != nil {
			return err
		}
	}
	return nil
}

// validChocoSource takes an http(s) feed without a login in it, which would
// end up in state and the plan, or an absolute folder path.
func validChocoSource(s string) error {
	if strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return errors.New("source has a control character")
	}
	if u, err := url.Parse(s); err == nil && (u.Scheme == "https" || u.Scheme == "http") {
		if u.User != nil {
			return errors.New("source has a login in it, which would be stored in state and shown in plans; feed logins aren't supported yet")
		}
		if u.Host == "" {
			return fmt.Errorf("source %q has no host", s)
		}
		return nil
	}
	if !filepath.IsAbs(strings.ReplaceAll(s, `\`, "/")) && !regexp.MustCompile(`^[A-Za-z]:[\\/]|^\\\\[^\\]+\\`).MatchString(s) {
		return fmt.Errorf("source %q is neither an http(s) feed nor an absolute folder", s)
	}
	return nil
}

// sameVersion compares NuGet versions: missing trailing parts are zero, so
// 1.2 is 1.2.0.0, and a pre-release label ignores case.
func sameVersion(a, b string) bool {
	an, ap, _ := strings.Cut(a, "-")
	bn, bp, _ := strings.Cut(b, "-")
	if !strings.EqualFold(ap, bp) {
		return false
	}
	as, bs := strings.Split(an, "."), strings.Split(bn, ".")
	for i := range max(len(as), len(bs)) {
		x, y := 0, 0
		if i < len(as) {
			x, _ = strconv.Atoi(as[i])
		}
		if i < len(bs) {
			y, _ = strconv.Atoi(bs[i])
		}
		if x != y {
			return false
		}
	}
	return true
}

// ActualChoco is a package as the host's files have it.
type ActualChoco struct {
	Installed bool
	Version   string
	Pinned    bool
}

// ReadChoco reads a package from Chocolatey's files, running nothing: its
// lib folder's .nuspec for the version, and the .pin Chocolatey keeps for
// it. A host without Chocolatey is an error.
func ReadChoco(ctx context.Context, r ps.Runner, name string) (ActualChoco, error) {
	res, err := ps.Read(ctx, r, script("read_choco_package.ps1"), map[string]any{"name": name})
	if err != nil {
		return ActualChoco{}, err
	}
	var a struct {
		Chocolatey bool   `json:"chocolatey"`
		Installed  bool   `json:"installed"`
		Version    string `json:"version"`
		Pinned     bool   `json:"pinned"`
	}
	if err := json.Unmarshal(res.Value, &a); err != nil {
		return ActualChoco{}, fmt.Errorf("reading package %s: the host's answer wasn't valid", name)
	}
	if !a.Chocolatey {
		return ActualChoco{}, errors.New("Chocolatey isn't installed: the machine has no ChocolateyInstall variable, or no choco.exe under it")
	}
	return ActualChoco{Installed: a.Installed, Version: a.Version, Pinned: a.Pinned}, nil
}

// Matches reports whether the host has the package as configured.
func (p ChocoPackage) Matches(a ActualChoco) bool {
	if p.Absent {
		return !a.Installed
	}
	return a.Installed && (p.Version == "" || sameVersion(p.Version, a.Version)) && (p.Pinned == nil || *p.Pinned == a.Pinned)
}

// ApplyChoco installs, changes or removes a package with choco.exe and
// reports whether it asked for a reboot (3010 or 1641). It never reboots.
func ApplyChoco(ctx context.Context, r ps.Runner, p ChocoPackage, a ActualChoco, timeout time.Duration) (restart bool, err error) {
	if err := p.Validate(); err != nil {
		return false, err
	}
	install := !p.Absent && (!a.Installed || (p.Version != "" && !sameVersion(p.Version, a.Version)))
	// choco doesn't upgrade a pinned package, so the pin comes off first;
	// then it ends as wanted, which unset means as it was.
	unpin := install && a.Pinned
	pin := ""
	if !p.Absent {
		want, now := a.Pinned, a.Pinned && !unpin
		if p.Pinned != nil {
			want = *p.Pinned
		}
		switch {
		case want && !now:
			pin = "add"
		case !want && now:
			pin = "remove"
		}
	}
	res, err := ps.Apply(ctx, r, script("apply_choco_package.ps1"), map[string]any{
		"name": p.Name, "remove": p.Absent && a.Installed, "install": install, "version": p.Version,
		"source": p.Source, "unpin_first": unpin, "pin": pin,
	}, timeout)
	if err != nil {
		return false, err
	}
	var out struct {
		Restart bool `json:"restart"`
	}
	if err := json.Unmarshal(res.Value, &out); err != nil {
		return false, fmt.Errorf("reading the result for package %s: %w", p.Name, err)
	}
	return out.Restart, nil
}
