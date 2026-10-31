// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package pip installs Python packages into a virtual environment. There is
// no system-wide mode: it would fight the OS package manager, and pip itself
// refuses it on current distros.
package pip

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/opentofu/opentofu/internal/conn3x/modules"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
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
	Venv    string
	User    string // who runs everything; empty means whoever is connected
	State   State
	Version string // optional, with Present
}

// Actual describes the package as it is.
type Actual struct {
	Installed bool
	Version   string
	Candidate string // what pip would install, only read for Latest
}

var (
	namePattern = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$`)
	// A version pip's == reads as exactly one thing. Epochs and wildcards aren't pins this module can compare.
	versionPattern = regexp.MustCompile(`^([0-9]+(?:\.[0-9]+)*)((?:a|b|rc)[0-9]+)?(\.post[0-9]+)?(\.dev[0-9]+)?(\+[a-z0-9.]+)?$`)
	separators     = regexp.MustCompile(`[-_.]+`)
)

// Validate checks a Desired before anything runs on a host.
func (d Desired) Validate() error {
	if !namePattern.MatchString(d.Name) {
		return fmt.Errorf("package name %q must be a plain name, with no version, extras, URL or path", d.Name)
	}
	if !path.IsAbs(d.Venv) || path.Clean(d.Venv) != d.Venv || d.Venv == "/" || strings.ContainsAny(d.Venv, "\r\n") {
		return fmt.Errorf("venv %q must be a clean absolute path", d.Venv)
	}
	switch d.State {
	case Present, Latest, Absent:
	default:
		return fmt.Errorf("state must be %q, %q or %q, not %q", Present, Absent, Latest, d.State)
	}
	if d.Version != "" {
		if d.State != Present {
			return errors.New("version only applies when state is \"present\"")
		}
		if !versionPattern.MatchString(d.Version) {
			return fmt.Errorf("version %q must be one exact version, such as 2.32.3", d.Version)
		}
	}
	return nil
}

// comparable reduces a version to what pip's == compares: 1.0 equals 1.0.0,
// and a pin without a local part matches a build with one.
func comparable(v string, keepLocal bool) string {
	m := versionPattern.FindStringSubmatch(strings.ToLower(v))
	if m == nil {
		return v
	}
	release := m[1]
	for strings.HasSuffix(release, ".0") {
		release = strings.TrimSuffix(release, ".0")
	}
	out := release + m[2] + m[3] + m[4]
	if keepLocal {
		out += m[5]
	}
	return out
}

// sameVersion reports whether installed satisfies a pin of want.
func sameVersion(want, installed string) bool {
	return comparable(want, true) == comparable(installed, strings.Contains(want, "+"))
}

// NeedsChange says whether the host differs from what is wanted.
func NeedsChange(d Desired, a Actual) bool {
	switch d.State {
	case Absent:
		return a.Installed
	case Latest:
		return !a.Installed || (a.Candidate != "" && a.Candidate != a.Version)
	}
	return !a.Installed || (d.Version != "" && !sameVersion(d.Version, a.Version))
}

// normalize is the name rule from PEP 503.
func normalize(name string) string {
	return separators.ReplaceAllString(strings.ToLower(name), "-")
}

// script runs body as d.User, or whoever is connected, with $py set to the
// venv's python. Whoever runs it executes code from the venv, and pip builds
// can run more, so it first proves nobody else could have put code there: each
// directory down to the venv, and everything inside it, has to belong to root
// or to this user, and be safe from everyone else writing to it. That's what
// stops a run as root trusting a venv in someone's home. -I keeps python from
// importing out of the working directory or following PYTHON* variables.
func (d Desired) script(body string) string {
	s := fmt.Sprintf(`set -e
cd /
HOME=$(getent passwd "$(id -u)" | cut -d: -f6); export HOME
me=$(id -u)
real=$(readlink -m -- %s)
py=$real/bin/python
if [ "$me" = 0 ]; then w=022; else w=002; fi
p=$real
while :; do
  if [ -e "$p" ]; then
    set -- $(stat -L -c '%%u %%a' -- "$p")
    if [ "$1" != 0 ] && [ "$1" != "$me" ]; then
      echo "$p belongs to uid $1, so its owner could change what runs here; set user to the owner, or move the venv" >&2; exit 3
    fi
    m=0$2
    if [ $(( m & 0$w )) -ne 0 ] && [ $(( m & 01000 )) -eq 0 ]; then
      echo "$p can be written by other users, so they could change what runs here; fix its mode, or move the venv" >&2; exit 3
    fi
  fi
  [ "$p" = / ] && break
  p=$(dirname -- "$p")
done
if [ -e "$real" ]; then
  bad=$(find "$real" ! -type l \( \( ! -uid "$me" ! -uid 0 \) -o -perm /$w \) -print -quit)
  if [ -n "$bad" ]; then
    echo "$bad could have been changed by another user, so it won't be run; set user to the venv's owner, or rebuild the venv" >&2; exit 3
  fi
fi
usable() { [ -x "$py" ] && "$py" -I -m pip --version >/dev/null 2>&1; }
%s`, ssh.Quote(d.Venv), body)
	if d.User != "" {
		return modules.AsUser(d.User, s)
	}
	return s
}

func (d Desired) run(ctx context.Context, r modules.Runner, body string) (string, error) {
	res, err := r.Run(ctx, d.script(body), nil)
	if err != nil {
		return "", err
	}
	if res.ExitCode != 0 {
		return "", fmt.Errorf("%s", strings.TrimSpace(string(res.Stderr)))
	}
	return string(res.Stdout), nil
}

const pipFlags = "--disable-pip-version-check --no-input"

// Read reports what the venv holds. A venv that's missing, or that python or
// pip can't run in, holds nothing; apply builds it.
func Read(ctx context.Context, r modules.Runner, d Desired) (Actual, error) {
	out, err := d.run(ctx, r, fmt.Sprintf(`usable || exit 0
"$py" -I -m pip list %s --format=json`, pipFlags))
	if err != nil {
		return Actual{}, err
	}
	var a Actual
	if strings.TrimSpace(out) == "" {
		return a, nil
	}
	var list []struct{ Name, Version string }
	if err := json.Unmarshal([]byte(out), &list); err != nil {
		return a, fmt.Errorf("reading pip's list: %w", err)
	}
	for _, p := range list {
		if normalize(p.Name) == normalize(d.Name) {
			a.Installed, a.Version = true, p.Version
		}
	}
	if d.State == Latest && a.Installed {
		a.Candidate, err = candidate(ctx, r, d, a.Version)
	}
	return a, err
}

// candidate asks pip what an upgrade would install, so a plan and an apply
// choose alike, including which pre-releases and Python versions count. It
// reports nothing to install once the package is as new as pip would go.
func candidate(ctx context.Context, r modules.Runner, d Desired, installed string) (string, error) {
	out, err := d.run(ctx, r, fmt.Sprintf(`"$py" -I -m pip install %s --quiet --dry-run --upgrade --no-deps --report - %s`, pipFlags, ssh.Quote(d.Name)))
	if err != nil {
		return "", fmt.Errorf("asking pip for the newest version (it needs pip 22.2 or later): %w", err)
	}
	var report struct {
		Install []struct {
			Metadata struct{ Version string } `json:"metadata"`
		} `json:"install"`
	}
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		return "", fmt.Errorf("reading pip's report: %w", err)
	}
	if len(report.Install) == 0 {
		return installed, nil
	}
	return report.Install[0].Metadata.Version, nil
}

// Apply makes the host match. Removing never builds a venv; installing builds
// one when it's missing or unusable.
func Apply(ctx context.Context, r modules.Runner, d Desired) error {
	var body string
	switch d.State {
	case Absent:
		body = fmt.Sprintf(`usable || exit 0
"$py" -I -m pip uninstall %s --yes --quiet %s`, pipFlags, ssh.Quote(d.Name))
	default:
		spec, upgrade := d.Name, ""
		if d.Version != "" {
			spec += "==" + d.Version
		}
		if d.State == Latest {
			upgrade = "--upgrade "
		}
		body = fmt.Sprintf(`usable || python3 -I -m venv "$real"
"$py" -I -m pip install %s --quiet %s%s`, pipFlags, upgrade, ssh.Quote(spec))
	}
	_, err := d.run(ctx, r, body)
	return err
}
