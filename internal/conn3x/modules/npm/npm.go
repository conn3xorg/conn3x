// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package npm installs Node.js packages, globally or into one project
// directory, with the host's own npm.
package npm

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
	Global  bool   // in npm's global prefix, for CLIs
	Path    string // the project directory, when not Global
	State   State
	Version string // optional, with Present
}

// Actual describes the package as it is.
type Actual struct {
	Installed bool
	Version   string
	Candidate string // the registry's latest tag, only read for Latest
}

var (
	// A name as the registry accepts it, with an optional scope.
	namePattern = regexp.MustCompile(`^(@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*$`)
	// One semver version. A range or a tag isn't a pin this module can compare.
	versionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$`)
)

// Validate checks a Desired before anything runs on a host.
func (d Desired) Validate() error {
	if !namePattern.MatchString(d.Name) {
		return fmt.Errorf("package name %q must be a plain name, such as pm2 or @angular/cli, with no version, tag, URL or path", d.Name)
	}
	switch {
	case d.Global && d.Path != "":
		return errors.New("path only applies when global is false")
	case !d.Global && d.Path == "":
		return errors.New("set path to the project directory, or global = true")
	case d.Path != "" && (!path.IsAbs(d.Path) || path.Clean(d.Path) != d.Path || d.Path == "/" || strings.ContainsAny(d.Path, "\r\n")):
		return fmt.Errorf("path %q must be a clean absolute path", d.Path)
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
			return fmt.Errorf("version %q must be one exact version, such as 5.4.2", d.Version)
		}
	}
	return nil
}

// NeedsChange says whether the host differs from what is wanted.
func NeedsChange(d Desired, a Actual) bool {
	switch d.State {
	case Absent:
		return a.Installed
	case Latest:
		return !a.Installed || (a.Candidate != "" && a.Candidate != a.Version)
	}
	return !a.Installed || (d.Version != "" && d.Version != a.Version)
}

const npmFlags = "--no-fund --no-audit --no-update-notifier --loglevel=error"

// script runs body with $npm set to npm and its flags. A project install runs
// what the directory holds: its .npmrc picks the registry and the shell for
// scripts, and its package.json's scripts run. So the walk down to path
// decides who runs it: as root, a directory that belongs to a user runs as
// that user, and one anyone can write to is refused. A global install runs
// as whoever is connected.
func (d Desired) script(body string) string {
	s := fmt.Sprintf(`set -e
cd /
npm="npm %s"
command -v npm >/dev/null 2>&1 || { echo "npm is not installed; put a package step for nodejs and npm first" >&2; exit 1; }
`, npmFlags)
	if d.Global {
		return s + "npm=\"$npm --global\"\n" + body
	}
	q := ssh.Quote(d.Path)
	s += fmt.Sprintf(`[ -d %s ] || { echo "path %s is not a directory; make it with a directory step first" >&2; exit 1; }
cd %s
`, q, q, q)
	return modules.Guard(s+body, modules.Whole(d.Path))
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

// Read reports what npm has at the top of the tree, from npm ls. That exits
// 1 for a tree with problems, such as a dependency package.json names but
// node_modules lacks, so the script answers with the JSON either way; a
// dependency without a version is one that isn't there.
func Read(ctx context.Context, r modules.Runner, d Desired) (Actual, error) {
	if err := d.Validate(); err != nil {
		return Actual{}, err
	}
	out, err := d.run(ctx, r, fmt.Sprintf(`$npm ls --json --depth=0 -- %s || true`, ssh.Quote(d.Name)))
	if err != nil {
		return Actual{}, err
	}
	var tree struct {
		Error        *struct{ Summary string } `json:"error"`
		Dependencies map[string]struct {
			Version string `json:"version"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal([]byte(out), &tree); err != nil {
		return Actual{}, fmt.Errorf("reading npm's list: %w", err)
	}
	if tree.Error != nil {
		return Actual{}, fmt.Errorf("npm ls: %s", tree.Error.Summary)
	}
	var a Actual
	if dep, ok := tree.Dependencies[d.Name]; ok && dep.Version != "" {
		a.Installed, a.Version = true, dep.Version
	}
	if d.State == Latest && a.Installed {
		out, err := d.run(ctx, r, fmt.Sprintf(`$npm view -- %s version`, ssh.Quote(d.Name)))
		if err != nil {
			return a, fmt.Errorf("asking the registry for the newest version: %w", err)
		}
		a.Candidate = strings.TrimSpace(out)
	}
	return a, nil
}

// Apply makes the host match.
func Apply(ctx context.Context, r modules.Runner, d Desired) error {
	if err := d.Validate(); err != nil {
		return err
	}
	var body string
	switch d.State {
	case Absent:
		body = fmt.Sprintf(`$npm uninstall -- %s`, ssh.Quote(d.Name))
	default:
		spec := d.Name
		if d.Version != "" {
			spec += "@" + d.Version
		}
		if d.State == Latest {
			spec += "@latest"
		}
		body = fmt.Sprintf(`$npm install -- %s`, ssh.Quote(spec))
	}
	_, err := d.run(ctx, r, body)
	return err
}
