// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package alternatives picks which of several programs a generic name runs,
// with update-alternatives on the Debian family and alternatives on the Red
// Hat family.
package alternatives

import (
	"context"
	"errors"
	"fmt"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/opentofu/opentofu/internal/conn3x/modules"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// DefaultPriority is given to a path Conn3x registers when none is set, as
// Ansible's alternatives module does.
const DefaultPriority = "50"

// Alternative is one choice for a generic name, such as /usr/bin/vim.basic
// for editor.
type Alternative struct {
	Name, Path string
	Link       string // the generic link, such as /usr/bin/editor; needed to register a new name
	Priority   string // a whole number, or "" for DefaultPriority
}

var altName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]*$`)

// Validate checks an Alternative before anything reaches the host.
func (a Alternative) Validate() error {
	if !altName.MatchString(a.Name) {
		return fmt.Errorf("name %q must be letters, digits, ., _, + or -, such as editor or python3", a.Name)
	}
	if err := checkPath("path", a.Path); err != nil {
		return err
	}
	if a.Link != "" {
		if err := checkPath("link", a.Link); err != nil {
			return err
		}
	}
	if a.Priority != "" {
		if _, err := strconv.Atoi(a.Priority); err != nil {
			return fmt.Errorf("priority %q must be a whole number", a.Priority)
		}
	}
	return nil
}

func checkPath(attr, p string) error {
	if !path.IsAbs(p) || path.Clean(p) != p || p == "/" || strings.ContainsAny(p, " \t\r\n") {
		return fmt.Errorf("%s %q must be a clean absolute path without spaces", attr, p)
	}
	return nil
}

// Actual is what the host has for a name.
type Actual struct {
	Registered bool              // the name is known to the tool
	Current    string            // what the name points to now
	Link       string            // the generic link, where the tool prints it; the Red Hat family doesn't
	Priority   map[string]string // each registered path's priority
}

// InSync reports whether the name points to Path, registered with Priority
// when one is set.
func (a Alternative) InSync(act Actual) bool {
	return act.Current == a.Path && (a.Priority == "" || act.Priority[a.Path] == a.Priority)
}

// findTool names the command: update-alternatives on both families, since
// the Red Hat family's chkconfig ships it beside alternatives.
const findTool = `cmd=$(command -v update-alternatives || command -v alternatives) || { echo "neither update-alternatives nor alternatives is on this host" >&2; exit 1; }
`

var (
	currentLine  = regexp.MustCompile(`(?m)^\s*link currently points to (\S+)$`)
	linkLine     = regexp.MustCompile(`(?m)^\s*link \S+ is (\S+)$`)
	priorityLine = regexp.MustCompile(`(?m)^(/\S+) - priority (-?\d+)$`)
)

// Read returns what the host has for a.Name.
func Read(ctx context.Context, r modules.Runner, a Alternative) (Actual, error) {
	res, err := r.Run(ctx, findTool+`"$cmd" --display `+ssh.Quote(a.Name), nil)
	if err != nil {
		return Actual{}, err
	}
	stderr := strings.TrimSpace(string(res.Stderr))
	if res.ExitCode != 0 {
		// Debian says "no alternatives for NAME"; the Red Hat family says
		// nothing. Both exit 2 for every error, so the message is the tell.
		if stderr == "" || strings.Contains(stderr, "no alternatives for") {
			return Actual{}, nil
		}
		return Actual{}, errors.New(stderr)
	}
	return parseDisplay(string(res.Stdout)), nil
}

// parseDisplay reads --display output, which both tools print in the same
// shape apart from the mode line and Debian's extra link line.
func parseDisplay(out string) Actual {
	act := Actual{Registered: true, Priority: map[string]string{}}
	if m := currentLine.FindStringSubmatch(out); m != nil {
		act.Current = m[1]
	}
	if m := linkLine.FindStringSubmatch(out); m != nil {
		act.Link = m[1]
	}
	for _, m := range priorityLine.FindAllStringSubmatch(out, -1) {
		act.Priority[m[1]] = m[2]
	}
	return act
}

// Apply registers Path when it isn't, or has another priority, and points
// Name at it. Setting it by hand puts the name in manual mode, so a package
// installed later with a higher priority doesn't take it over.
func Apply(ctx context.Context, r modules.Runner, a Alternative) error {
	if err := a.Validate(); err != nil {
		return err
	}
	act, err := Read(ctx, r, a)
	if err != nil {
		return err
	}
	script := "set -e\n" + findTool
	if prio, ok := act.Priority[a.Path]; !ok || (a.Priority != "" && prio != a.Priority) {
		link := a.Link
		if link == "" {
			link = act.Link
		}
		if link == "" {
			return fmt.Errorf("registering %s for %s needs link, such as /usr/bin/%s, since this host's tool doesn't say where the link is", a.Path, a.Name, a.Name)
		}
		if prio = a.Priority; prio == "" {
			prio = DefaultPriority
		}
		script += fmt.Sprintf(`"$cmd" --install %s %s %s %s`+"\n", ssh.Quote(link), ssh.Quote(a.Name), ssh.Quote(a.Path), prio)
	}
	if act.Current != a.Path {
		script += fmt.Sprintf(`"$cmd" --set %s %s`+"\n", ssh.Quote(a.Name), ssh.Quote(a.Path))
	}
	return check(r.Run(ctx, script, nil))
}

// Delete removes Path from Name's choices. The tool picks the next best, or
// drops the name when it was the last one.
func Delete(ctx context.Context, r modules.Runner, a Alternative) error {
	act, err := Read(ctx, r, a)
	if err != nil {
		return err
	}
	if _, ok := act.Priority[a.Path]; !ok {
		return nil
	}
	return check(r.Run(ctx, findTool+fmt.Sprintf(`"$cmd" --remove %s %s`, ssh.Quote(a.Name), ssh.Quote(a.Path)), nil))
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
