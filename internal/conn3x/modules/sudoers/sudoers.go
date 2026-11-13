// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package sudoers keeps one sudo rule in its own file in /etc/sudoers.d,
// checked with visudo before it replaces anything, so a bad rule never
// stops sudo working for everyone.
package sudoers

import (
	"context"
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/opentofu/opentofu/internal/conn3x/modules"
	"github.com/opentofu/opentofu/internal/conn3x/modules/file"
)

// Dir is where sudo reads drop-in rules.
const Dir = "/etc/sudoers.d"

// Rule is one rule: who may run which commands, as whom.
type Rule struct {
	Name       string
	User       string // set this or Group
	Group      string
	Commands   []string // absolute paths with their arguments, or "ALL"
	RunAs      string   // defaults to "ALL"
	NoPassword bool
	Host       string // defaults to "ALL"
}

var (
	// sudo skips a file in sudoers.d whose name ends in ~ or holds a dot,
	// so such a name would be a rule that silently does nothing.
	nameRe  = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	whoRe   = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$`)
	hostRe  = regexp.MustCompile(`^(ALL|[A-Za-z0-9][A-Za-z0-9.-]{0,252})$`)
	runAsRe = regexp.MustCompile(`^(ALL|[A-Za-z0-9_][A-Za-z0-9_.-]{0,63})(:(ALL|[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}))?$`)
)

// Path is the rule's file.
func (r Rule) Path() string { return path.Join(Dir, r.Name) }

// Validate checks a Rule before anything reaches the host. visudo checks
// the rest on the host.
func (r Rule) Validate() error {
	if !nameRe.MatchString(r.Name) {
		return fmt.Errorf("name %q must be letters, digits, _ and -: sudo skips a file in %s whose name holds a dot or ends in ~", r.Name, Dir)
	}
	switch {
	case (r.User == "") == (r.Group == ""):
		return fmt.Errorf("set one of user and group")
	case r.User != "" && !whoRe.MatchString(r.User):
		return fmt.Errorf("user %q must be a user name", r.User)
	case r.Group != "" && !whoRe.MatchString(r.Group):
		return fmt.Errorf("group %q must be a group name", r.Group)
	}
	if len(r.Commands) == 0 {
		return fmt.Errorf("commands must name at least one command, or \"ALL\"")
	}
	for _, c := range r.Commands {
		if strings.ContainsAny(c, "\n\r\x00#") {
			return fmt.Errorf("commands %q can't hold a line break or #", c)
		}
		if c != "ALL" && !strings.HasPrefix(c, "/") {
			return fmt.Errorf("commands %q must start with the command's absolute path, such as /usr/bin/systemctl, or be \"ALL\"", c)
		}
	}
	if r.RunAs != "" && !runAsRe.MatchString(r.RunAs) {
		return fmt.Errorf("runas %q must be a user, or user:group, or ALL", r.RunAs)
	}
	if r.Host != "" && !hostRe.MatchString(r.Host) {
		return fmt.Errorf("host %q must be a host name or ALL", r.Host)
	}
	return nil
}

// escape protects the characters sudoers reads specially inside a command.
func escape(c string) string {
	return strings.NewReplacer(`\`, `\\`, `,`, `\,`, `:`, `\:`, `=`, `\=`).Replace(c)
}

// Content is the file as Conn3x writes it.
func (r Rule) Content() string {
	who := r.User
	if r.Group != "" {
		who = "%" + r.Group
	}
	host, runas := r.Host, r.RunAs
	if host == "" {
		host = "ALL"
	}
	if runas == "" {
		runas = "ALL"
	}
	tag := ""
	if r.NoPassword {
		tag = "NOPASSWD: "
	}
	cmds := make([]string, len(r.Commands))
	for i, c := range r.Commands {
		cmds[i] = escape(c)
	}
	return fmt.Sprintf("# Written by Conn3x; changes here are put back on the next apply.\n%s %s=(%s) %s%s\n", who, host, runas, tag, strings.Join(cmds, ", "))
}

// Desired is the file write, checked by visudo first.
func (r Rule) Desired() file.Desired {
	return file.Desired{Path: r.Path(), Content: r.Content(), Mode: "0440", Owner: "root", Group: "root", ValidateCommand: "visudo -cf %s"}
}

// Read reads the rule's file.
func Read(ctx context.Context, h modules.Runner, r Rule) (file.Actual, error) {
	return file.Read(ctx, h, r.Path())
}

// InSync reports whether the file holds the rule, with sudo's mode.
func (r Rule) InSync(a file.Actual) bool {
	return a.Exists && a.Content == r.Content() && a.Mode == "0440" && a.Owner == "root"
}

// Apply writes the rule, which visudo checks before it replaces the file.
func Apply(ctx context.Context, h modules.Runner, r Rule) error {
	if err := r.Validate(); err != nil {
		return err
	}
	return file.Apply(ctx, h, r.Desired())
}
