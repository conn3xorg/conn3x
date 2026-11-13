// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package setcfg is configuration as set statements, the model Junos and
// VyOS share: a device's configuration printed as "set ..." lines, steps
// that own some of them, and the set and delete commands that bring the
// device in line. Each platform reads its device into this form first.
package setcfg

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode"
)

// SetLines picks the set statements out of show configuration | display
// set. Junos prints a deactivated statement as its set line followed by a
// deactivate line; those are left out, so a step owning a deactivated
// statement is never in sync.
func SetLines(config string) []string {
	var lines, inactive []string
	for _, raw := range strings.Split(config, "\n") {
		line := strings.TrimRight(raw, " \r")
		switch {
		case strings.HasPrefix(line, "set "):
			lines = append(lines, line)
		case strings.HasPrefix(line, "deactivate "):
			inactive = append(inactive, "set "+strings.TrimPrefix(line, "deactivate "))
		}
	}
	return slices.DeleteFunc(lines, func(l string) bool {
		return slices.ContainsFunc(inactive, func(p string) bool { return l == p || strings.HasPrefix(l, p+" ") })
	})
}

// Match modes for a Config.
const (
	MatchLines = "lines" // these lines must be there; others are left alone
	MatchBlock = "block" // the lines under prefix must be exactly these
)

// Config is a set of statements, the way junos_config and vyos_config own
// them: each one a set line as the device prints it.
type Config struct {
	Prefix string // block mode: the hierarchy the lines own, such as "interfaces ge-0/0/1"
	Lines  []string
	Match  string
}

// Validate checks a Config before anything reaches the device.
func (c Config) Validate() error {
	if c.Match != "" && c.Match != MatchLines && c.Match != MatchBlock {
		return fmt.Errorf("match must be %q or %q", MatchLines, MatchBlock)
	}
	if c.Match == MatchBlock {
		if c.Prefix == "" {
			return errors.New(`match = "block" needs prefix: owning the whole configuration would delete every other statement`)
		}
		if err := CheckText(c.Prefix, "prefix"); err != nil {
			return err
		}
	} else if len(c.Lines) == 0 {
		return errors.New("lines must not be empty")
	}
	for _, l := range c.Lines {
		if err := CheckLine(l); err != nil {
			return err
		}
		if c.Match == MatchBlock && !Under(l, c.Prefix) {
			return fmt.Errorf("line %q isn't under prefix %q; in block mode every line starts with \"set %s\"", l, c.Prefix, c.Prefix)
		}
	}
	return nil
}

// Under reports whether a set line is at or below prefix.
func Under(line, prefix string) bool {
	rest, ok := strings.CutPrefix(line, "set "+prefix)
	return ok && (rest == "" || rest[0] == ' ')
}

// CheckLine refuses anything but one set statement: every line is typed
// into the CLI as it is, so a line that isn't a set statement could leave
// configuration mode, commit early or run an operational command.
func CheckLine(l string) error {
	if err := CheckText(l, "line"); err != nil {
		return err
	}
	if !strings.HasPrefix(l, "set ") || len(strings.Fields(l)) < 2 {
		return fmt.Errorf("line %q must be a set statement, as the device prints its configuration as set commands, such as \"set system host-name sw1\"", l)
	}
	if pipeOutsideQuotes(l) {
		return fmt.Errorf("line %q has a | outside quotes, which the CLI would read as a pipe; quote the value", l)
	}
	if slices.Contains(strings.Fields(l), "plain-text-password") {
		return fmt.Errorf("line %q would prompt for a password, which a script can't answer (Junos says \"error: Invalid password\"); set the device's hashed form instead", l)
	}
	return nil
}

func CheckText(s, what string) error {
	t := strings.TrimSpace(s)
	switch {
	case t == "":
		return fmt.Errorf("%s must not be empty", what)
	case strings.ContainsFunc(s, unicode.IsControl):
		return fmt.Errorf("%s %q holds a newline or another control character; write it on one line, with printable characters and spaces only", what, s)
	case t != s:
		return fmt.Errorf("%s %q has leading or trailing spaces", what, s)
	case strings.HasPrefix(t, "#"):
		return fmt.Errorf("%s %q is a comment; leave it out", what, s)
	}
	return nil
}

func pipeOutsideQuotes(s string) bool {
	quoted := false
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '\\' && quoted:
			i++
		case s[i] == '"':
			quoted = !quoted
		case s[i] == '|' && !quoted:
			return true
		}
	}
	return false
}

// InSync reports whether config, as set lines, has what c wants.
func (c Config) InSync(config string) bool {
	return c.Commands(config) == nil
}

// Commands are what to type in configuration mode to bring config in line:
// in block mode, delete the extras under the prefix, then set what's
// missing. Nil when nothing needs to change.
func (c Config) Commands(config string) []string {
	have := SetLines(config)
	var cmds []string
	if c.Match == MatchBlock {
		for _, h := range have {
			if Under(h, c.Prefix) && !slices.Contains(c.Lines, h) && !coveredBy(h, c.Lines) {
				cmds = append(cmds, DeleteOf(h))
			}
		}
	}
	for _, w := range c.Lines {
		if !slices.Contains(have, w) {
			cmds = append(cmds, w)
		}
	}
	return cmds
}

// coveredBy reports whether line h is a prefix of a wanted line: Junos
// prints "set interfaces ge-0/0/1 unit 0" and the wanted "set interfaces
// ge-0/0/1 unit 0 family inet" both, and deleting the first would take the
// second with it.
func coveredBy(h string, want []string) bool {
	return slices.ContainsFunc(want, func(w string) bool { return strings.HasPrefix(w, h+" ") })
}

// RemoveCommands delete the lines c owns that config still has. Nil when
// none are left.
func (c Config) RemoveCommands(config string) []string {
	have := SetLines(config)
	var cmds []string
	for _, l := range c.Lines {
		if slices.Contains(have, l) {
			cmds = append(cmds, DeleteOf(l))
		}
	}
	return cmds
}

// DeleteOf is the delete statement for a set line.
func DeleteOf(line string) string {
	return "delete " + strings.TrimPrefix(line, "set ")
}

// Leaf is one single-valued statement: the device holds one value at Path.
type Leaf struct{ Path, Value string }

func (l Leaf) want() string { return "set " + l.Path + " " + l.Value }

// InSync reports whether config holds the leaf with this value.
func (l Leaf) InSync(config string) bool { return l.Commands(config) == nil }

// Commands set the leaf, deleting another value first so WithLines shows
// the next step only this one. Nil when it already holds this value.
func (l Leaf) Commands(config string) []string {
	got := HaveLeaf(SetLines(config), l.Path)
	switch {
	case got == l.want():
		return nil
	case got != "":
		return []string{"delete " + l.Path, l.want()}
	}
	return []string{l.want()}
}

// WithLines is config, as set lines, with cmds applied: what
// the device will hold once they commit, for the next step of the same
// commit to compare with. A delete takes the statements at and below it.
//
// It can't tell a leaf from a list, so a set on a leaf keeps the old
// value's line beside the new one; steps that own a leaf delete it before
// setting another value (see Leaf), which keeps the view exact.
func WithLines(config string, cmds []string) string {
	lines := SetLines(config)
	for _, c := range cmds {
		if rest, ok := strings.CutPrefix(c, "delete "); ok {
			lines = slices.DeleteFunc(lines, func(l string) bool { return Under(l, rest) })
		} else if !slices.Contains(lines, c) {
			lines = append(lines, c)
		}
	}
	return strings.Join(lines, "\n") + "\n"
}

// HaveLeaf is the set line at path in lines, or "".
func HaveLeaf(lines []string, path string) string {
	for _, l := range lines {
		if Under(l, path) {
			return l
		}
	}
	return ""
}
