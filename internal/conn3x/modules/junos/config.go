// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package junos

import (
	"errors"
	"fmt"
	"regexp"
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

// Config is a set of statements, the way junos_config owns them: each one a
// set line as display set prints it.
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
		if err := checkText(c.Prefix, "prefix"); err != nil {
			return err
		}
	} else if len(c.Lines) == 0 {
		return errors.New("lines must not be empty")
	}
	for _, l := range c.Lines {
		if err := CheckLine(l); err != nil {
			return err
		}
		if c.Match == MatchBlock && !under(l, c.Prefix) {
			return fmt.Errorf("line %q isn't under prefix %q; in block mode every line starts with \"set %s\"", l, c.Prefix, c.Prefix)
		}
	}
	return nil
}

// under reports whether a set line is at or below prefix.
func under(line, prefix string) bool {
	rest, ok := strings.CutPrefix(line, "set "+prefix)
	return ok && (rest == "" || rest[0] == ' ')
}

// CheckLine refuses anything but one set statement: every line is typed
// into the CLI as it is, so a line that isn't a set statement could leave
// configuration mode, commit early or run an operational command.
func CheckLine(l string) error {
	if err := checkText(l, "line"); err != nil {
		return err
	}
	if !strings.HasPrefix(l, "set ") || len(strings.Fields(l)) < 2 {
		return fmt.Errorf("line %q must be a set statement, as show configuration | display set prints it, such as \"set system host-name sw1\"", l)
	}
	if pipeOutsideQuotes(l) {
		return fmt.Errorf("line %q has a | outside quotes, which the CLI would read as a pipe; quote the value", l)
	}
	if slices.Contains(strings.Fields(l), "plain-text-password") {
		return fmt.Errorf("line %q would prompt for a password, which a script can't answer (Junos says \"error: Invalid password\"); set encrypted-password with a hash instead", l)
	}
	return nil
}

func checkText(s, what string) error {
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

// InSync reports whether config, as display set prints it, has what c wants.
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
			if under(h, c.Prefix) && !slices.Contains(c.Lines, h) && !coveredBy(h, c.Lines) {
				cmds = append(cmds, deleteOf(h))
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

// coveredBy reports whether line h is a prefix of a wanted line: display set
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
			cmds = append(cmds, deleteOf(l))
		}
	}
	return cmds
}

// deleteOf is the delete statement for a set line.
func deleteOf(line string) string {
	return "delete " + strings.TrimPrefix(line, "set ")
}

var hostnameRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,62}[A-Za-z0-9])?$`)

// ValidateHostname checks a name Junos takes as it is, without quotes.
func ValidateHostname(name string) error {
	if !hostnameRe.MatchString(name) {
		return fmt.Errorf("hostname %q must be letters, digits, hyphens and dots, starting and ending with a letter or digit, at most 64 characters", name)
	}
	return nil
}

// Hostname is the device's name as one statement.
func Hostname(name string) Config {
	return Config{Lines: []string{"set system host-name " + name}, Match: MatchLines}
}

// VLAN is one VLAN on an ELS switch, keyed by name as Junos keys them.
type VLAN struct {
	Name string
	ID   int
}

var vlanNameRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]{0,63}$`)

// Validate checks the name and ID.
func (v VLAN) Validate() error {
	if !vlanNameRe.MatchString(v.Name) {
		return fmt.Errorf("name %q must start with a letter and be letters, digits, hyphens, underscores and dots, at most 64 characters", v.Name)
	}
	if v.ID < 1 || v.ID > 4094 {
		return fmt.Errorf("vlan_id must be between 1 and 4094, not %d", v.ID)
	}
	return nil
}

// Config owns the VLAN's ID only, so interfaces and descriptions set on it
// elsewhere are left alone.
func (v VLAN) Config() Config {
	return Config{Lines: []string{fmt.Sprintf("set vlans %s vlan-id %d", v.Name, v.ID)}, Match: MatchLines}
}

// InSync reports whether the VLAN is there with this ID.
func (v VLAN) InSync(config string) bool { return v.Config().InSync(config) }

// Commands are what makes config have the VLAN, or nil.
func (v VLAN) Commands(config string) []string { return v.Config().Commands(config) }

// RemoveCommands delete the whole VLAN, when it's there.
func (v VLAN) RemoveCommands(config string) []string {
	if !slices.ContainsFunc(SetLines(config), func(l string) bool { return under(l, "vlans "+v.Name) }) {
		return nil
	}
	return []string{"delete vlans " + v.Name}
}
