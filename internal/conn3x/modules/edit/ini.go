// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package edit

import (
	"errors"
	"fmt"
	"strings"
)

// INI is one option that should, or should not, be in an INI-style file.
type INI struct {
	Section       string // empty means before the first section
	Option        string
	Value         string
	State         State // default Present
	NoExtraSpaces bool  // write option=value rather than option = value
	Uncomment     bool  // put the value on a commented-out line for the option
}

// Validate checks an INI edit before anything is edited.
func (c INI) Validate() error {
	switch c.State {
	case "", Present, Absent:
	default:
		return fmt.Errorf("state must be %q or %q, not %q", Present, Absent, c.State)
	}
	if c.Option == "" {
		return errors.New("option is required")
	}
	if c.Option != strings.TrimSpace(c.Option) || strings.ContainsAny(c.Option, "=\n") || strings.ContainsAny(c.Option[:1], "#;[") {
		return fmt.Errorf("option %q can't be an option name: it has an = or a line break, spaces at either end, or starts like a comment or a section", c.Option)
	}
	if strings.ContainsAny(c.Section, "]\n") {
		return fmt.Errorf("section %q can't have a ] or a line break", c.Section)
	}
	if strings.Contains(c.Value, "\n") {
		return errors.New("value must be a single line")
	}
	return nil
}

// ApplyINI returns content with the option set or removed. Only lines for
// the option change, and only in the first section of that name. The file
// ends with a newline afterwards, and a byte order mark goes when the file
// changes.
func ApplyINI(content string, c INI) (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	body := strings.TrimPrefix(content, "\xef\xbb\xbf")
	lines, _ := split(body)
	eol := ""
	if len(lines) > 0 && strings.HasSuffix(lines[0], "\r") {
		eol = "\r"
	}
	sep := " = "
	if c.NoExtraSpaces {
		sep = "="
	}
	want := c.Option + sep + c.Value + eol

	start, end := -1, len(lines)
	if c.Section == "" {
		start = 0
	}
	for i, l := range lines {
		name, ok := sectionName(l)
		if !ok {
			continue
		}
		if start >= 0 {
			end = i
			break
		}
		if name == c.Section {
			start = i + 1
		}
	}

	var out []string
	switch {
	case start >= 0:
		out = append(out, lines[:start]...)
		found := false
		at := start // a new option goes after the section's last setting
		for _, l := range lines[start:end] {
			if c.isOption(l) || (c.Uncomment && c.State != Absent && c.isCommented(l)) {
				if c.State != Absent && !found {
					found = true
					out = append(out, want)
					at = len(out)
				}
				continue
			}
			out = append(out, l)
			if t := strings.TrimSpace(l); t != "" && t[0] != '#' && t[0] != ';' {
				at = len(out)
			}
		}
		if !found && c.State != Absent {
			out = append(out[:at:at], append([]string{want}, out[at:]...)...)
		}
		out = append(out, lines[end:]...)
	case c.State == Absent:
		out = lines
	default:
		out = append(append(out, lines...), "["+c.Section+"]"+eol, want)
	}

	edited := join(out, true)
	if edited == body {
		return content, nil
	}
	return edited, nil
}

// sectionName reads a section header. It has to start the line.
func sectionName(line string) (string, bool) {
	if !strings.HasPrefix(line, "[") {
		return "", false
	}
	name, _, ok := strings.Cut(line[1:], "]")
	return name, ok
}

func (c INI) isOption(line string) bool {
	name, _, _ := strings.Cut(strings.TrimSpace(line), "=")
	return strings.TrimSpace(name) == c.Option
}

func (c INI) isCommented(line string) bool {
	t := strings.TrimSpace(line)
	if t == "" || (t[0] != '#' && t[0] != ';') {
		return false
	}
	name, _, ok := strings.Cut(t[1:], "=")
	return ok && strings.TrimSpace(name) == c.Option
}
