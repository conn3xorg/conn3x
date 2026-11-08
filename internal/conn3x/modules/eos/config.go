// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package eos

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// node is one line of a running-config and the lines indented under it.
type node struct {
	text string
	kids []*node
}

// parse reads a running-config as EOS prints it, each level indented
// further than its parent, into a tree. "!" lines only separate blocks.
func parse(config string) *node {
	root := &node{}
	type open struct {
		n      *node
		indent int
	}
	stack := []open{{root, -1}}
	for _, raw := range strings.Split(config, "\n") {
		line := strings.TrimRight(raw, " \r")
		text := strings.TrimLeft(line, " ")
		if text == "" || strings.HasPrefix(text, "!") {
			continue
		}
		indent := len(line) - len(text)
		for stack[len(stack)-1].indent >= indent {
			stack = stack[:len(stack)-1]
		}
		n := &node{text: text}
		top := stack[len(stack)-1].n
		top.kids = append(top.kids, n)
		stack = append(stack, open{n, indent})
	}
	return root
}

// Section returns the lines directly under the block that parents name in a
// running-config. With no parents it is the top level. found is false when a
// parent isn't there.
func Section(config string, parents []string) (lines []string, found bool) {
	cur := parse(config)
outer:
	for _, p := range parents {
		for _, k := range cur.kids {
			if k.text == p {
				cur = k
				continue outer
			}
		}
		return nil, false
	}
	for _, k := range cur.kids {
		lines = append(lines, k.text)
	}
	return lines, true
}

// Diff compares the lines wanted under a block with what is there: missing
// lines have to be added, and in block mode extra lines have to go.
func Diff(have, want []string) (missing, extra []string) {
	for _, w := range want {
		if !slices.Contains(have, w) {
			missing = append(missing, w)
		}
	}
	for _, h := range have {
		if !slices.Contains(want, h) {
			extra = append(extra, h)
		}
	}
	return missing, extra
}

// Match modes for a Config.
const (
	MatchLines = "lines" // these lines must be there; others are left alone
	MatchBlock = "block" // the block must be exactly these lines
)

// Config is a set of lines under a parent block, the way eos_config owns them.
type Config struct {
	Parents []string
	Lines   []string
	Match   string
}

// Validate checks a Config before anything reaches the device.
func (c Config) Validate() error {
	if len(c.Lines) == 0 && c.Match != MatchBlock {
		return errors.New("lines must not be empty")
	}
	if c.Match != "" && c.Match != MatchLines && c.Match != MatchBlock {
		return fmt.Errorf("match must be %q or %q", MatchLines, MatchBlock)
	}
	if c.Match == MatchBlock && len(c.Parents) == 0 {
		return errors.New(`match = "block" needs parents: owning the whole top level would remove every other line of the config`)
	}
	for _, l := range append(slices.Clone(c.Parents), c.Lines...) {
		if err := checkLine(l); err != nil {
			return err
		}
	}
	return nil
}

// checkLine refuses what would change mode or end the session early: a
// line is sent to the device as typed.
func checkLine(l string) error {
	t := strings.TrimSpace(l)
	switch {
	case t == "":
		return errors.New("lines and parents must not be empty strings")
	case t != l:
		return fmt.Errorf("line %q has leading or trailing spaces; write it the way show running-config prints it, without the indent", l)
	case strings.ContainsAny(l, "\r\n"):
		return fmt.Errorf("line %q must be a single line", l)
	case strings.HasPrefix(t, "!"):
		return fmt.Errorf("line %q is a comment; leave it out", l)
	}
	switch strings.Fields(strings.ToLower(t))[0] {
	case "end", "exit", "abort", "commit", "configure", "copy", "write", "reload", "bash", "enable", "disable":
		return fmt.Errorf("line %q would leave or end the config session; Conn3x opens, commits and saves the session itself", l)
	}
	return nil
}

// InSync reports whether config has what c wants.
func (c Config) InSync(config string) bool {
	have, found := Section(config, c.Parents)
	if !found {
		return false
	}
	missing, extra := Diff(have, c.Lines)
	return len(missing) == 0 && (c.Match != MatchBlock || len(extra) == 0)
}

// Commands are what to type in a config session to bring config in line:
// enter each parent, remove the extras in block mode, then add what's
// missing. Nil when nothing needs to change.
func (c Config) Commands(config string) []string {
	have, found := Section(config, c.Parents)
	missing, extra := Diff(have, c.Lines)
	if c.Match != MatchBlock {
		extra = nil
	}
	if found && len(missing) == 0 && len(extra) == 0 {
		return nil
	}
	cmds := slices.Clone(c.Parents)
	for _, e := range extra {
		cmds = append(cmds, negate(e))
	}
	return append(cmds, missing...)
}

// RemoveCommands take out the lines c owns that config still has, leaving
// the parents and everything else. Nil when none are left.
func (c Config) RemoveCommands(config string) []string {
	have, _ := Section(config, c.Parents)
	var cmds []string
	for _, l := range c.Lines {
		if slices.Contains(have, l) {
			cmds = append(cmds, negate(l))
		}
	}
	if cmds == nil {
		return nil
	}
	return append(slices.Clone(c.Parents), cmds...)
}

// VLAN is one VLAN in the VLAN database, with an optional name.
type VLAN struct {
	ID   int
	Name string
}

// Validate checks the ID and name.
func (v VLAN) Validate() error {
	if v.ID < 1 || v.ID > 4094 {
		return fmt.Errorf("vlan_id must be between 1 and 4094, not %d", v.ID)
	}
	if strings.ContainsAny(v.Name, " \t\r\n") || len(v.Name) > 32 {
		return errors.New("name must be one word of at most 32 characters")
	}
	return nil
}

// Config is the VLAN as running-config shows it: "vlan 10", with "name x"
// under it when there is one. Block mode, so a name set by hand goes when
// this VLAN has none.
func (v VLAN) Config() Config {
	c := Config{Parents: []string{fmt.Sprintf("vlan %d", v.ID)}, Match: MatchBlock}
	if v.Name != "" {
		c.Lines = []string{"name " + v.Name}
	}
	return c
}

// exists reports whether config has the VLAN, and whether it has a block of
// its own. EOS prints VLANs with nothing set under them together on one
// line, as in "vlan 10,20-22", and a VLAN with a name as its own block.
func (v VLAN) exists(config string) (found, own bool) {
	if _, ok := Section(config, v.Config().Parents); ok {
		return true, true
	}
	for _, k := range parse(config).kids {
		if list, ok := strings.CutPrefix(k.text, "vlan "); ok && len(k.kids) == 0 && inVLANList(list, v.ID) {
			return true, false
		}
	}
	return false, false
}

// inVLANList reports whether a list such as 10,20-22 holds id.
func inVLANList(list string, id int) bool {
	for _, part := range strings.Split(list, ",") {
		lo, hi, isRange := strings.Cut(part, "-")
		a, errA := strconv.Atoi(lo)
		b, errB := a, error(nil)
		if isRange {
			b, errB = strconv.Atoi(hi)
		}
		if errA == nil && errB == nil && a <= id && id <= b {
			return true
		}
	}
	return false
}

// InSync reports whether config has the VLAN with this name, or with none.
func (v VLAN) InSync(config string) bool {
	found, own := v.exists(config)
	if !own {
		return found && v.Name == ""
	}
	return v.Config().InSync(config)
}

// Commands are what makes config have the VLAN as v wants it, or nil.
func (v VLAN) Commands(config string) []string {
	if v.InSync(config) {
		return nil
	}
	return v.Config().Commands(config)
}

// RemoveCommands delete the VLAN, when it's there.
func (v VLAN) RemoveCommands(config string) []string {
	if found, _ := v.exists(config); !found {
		return nil
	}
	return []string{fmt.Sprintf("no vlan %d", v.ID)}
}

var hostnameRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,62}[A-Za-z0-9])?$`)

// ValidateHostname checks a name EOS will take as it is.
func ValidateHostname(name string) error {
	if !hostnameRe.MatchString(name) {
		return fmt.Errorf("hostname %q must be letters, digits, hyphens and dots, starting and ending with a letter or digit, at most 64 characters", name)
	}
	return nil
}

// Hostname is the switch's name as one top-level line.
func Hostname(name string) Config {
	return Config{Lines: []string{"hostname " + name}, Match: MatchLines}
}

// negate is the command that removes a line: "no x", or "x" for a line that
// is itself a "no" form, such as "no shutdown" (EOS's "default" would also
// do, but "x" is what show running-config then prints back, or nothing).
func negate(line string) string {
	if rest, ok := strings.CutPrefix(line, "no "); ok {
		return rest
	}
	return "no " + line
}
