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

// Config is a set of statements, the way junos_config and vyos_config own
// them: each one a set line as the device prints it.
type Config struct {
	Prefix string // block mode: the hierarchy the lines own, such as "interfaces ge-0/0/1"
	Lines  []string
	Match  string
	// Secrets are set lines whose last word is a secret, known only at
	// apply. A device prints most of them hashed or encrypted, so each is
	// matched by its path, the line without that word, which state keeps
	// in Paths.
	Secrets []string
	Paths   []string
	// Resend sets every secret again, as when one of them changed: the
	// device can't show which secret it holds.
	Resend bool
}

// secretKeyword is the word before a secret value: password, secret,
// encrypted-password, pre-shared-secret, authentication-key, key, and the
// Junos ascii-text and hexadecimal of a pre-shared-key.
var secretKeyword = regexp.MustCompile(`(?i)^([\w-]*(password|secret|passphrase|key)|ascii-text|hexadecimal)$`)

// SecretPath is a secret line without its secret: "set protocols bgp
// neighbor 192.0.2.1 password" for "set protocols bgp neighbor 192.0.2.1
// password 'x'". An error when the last word isn't a secret's value.
// Errors never quote the line.
func SecretPath(line string) (string, error) {
	words, closed := secretWords(line)
	if !closed {
		return "", errors.New("a line in lines_wo has an unclosed quote")
	}
	if len(words) < 3 || words[0] != "set" || !secretKeyword.MatchString(words[len(words)-2]) {
		return "", errors.New("a line in lines_wo must end with a secret after its keyword, such as password, secret or key; put other lines in lines")
	}
	switch kw := strings.ToLower(words[len(words)-2]); {
	case kw == "plaintext-password" || kw == "plain-text-password":
		return "", errors.New("a line in lines_wo sets a plain-text password, which the device stores hashed under another name, so it would never show as there; set the hashed form (encrypted-password) instead, or use the platform's user step")
	case slices.Contains(words, "community"):
		return "", errors.New("lines_wo can't hold an SNMP community: its name is its secret, so a path can't tell one community from another; use an SNMPv3 user")
	}
	path := strings.Join(words[:len(words)-1], " ")
	// No set path holds a quote; one here means the secret was split, and
	// part of it would land in state.
	if strings.ContainsAny(path, `'"`) {
		return "", errors.New("a line in lines_wo couldn't be split into a path and its secret; quote the secret as one value, in double or single quotes")
	}
	return path, nil
}

// secretWords splits a statement at spaces outside quotes, single or
// double, as VyOS takes both. splitWords, which deletes use, keeps to
// double quotes, since Junos reads an apostrophe as part of a word.
func secretWords(s string) (_ []string, closed bool) {
	var words []string
	quote, start := byte(0), 0
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case quote == '"' && c == '\\':
			i++
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == ' ':
			if i > start {
				words = append(words, s[start:i])
			}
			start = i + 1
		}
	}
	if start < len(s) {
		words = append(words, s[start:])
	}
	return words, quote == 0
}

// secretLine reports whether have is a line one of the paths owns.
func (c Config) secretLine(have string) bool {
	return slices.ContainsFunc(c.Paths, func(p string) bool { return strings.HasPrefix(have, p+" ") })
}

// present reports whether have holds a line at path.
func present(have []string, path string) bool {
	return slices.ContainsFunc(have, func(h string) bool { return strings.HasPrefix(h, path+" ") })
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
	} else if len(c.Lines) == 0 && len(c.Secrets) == 0 {
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
	seen := map[string]bool{}
	for _, l := range c.Secrets {
		if CheckLine(l) != nil {
			return errors.New("a line in lines_wo isn't one set statement on one line, with any | inside quotes")
		}
		p, err := SecretPath(l)
		if err != nil {
			return err
		}
		if c.Match == MatchBlock && !Under(l, c.Prefix) {
			return fmt.Errorf("a line in lines_wo isn't under prefix %q; in block mode every line starts with \"set %s\"", c.Prefix, c.Prefix)
		}
		if seen[p] {
			return fmt.Errorf("two lines in lines_wo set %q; give each secret its own path", p)
		}
		seen[p] = true
		for _, plain := range c.Lines {
			if strings.HasPrefix(plain, p+" ") {
				return fmt.Errorf("line %q in lines sets %q, which a line in lines_wo owns; take it out of one of them", plain, p)
			}
		}
	}
	return nil
}

// LooksSecret reports whether a line in lines ends with a secret, which
// state would then keep.
func LooksSecret(line string) bool {
	words := splitWords(line)
	return len(words) >= 3 && secretKeyword.MatchString(words[len(words)-2])
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
	have := SetLines(config)
	return c.Commands(config) == nil && !slices.ContainsFunc(c.Paths, func(p string) bool { return !present(have, p) })
}

// Commands are what to type in configuration mode to bring config in line:
// in block mode, delete the extras under the prefix, then set what's
// missing. Nil when nothing needs to change.
func (c Config) Commands(config string) []string {
	have := SetLines(config)
	var cmds []string
	if c.Match == MatchBlock {
		for _, h := range have {
			if Under(h, c.Prefix) && !slices.Contains(c.Lines, h) && !coveredBy(h, c.Lines) && !c.secretLine(h) && !coveredBy(h, c.Paths) {
				if d := c.deleteFor(h); !slices.Contains(cmds, d) {
					cmds = append(cmds, d)
				}
			}
		}
	}
	for _, w := range c.Lines {
		if !slices.Contains(have, w) {
			cmds = append(cmds, w)
		}
	}
	for _, l := range c.Secrets {
		p, _ := SecretPath(l)
		switch there := present(have, p); {
		case there && !c.Resend:
		case there:
			// Deleted first, so WithLines shows the next step one value.
			cmds = append(cmds, DeleteOf(p), l)
		default:
			cmds = append(cmds, l)
		}
	}
	return cmds
}

// deleteFor is the delete that takes extra line h away: at the highest
// node below the prefix that holds no wanted line, not at h's last word.
// Deleting only a leaf can leave its node behind: on VyOS, deleting
// "next-hop 192.0.2.2 distance 10" leaves next-hop 192.0.2.2 routing
// traffic, and on Junos, deleting "preference 10" leaves an empty
// preference that the commit refuses. Found on VyOS rolling and vJunos-
// switch 26.2 (#833).
func (c Config) deleteFor(h string) string {
	words := splitWords(strings.TrimPrefix(h, "set "))
	floor := len(splitWords(c.Prefix))
	for n := floor + 1; n < len(words); n++ {
		node := strings.Join(words[:n], " ")
		under := func(w string) bool { return Under(w, node) }
		if !slices.ContainsFunc(c.Lines, under) && !slices.ContainsFunc(c.Paths, under) {
			return "delete " + node
		}
	}
	return DeleteOf(h)
}

// splitWords splits a statement at spaces outside double quotes.
func splitWords(s string) []string {
	var words []string
	quoted, start := false, 0
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '\\' && quoted:
			i++
		case s[i] == '"':
			quoted = !quoted
		case s[i] == ' ' && !quoted:
			if i > start {
				words = append(words, s[start:i])
			}
			start = i + 1
		}
	}
	if start < len(s) {
		words = append(words, s[start:])
	}
	return words
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
	for _, p := range c.Paths {
		if present(have, p) {
			cmds = append(cmds, DeleteOf(p))
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
