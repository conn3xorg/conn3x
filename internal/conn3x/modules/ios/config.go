// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ios

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode"
)

// node is one line of a running-config and the lines indented under it.
type node struct {
	text string
	kids []*node
}

// parse reads a running-config as IOS prints it, each level indented one
// space further than its parent, into a tree. "!" lines only separate blocks.
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

func (n *node) kid(text string) *node {
	for _, k := range n.kids {
		if k.text == text {
			return k
		}
	}
	return nil
}

func (n *node) render(b *strings.Builder, depth int) {
	for _, k := range n.kids {
		b.WriteString(strings.Repeat(" ", depth) + k.text + "\n")
		k.render(b, depth+1)
	}
}

// section returns the lines directly under the block parents name. found is
// false when a parent isn't there.
func section(config string, parents []string) (lines []string, found bool) {
	cur := parse(config)
	for _, p := range parents {
		if cur = cur.kid(p); cur == nil {
			return nil, false
		}
	}
	for _, k := range cur.kids {
		lines = append(lines, k.text)
	}
	return lines, true
}

// WithLines is config as it reads once cmds, as Commands writes them,
// have gone in: a circuit's later steps work out their own commands from it.
// A command's indent is its depth; one at a depth enters that block, or
// makes it, and a "no" form takes the line it names away.
func WithLines(config string, cmds []string) string {
	root := parse(config)
	path := []*node{root}
	for _, c := range cmds {
		text := strings.TrimLeft(c, " ")
		depth := len(c) - len(text)
		if depth >= len(path) {
			depth = len(path) - 1
		}
		path = path[:depth+1]
		parent := path[depth]
		if rest, ok := strings.CutPrefix(text, "no "); ok && parent.kid(rest) != nil {
			parent.kids = slices.DeleteFunc(parent.kids, func(k *node) bool { return k.text == rest })
			continue
		}
		if parent.kid(text) == nil {
			// "shutdown" and "no shutdown" are one setting: the new one replaces.
			parent.kids = slices.DeleteFunc(parent.kids, func(k *node) bool { return k.text == negate(text) })
			parent.kids = append(parent.kids, &node{text: text})
		}
		path = append(path, parent.kid(text))
	}
	var b strings.Builder
	root.render(&b, 0)
	return b.String()
}

// Match modes for a Config.
const (
	MatchLines = "lines" // these lines must be there; others are left alone
	MatchBlock = "block" // the block must be exactly these lines
)

// Config is a set of lines under a parent block, the way ios_config owns
// them, as show running-config prints them.
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

// modeWords leave configuration mode, run something outside it, or save or
// reload. A word typed at the exec prompt by mistake is worse: IOS takes an
// unknown word there for a host name and tries to connect to it.
var modeWords = []string{"end", "exit", "configure", "copy", "write", "reload", "do"}

func checkLine(l string) error {
	t := strings.TrimSpace(l)
	switch {
	case t == "":
		return errors.New("lines and parents must not be empty strings")
	case strings.ContainsFunc(l, unicode.IsControl):
		return fmt.Errorf("line %q holds a newline or another control character; write it on one line, with printable characters and spaces only", l)
	case t != l:
		return fmt.Errorf("line %q has leading or trailing spaces; write it the way show running-config prints it, without the indent", l)
	case strings.HasPrefix(t, "!"):
		return fmt.Errorf("line %q is a comment; leave it out", l)
	}
	first := strings.ToLower(strings.Fields(t)[0])
	for _, w := range modeWords {
		if strings.HasPrefix(w, first) {
			return fmt.Errorf("line %q would leave configuration mode or act outside it, as %q or a short form of it; Conn3x enters, confirms and saves the configuration itself. Write a line the way show running-config prints it, in full", l, w)
		}
	}
	return nil
}

// InSync reports whether config has what c wants.
func (c Config) InSync(config string) bool { return c.Commands(config) == nil }

// Commands are what to type in configuration mode to bring config in line,
// each indented to its depth, as show running-config would print it: each
// parent, then the extras taken away in block mode, then what's missing.
// Nil when nothing needs to change.
func (c Config) Commands(config string) []string {
	have, found := section(config, c.Parents)
	var missing, extra []string
	for _, w := range c.Lines {
		if !slices.Contains(have, w) {
			missing = append(missing, w)
		}
	}
	if c.Match == MatchBlock {
		for _, h := range have {
			if !slices.Contains(c.Lines, h) {
				extra = append(extra, negate(h))
			}
		}
	}
	if found && len(missing) == 0 && len(extra) == 0 {
		return nil
	}
	return c.indented(append(extra, missing...))
}

// RemoveCommands take out the lines c owns that config still has, leaving
// the parents and everything else. Nil when none are left.
func (c Config) RemoveCommands(config string) []string {
	have, _ := section(config, c.Parents)
	var lines []string
	for _, l := range c.Lines {
		if slices.Contains(have, l) {
			lines = append(lines, negate(l))
		}
	}
	if lines == nil {
		return nil
	}
	return c.indented(lines)
}

func (c Config) indented(lines []string) []string {
	var cmds []string
	for i, p := range c.Parents {
		cmds = append(cmds, strings.Repeat(" ", i)+p)
	}
	for _, l := range lines {
		cmds = append(cmds, strings.Repeat(" ", len(c.Parents))+l)
	}
	return cmds
}

// negate is the command that removes a line: "no x", or "x" for a line that
// is itself a "no" form, such as "no shutdown".
func negate(line string) string {
	if rest, ok := strings.CutPrefix(line, "no "); ok {
		return rest
	}
	return "no " + line
}
