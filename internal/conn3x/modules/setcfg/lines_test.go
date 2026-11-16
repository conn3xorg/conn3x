// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package setcfg

import (
	"slices"
	"strings"
	"testing"
)

// A deactivated statement, and everything under it, isn't a set line.
func TestSetLinesLeavesOutDeactivated(t *testing.T) {
	got := SetLines("set system host-name r1\r\nset interfaces ge-0/0/1 unit 0\nset interfaces ge-0/0/1 unit 0 family inet\ndeactivate interfaces ge-0/0/1\n# comment\n")
	if !slices.Equal(got, []string{"set system host-name r1"}) {
		t.Errorf("got %q", got)
	}
}

func TestCheckLineAndText(t *testing.T) {
	for line, want := range map[string]string{
		"":                                      "line must not be empty",
		"set system\nhost-name r1":              "holds a newline",
		" set system host-name r1":              "leading or trailing spaces",
		"# set system host-name r1":             "is a comment",
		"show configuration":                    "must be a set statement",
		"set ":                                  "leading or trailing spaces",
		"set system host-name r1 | display set": "has a | outside quotes",
		"set system root-authentication plain-text-password": "would prompt for a password",
	} {
		if err := CheckLine(line); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("CheckLine(%q) = %v, want %q", line, err, want)
		}
	}
	for _, ok := range []string{`set system login message "a | b \" | c"`, "set system host-name r1"} {
		if err := CheckLine(ok); err != nil {
			t.Errorf("CheckLine(%q) = %v", ok, err)
		}
	}
}

func TestValidate(t *testing.T) {
	for want, c := range map[string]Config{
		"match must be":            {Match: "all", Lines: []string{"set a b"}},
		"needs prefix":             {Match: MatchBlock},
		"prefix must not be empty": {Match: MatchBlock, Prefix: " "},
		"lines must not be empty":  {},
		"isn't under prefix":       {Match: MatchBlock, Prefix: "system", Lines: []string{"set interfaces ge-0/0/1"}},
		"must be a set statement":  {Lines: []string{"delete system"}},
		"isn't one set statement":  {Secrets: []string{"set a password 'x' | y"}},
	} {
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%+v: %v, want %q", c, err, want)
		}
	}
	// Block mode owns the prefix with no lines at all: it deletes all under it.
	if err := (Config{Match: MatchBlock, Prefix: "system syslog"}).Validate(); err != nil {
		t.Error(err)
	}
}

// A split secret would leave part of it in state.
func TestSecretPathQuotes(t *testing.T) {
	if _, err := SecretPath(`set a "b c" password x`); err == nil || !strings.Contains(err.Error(), "couldn't be split") {
		t.Errorf("quote in the path: %v", err)
	}
	// Inside double quotes a backslash escapes the next byte, a quote too.
	if p, err := SecretPath(`set a password "x \" y"`); err != nil || p != "set a password" {
		t.Errorf("escaped quote: %q, %v", p, err)
	}
	if words, closed := secretWords("set  a "); !closed || !slices.Equal(words, []string{"set", "a"}) {
		t.Errorf("spaces: %q", words)
	}
}

func TestLeaf(t *testing.T) {
	l := Leaf{Path: "system host-name", Value: "r1"}
	for have, want := range map[string][]string{
		"set system host-name r1\n": nil,
		"set system host-name r2\n": {"delete system host-name", "set system host-name r1"},
		"set system domain x\n":     {"set system host-name r1"},
	} {
		if got := l.Commands(have); !slices.Equal(got, want) {
			t.Errorf("%q: %q, want %q", have, got, want)
		}
	}
	if !l.InSync("set system host-name r1\n") || l.InSync("") {
		t.Error("InSync")
	}
	if HaveLeaf([]string{"set system host-namex y"}, "system host-name") != "" {
		t.Error("a longer word matched the path")
	}
}

// WithLines is what the device holds after cmds: a delete takes what's at
// and below it, a set adds a line once.
func TestWithLines(t *testing.T) {
	got := WithLines("set system host-name r1\nset system syslog host a\nset system syslog host b\n",
		[]string{"delete system syslog", "set system host-name r1", "set system domain x"})
	if got != "set system host-name r1\nset system domain x\n" {
		t.Errorf("got %q", got)
	}
}

func TestLinesModeAndRemove(t *testing.T) {
	c := Config{Lines: []string{"set system host-name r1", "set system domain x"}}
	have := "set system host-name r1\nset system ntp server a\n"
	if got := c.Commands(have); !slices.Equal(got, []string{"set system domain x"}) {
		t.Errorf("lines mode touched others: %q", got)
	}
	if c.InSync(have) || !c.InSync(have+"set system domain x\n") {
		t.Error("InSync")
	}
	if got := c.RemoveCommands(have); !slices.Equal(got, []string{"delete system host-name r1"}) {
		t.Errorf("remove: %q", got)
	}
	if got := (Config{Paths: []string{"set a password"}}).RemoveCommands(have); got != nil {
		t.Errorf("nothing to remove: %q", got)
	}
}
