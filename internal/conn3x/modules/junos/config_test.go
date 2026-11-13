// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package junos

import (
	"slices"
	"strings"
	"testing"
)

// running is show configuration | display set as vJunos-switch 26.2R1.7
// printed it in the spike, trimmed.
const running = `set version 26.2R1.7
set system host-name sw-spike
set system services ssh root-login allow
set interfaces ge-0/0/1 description spike
set interfaces ge-0/0/2 description from-file
set interfaces ge-0/0/2 mtu 9000
set interfaces ge-0/0/9 description off
deactivate interfaces ge-0/0/9
set vlans v10 vlan-id 10
set vlans v10 description users
`

func TestSetLinesDropsDeactivated(t *testing.T) {
	got := SetLines(running)
	if slices.Contains(got, "set interfaces ge-0/0/9 description off") {
		t.Error("kept a deactivated statement")
	}
	if !slices.Contains(got, "set interfaces ge-0/0/1 description spike") {
		t.Error("lost an active statement")
	}
}

func TestConfigLines(t *testing.T) {
	c := Config{Lines: []string{"set interfaces ge-0/0/1 description spike", "set interfaces ge-0/0/1 mtu 9216"}}
	if c.InSync(running) {
		t.Error("in sync with a line missing")
	}
	if got := c.Commands(running); !slices.Equal(got, []string{"set interfaces ge-0/0/1 mtu 9216"}) {
		t.Errorf("Commands = %q", got)
	}
	if got := c.RemoveCommands(running); !slices.Equal(got, []string{"delete interfaces ge-0/0/1 description spike"}) {
		t.Errorf("RemoveCommands = %q", got)
	}
}

func TestConfigBlock(t *testing.T) {
	c := Config{Prefix: "interfaces ge-0/0/2", Lines: []string{"set interfaces ge-0/0/2 description uplink"}, Match: MatchBlock}
	want := []string{"delete interfaces ge-0/0/2 description from-file", "delete interfaces ge-0/0/2 mtu 9000", "set interfaces ge-0/0/2 description uplink"}
	if got := c.Commands(running); !slices.Equal(got, want) {
		t.Errorf("Commands = %q, want %q", got, want)
	}
	// ge-0/0/20 isn't under ge-0/0/2.
	other := running + "set interfaces ge-0/0/20 mtu 1500\n"
	if got := c.Commands(other); slices.ContainsFunc(got, func(s string) bool { return strings.Contains(s, "ge-0/0/20") }) {
		t.Errorf("Commands touched another interface: %q", got)
	}
}

func TestConfigValidate(t *testing.T) {
	for name, c := range map[string]Config{
		"not set":          {Lines: []string{"delete system host-name"}},
		"leaves the mode":  {Lines: []string{"exit"}},
		"runs a command":   {Lines: []string{"run show version"}},
		"two lines":        {Lines: []string{"set system host-name a\ncommit"}},
		"pipe":             {Lines: []string{"set system host-name a | save /tmp/x"}},
		"block, no prefix": {Lines: []string{"set system host-name a"}, Match: MatchBlock},
		"outside prefix":   {Prefix: "interfaces ge-0/0/1", Lines: []string{"set interfaces ge-0/0/10 mtu 9000"}, Match: MatchBlock},
		"empty":            {},
		"bad match":        {Lines: []string{"set system host-name a"}, Match: "all"},
		"password prompt":  {Lines: []string{"set system login user x authentication plain-text-password"}},
	} {
		if err := c.Validate(); err == nil {
			t.Errorf("%s: Validate passed", name)
		}
	}
	ok := Config{Lines: []string{`set interfaces ge-0/0/1 description "a | b"`}}
	if err := ok.Validate(); err != nil {
		t.Errorf("a quoted pipe: %v", err)
	}
	empty := Config{Prefix: "interfaces ge-0/0/1", Match: MatchBlock}
	if err := empty.Validate(); err != nil {
		t.Errorf("an empty block: %v", err)
	}
}

func TestVLAN(t *testing.T) {
	v := VLAN{Name: "v10", ID: 10}
	if !v.InSync(running) {
		t.Error("v10 out of sync")
	}
	if got := (VLAN{Name: "v10", ID: 11}).Commands(running); !slices.Equal(got, []string{"set vlans v10 vlan-id 11"}) {
		t.Errorf("Commands = %q", got)
	}
	if got := v.RemoveCommands(running); !slices.Equal(got, []string{"delete vlans v10"}) {
		t.Errorf("RemoveCommands = %q", got)
	}
	if got := (VLAN{Name: "v1", ID: 1}).RemoveCommands(running); got != nil {
		t.Errorf("removing a VLAN that isn't there: %q", got)
	}
	for _, bad := range []VLAN{{Name: "10", ID: 10}, {Name: "v", ID: 0}, {Name: "v x", ID: 5}} {
		if bad.Validate() == nil {
			t.Errorf("%+v passed", bad)
		}
	}
}

func TestHostname(t *testing.T) {
	if !Hostname("sw-spike").InSync(running) {
		t.Error("out of sync")
	}
	if ValidateHostname("-bad") == nil || ValidateHostname("sw1.lab") != nil {
		t.Error("ValidateHostname")
	}
}
