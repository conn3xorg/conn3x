// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package eos

import (
	"slices"
	"strings"
	"testing"
)

const running = `! Command: show running-config
! device: ceos1 (cEOSLab, EOS-4.37.0F)
!
no aaa root
!
username admin privilege 15 role network-admin nopassword
!
hostname ceos1
!
vlan 10
   name users
!
interface Ethernet1
   description uplink
   switchport mode trunk
!
router bgp 65000
   neighbor 10.0.0.1 remote-as 65001
   !
   address-family ipv4
      neighbor 10.0.0.1 activate
!
interface Ethernet2
!
end
`

func TestSection(t *testing.T) {
	for _, tc := range []struct {
		parents []string
		want    []string
		found   bool
	}{
		{[]string{"vlan 10"}, []string{"name users"}, true},
		{[]string{"interface Ethernet1"}, []string{"description uplink", "switchport mode trunk"}, true},
		{[]string{"router bgp 65000"}, []string{"neighbor 10.0.0.1 remote-as 65001", "address-family ipv4"}, true},
		{[]string{"router bgp 65000", "address-family ipv4"}, []string{"neighbor 10.0.0.1 activate"}, true},
		{[]string{"interface Ethernet2"}, nil, true},
		{[]string{"interface Ethernet3"}, nil, false},
		{[]string{"address-family ipv4"}, nil, false},
	} {
		got, found := Section(running, tc.parents)
		if found != tc.found || !slices.Equal(got, tc.want) {
			t.Errorf("Section(%q) = %q, %v; want %q, %v", tc.parents, got, found, tc.want, tc.found)
		}
	}
	top, _ := Section(running, nil)
	if !slices.Contains(top, "hostname ceos1") || slices.Contains(top, "name users") {
		t.Errorf("top level = %q", top)
	}
}

func TestConfigCommands(t *testing.T) {
	c := Config{Parents: []string{"interface Ethernet1"}, Lines: []string{"description core", "switchport mode trunk"}, Match: MatchLines}
	if c.InSync(running) {
		t.Fatal("in sync with a different description")
	}
	want := []string{"interface Ethernet1", "description core"}
	if got := c.Commands(running); !slices.Equal(got, want) {
		t.Errorf("lines: %q, want %q", got, want)
	}

	c.Match = MatchBlock
	want = []string{"interface Ethernet1", "no description uplink", "description core"}
	if got := c.Commands(running); !slices.Equal(got, want) {
		t.Errorf("block: %q, want %q", got, want)
	}

	same := Config{Parents: []string{"vlan 10"}, Lines: []string{"name users"}, Match: MatchBlock}
	if !same.InSync(running) || same.Commands(running) != nil {
		t.Error("a matching block should be in sync with nothing to send")
	}

	top := Config{Lines: []string{"hostname ceos1"}}
	if !top.InSync(running) {
		t.Error("top-level line not found")
	}

	missing := Config{Parents: []string{"interface Ethernet9"}, Lines: []string{"description new"}}
	if missing.InSync(running) {
		t.Error("a missing parent is not in sync")
	}
	if got := missing.Commands(running); !slices.Equal(got, []string{"interface Ethernet9", "description new"}) {
		t.Errorf("new block: %q", got)
	}
}

func TestNegate(t *testing.T) {
	if negate("no shutdown") != "shutdown" || negate("shutdown") != "no shutdown" {
		t.Error("negate")
	}
}

func TestConfigValidate(t *testing.T) {
	for _, c := range []Config{
		{Lines: nil},
		{Lines: []string{"x"}, Match: "exact"},
		{Lines: []string{"x"}, Match: MatchBlock},
		{Lines: []string{" description x"}},
		{Lines: []string{"a\nb"}},
		{Lines: []string{"end"}},
		{Lines: []string{"copy running-config startup-config"}},
		{Parents: []string{"exit"}, Lines: []string{"x"}},
		{Lines: []string{""}},
	} {
		if err := c.Validate(); err == nil {
			t.Errorf("%+v: no error", c)
		}
	}
	ok := Config{Parents: []string{"interface Ethernet1"}, Lines: []string{"description x"}, Match: MatchBlock}
	if err := ok.Validate(); err != nil {
		t.Error(err)
	}
	if err := (Config{Parents: []string{"interface Ethernet1"}, Match: MatchBlock}).Validate(); err != nil {
		t.Errorf("an empty block is allowed: %v", err)
	}
}

func TestVLAN(t *testing.T) {
	v := VLAN{ID: 10, Name: "users"}
	if !v.Config().InSync(running) {
		t.Error("vlan 10 named users is there")
	}
	renamed := VLAN{ID: 10}
	if renamed.Config().InSync(running) {
		t.Error("an unnamed vlan 10 should drop the hand-set name")
	}
	if got := renamed.Config().Commands(running); !slices.Equal(got, []string{"vlan 10", "no name users"}) {
		t.Errorf("commands %q", got)
	}
	added := VLAN{ID: 20}
	if got := added.Config().Commands(running); !slices.Equal(got, []string{"vlan 20"}) {
		t.Errorf("a new unnamed vlan: %q", got)
	}
	if got := v.RemoveCommands(running); !slices.Equal(got, []string{"no vlan 10"}) {
		t.Errorf("remove: %q", got)
	}
	if added.RemoveCommands(running) != nil {
		t.Error("removing a vlan that isn't there sends nothing")
	}
	for _, bad := range []VLAN{{ID: 0}, {ID: 4095}, {ID: 5, Name: "two words"}, {ID: 5, Name: strings.Repeat("x", 33)}} {
		if bad.Validate() == nil {
			t.Errorf("%+v: no error", bad)
		}
	}
}

func TestHostname(t *testing.T) {
	if !Hostname("ceos1").InSync(running) || Hostname("leaf1").InSync(running) {
		t.Error("InSync")
	}
	if got := Hostname("leaf1").Commands(running); !slices.Equal(got, []string{"hostname leaf1"}) {
		t.Errorf("commands %q", got)
	}
	for _, bad := range []string{"", "-a", "a b", "a_b", strings.Repeat("a", 65)} {
		if ValidateHostname(bad) == nil {
			t.Errorf("%q: no error", bad)
		}
	}
	if err := ValidateHostname("leaf1.dc1"); err != nil {
		t.Error(err)
	}
}

func TestRemoveCommands(t *testing.T) {
	c := Config{Parents: []string{"interface Ethernet1"}, Lines: []string{"description uplink", "mtu 9000"}}
	if got := c.RemoveCommands(running); !slices.Equal(got, []string{"interface Ethernet1", "no description uplink"}) {
		t.Errorf("remove: %q", got)
	}
	gone := Config{Parents: []string{"interface Ethernet1"}, Lines: []string{"mtu 9000"}}
	if gone.RemoveCommands(running) != nil {
		t.Error("nothing to remove sends nothing")
	}
}
