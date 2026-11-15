// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package eos

import (
	"fmt"
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
		// Short forms EOS takes for the words above, and the words that
		// run a command outside the session or empty it.
		{Lines: []string{"conf t"}},
		{Lines: []string{"wr"}},
		{Lines: []string{"ex"}},
		{Lines: []string{"EN"}},
		{Lines: []string{"ab"}},
		{Lines: []string{"do write"}},
		{Lines: []string{"run bash"}},
		{Lines: []string{"rollback clean-config"}},
		{Parents: []string{"e"}, Lines: []string{"x"}},
		{Lines: []string{"description a\x1bb"}},
		{Lines: []string{"description a\tb"}},
		{Lines: []string{"description a\x00"}},
	} {
		if err := c.Validate(); err == nil {
			t.Errorf("%+v: no error", c)
		}
	}
	for _, l := range []string{"control-plane", "router bgp 65000", "banner motd hello", "daemon x", "email from x@y", "errdisable recovery interval 30", "radius-server host 10.0.0.1", "dot1x system-auth-control"} {
		if err := (Config{Lines: []string{l}}).Validate(); err != nil {
			t.Errorf("%q: %v", l, err)
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
	if !v.InSync(running) {
		t.Error("vlan 10 named users is there")
	}
	renamed := VLAN{ID: 10}
	if renamed.InSync(running) {
		t.Error("an unnamed vlan 10 should drop the hand-set name")
	}
	if got := renamed.Commands(running); !slices.Equal(got, []string{"vlan 10", "no name users"}) {
		t.Errorf("commands %q", got)
	}
	added := VLAN{ID: 20}
	if got := added.Commands(running); !slices.Equal(got, []string{"vlan 20"}) {
		t.Errorf("a new unnamed vlan: %q", got)
	}
	// EOS prints VLANs with nothing under them on one line.
	grouped := running + "vlan 30,40-42\n!\n"
	for _, id := range []int{30, 41, 42} {
		if u := (VLAN{ID: id}); !u.InSync(grouped) || u.Commands(grouped) != nil || !slices.Equal(u.RemoveCommands(grouped), []string{fmt.Sprintf("no vlan %d", id)}) {
			t.Errorf("vlan %d in %q: in sync %v, commands %q, remove %q", id, "vlan 30,40-42", u.InSync(grouped), u.Commands(grouped), u.RemoveCommands(grouped))
		}
	}
	if named := (VLAN{ID: 41, Name: "web"}); named.InSync(grouped) || !slices.Equal(named.Commands(grouped), []string{"vlan 41", "name web"}) {
		t.Errorf("naming a grouped vlan: %q", named.Commands(grouped))
	}
	if (VLAN{ID: 35}).InSync(grouped) || (VLAN{ID: 35}).RemoveCommands(grouped) != nil {
		t.Error("vlan 35 isn't in 30,40-42")
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

func TestConfigSecrets(t *testing.T) {
	cfg := "tacacs-server key 7 0207165218120E\nsnmp-server community public ro\nsnmp-server community other ro\nrouter bgp 65000\n   neighbor 10.0.0.1 password 7 abc==\n   neighbor 10.0.0.1 remote-as 65001\n"
	for line, want := range map[string]string{
		"tacacs-server key MyKey":                           "tacacs-server key",
		"snmp-server community MyCommunity ro":              "snmp-server community",
		"neighbor 10.0.0.1 password MyPass":                 "neighbor 10.0.0.1 password",
		"username bob secret 0 MyPass":                      "username bob secret",
		"ntp authentication-key 2 sha1 MyKey":               "ntp authentication-key 2",
		"tacacs-server key 7 0207165218120E":                "tacacs-server key",
		"snmp-server user ops grp v3 auth sha A priv aes B": "snmp-server user ops grp v3 auth",
	} {
		if got, err := SecretPrefix(line); err != nil || got != want {
			t.Errorf("SecretPrefix(%q) = %q, %v; want %q", line, got, err, want)
		}
	}
	if _, err := SecretPrefix("hostname leaf1"); err == nil {
		t.Error("a plain line has a prefix")
	}

	// Present by prefix: in sync whatever secret the switch holds.
	c := Config{Parents: []string{"router bgp 65000"}, Lines: []string{"neighbor 10.0.0.1 remote-as 65001"}, Match: MatchBlock,
		Secrets: []string{"neighbor 10.0.0.1 password MyPass"}, Prefixes: []string{"neighbor 10.0.0.1 password"}}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if !c.InSync(cfg) {
		t.Error("block with its secret line out of sync")
	}
	if cmds := c.Commands(cfg); cmds != nil {
		t.Errorf("commands with nothing to change: %v", cmds)
	}
	// A changed secret replaces the line the switch holds.
	c.Resend = true
	want := []string{"router bgp 65000", "no neighbor 10.0.0.1 password 7 abc==", "neighbor 10.0.0.1 password MyPass"}
	if cmds := c.Commands(cfg); !slices.Equal(cmds, want) {
		t.Errorf("resend: %v", cmds)
	}
	if rm := c.RemoveCommands(cfg); !slices.Equal(rm, []string{"router bgp 65000", "no neighbor 10.0.0.1 remote-as 65001", "no neighbor 10.0.0.1 password 7 abc=="}) {
		t.Errorf("remove: %v", rm)
	}

	// Missing: out of sync, and sent without Resend.
	top := Config{Secrets: []string{"tacacs-server key MyKey", "ntp authentication-key 1 sha1 MyKey"},
		Prefixes: []string{"tacacs-server key", "ntp authentication-key 1"}, Match: MatchLines}
	if top.InSync(cfg) {
		t.Error("in sync without the ntp key")
	}
	if cmds := top.Commands(cfg); !slices.Equal(cmds, []string{"ntp authentication-key 1 sha1 MyKey"}) {
		t.Errorf("missing secret: %v", cmds)
	}
	// Two NTP keys are two lines: rotating one leaves the other.
	ntp := "ntp authentication-key 1 sha1 7 Aaa==\nntp authentication-key 2 sha1 7 Bbb==\n"
	two := Config{Secrets: []string{"ntp authentication-key 1 sha1 One", "ntp authentication-key 2 sha1 Two"},
		Prefixes: []string{"ntp authentication-key 1", "ntp authentication-key 2"}, Match: MatchLines}
	if err := two.Validate(); err != nil {
		t.Fatal(err)
	}
	if !two.InSync(ntp) {
		t.Error("two ntp keys out of sync")
	}
	one := Config{Secrets: []string{"ntp authentication-key 2 sha1 New"}, Prefixes: []string{"ntp authentication-key 2"}, Match: MatchLines, Resend: true}
	if cmds := one.Commands(ntp); !slices.Equal(cmds, []string{"no ntp authentication-key 2 sha1 7 Bbb==", "ntp authentication-key 2 sha1 New"}) {
		t.Errorf("rotating key 2: %v", cmds)
	}
	if one.InSync("ntp authentication-key 1 sha1 7 Aaa==\n") {
		t.Error("key 1 counts as key 2")
	}

	for _, bad := range []Config{
		{Secrets: []string{"hostname leaf1"}},
		{Secrets: []string{"tacacs-server key A", "tacacs-server key B"}},
		{Secrets: []string{"snmp-server community x ro"}},
		{Secrets: []string{"tacacs-server key x"}, Lines: []string{"tacacs-server key 7 0207"}},
		{Secrets: []string{"configure terminal key x"}},
	} {
		err := bad.Validate()
		if err == nil {
			t.Errorf("accepted %+v", bad)
			continue
		}
		for _, s := range bad.Secrets {
			if f := strings.Fields(s); strings.Contains(err.Error(), f[len(f)-1]) && len(f[len(f)-1]) > 2 {
				t.Errorf("error quotes a secret: %v", err)
			}
		}
	}
	if !LooksSecret("tacacs-server key 7 0207") || LooksSecret("description uplink") {
		t.Error("LooksSecret")
	}
}
