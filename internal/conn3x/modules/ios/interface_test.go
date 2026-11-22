// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ios

import (
	"slices"
	"strings"
	"testing"
)

const interfaces = `hostname sw1
!
interface GigabitEthernet1/0/1
 description old
 switchport mode access
 switchport access vlan 20
 shutdown
!
interface GigabitEthernet1/0/2
 switchport trunk allowed vlan 10,20-22,30-35,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60
 switchport trunk allowed vlan add 61,62,63,64,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,80,81,82,83,84
 switchport trunk allowed vlan add 100
 switchport mode trunk
!
interface Vlan1
 ip address 192.0.2.10 255.255.255.0
!
`

func ptr[T any](v T) *T { return &v }

func TestInterfaceCommands(t *testing.T) {
	for name, tc := range map[string]struct {
		i    Interface
		want []string
	}{
		"in sync": {Interface{Name: "GigabitEthernet1/0/1", Description: ptr("old"), Enabled: ptr(false), Mode: "access", AccessVLAN: 20}, nil},
		"changes": {Interface{Name: "GigabitEthernet1/0/1", Description: ptr("uplink"), Enabled: ptr(true), AccessVLAN: 10},
			[]string{"interface GigabitEthernet1/0/1", " description uplink", " no shutdown", " switchport access vlan 10"}},
		"VLAN 1 is the default, not printed": {Interface{Name: "GigabitEthernet1/0/1", AccessVLAN: 1},
			[]string{"interface GigabitEthernet1/0/1", " no switchport access vlan"}},
		"a new interface": {Interface{Name: "GigabitEthernet1/0/3", Mode: "trunk", AllowedVLANs: []int{10, 11, 12}},
			[]string{"interface GigabitEthernet1/0/3", " switchport mode trunk", " switchport trunk allowed vlan 10-12"}},
	} {
		if got := tc.i.Commands(interfaces); !slices.Equal(got, tc.want) {
			t.Errorf("%s: Commands = %q, want %q", name, got, tc.want)
		}
		if got := tc.i.InSync(interfaces); got != (tc.want == nil) {
			t.Errorf("%s: InSync = %v", name, got)
		}
	}
}

// A long trunk list goes on over add lines, and is compared as a set.
func TestInterfaceAllowedVLANsAcrossAddLines(t *testing.T) {
	var vlans []int
	for _, r := range [][2]int{{10, 10}, {20, 22}, {30, 35}, {40, 84}, {100, 100}} {
		for v := r[0]; v <= r[1]; v++ {
			vlans = append(vlans, v)
		}
	}
	slices.Reverse(vlans)
	i := Interface{Name: "GigabitEthernet1/0/2", Mode: "trunk", AllowedVLANs: vlans}
	if got := i.Commands(interfaces); got != nil {
		t.Errorf("Commands = %q", got)
	}
	i.AllowedVLANs = append(i.AllowedVLANs, 200)
	if got := i.Commands(interfaces); !slices.Equal(got, []string{"interface GigabitEthernet1/0/2", " switchport trunk allowed vlan 10,20-22,30-35,40-84,100,200"}) {
		t.Errorf("one more VLAN: Commands = %q", got)
	}
	// Every odd VLAN is 9,710 bytes of list: it goes in as IOS prints it,
	// a first part and add lines, and reads back as in sync.
	var odd []int
	for v := 1; v <= 4093; v += 2 {
		odd = append(odd, v)
	}
	big := Interface{Name: "GigabitEthernet1/0/9", AllowedVLANs: odd}
	cmds := big.Commands("")
	if len(cmds) < 3 || cmds[1] == "" || !strings.HasPrefix(cmds[2], " switchport trunk allowed vlan add ") {
		t.Fatalf("Commands = %q", cmds[:min(3, len(cmds))])
	}
	for _, c := range cmds[1:] {
		if len(c) > len(" "+allowedPrefix+"add ")+trunkLine || strings.HasSuffix(c, ",") {
			t.Errorf("line of %d bytes: %q", len(c), c)
		}
	}
	if !big.InSync(strings.Join(cmds, "\n")) {
		t.Error("the commands, read back, aren't in sync")
	}
	if got := (Interface{Name: "GigabitEthernet1/0/2", AllowedVLANs: []int{10}}).InSync("interface GigabitEthernet1/0/2\n switchport trunk allowed vlan none\n"); got {
		t.Error("none read as VLAN 10")
	}
}

func TestInterfaceRemoveCommands(t *testing.T) {
	i := Interface{Name: "GigabitEthernet1/0/1", Description: ptr("old"), Enabled: ptr(true), Mode: "access", AccessVLAN: 30}
	want := []string{"interface GigabitEthernet1/0/1", " no description", " no switchport mode"}
	if got := i.RemoveCommands(interfaces); !slices.Equal(got, want) {
		t.Errorf("RemoveCommands = %q, want %q", got, want)
	}
	if got := (Interface{Name: "GigabitEthernet9/0/9", Description: ptr("x")}).RemoveCommands(interfaces); got != nil {
		t.Errorf("missing interface: %q", got)
	}
}

func TestInterfaceGuard(t *testing.T) {
	shut := Interface{Name: "Vlan1", Enabled: ptr(false)}
	if err := shut.Guard(interfaces, "192.0.2.10"); err == nil || !strings.Contains(err.Error(), "cut it off") {
		t.Errorf("shutting the management SVI: %v", err)
	}
	if err := shut.Guard(interfaces, "192.0.2.11"); err != nil {
		t.Errorf("another address: %v", err)
	}
	if err := (Interface{Name: "Vlan1", Enabled: ptr(true)}).Guard(interfaces, "192.0.2.10"); err != nil {
		t.Errorf("bringing it up: %v", err)
	}
}

func TestInterfaceValidate(t *testing.T) {
	for _, ok := range []Interface{
		{Name: "GigabitEthernet1/0/1", Mode: "access", AccessVLAN: 10},
		{Name: "TenGigabitEthernet1/1/1", Mode: "trunk", AllowedVLANs: []int{1, 4094}},
		{Name: "Port-channel10", Mode: "trunk"},
		{Name: "Ethernet0/1", Description: ptr("iol port")},
		{Name: "Loopback0", Enabled: ptr(true), MTU: 9216},
	} {
		if err := ok.Validate(); err != nil {
			t.Errorf("%+v: %v", ok, err)
		}
	}
	for name, bad := range map[string]Interface{
		"EOS spelling":       {Name: "Port-Channel10"},
		"short name":         {Name: "Gi1/0/1"},
		"switchport on SVI":  {Name: "Vlan20", Mode: "access"},
		"access on a trunk":  {Name: "GigabitEthernet1", Mode: "trunk", AccessVLAN: 10},
		"allowed on access":  {Name: "GigabitEthernet1", Mode: "access", AllowedVLANs: []int{10}},
		"empty allowed list": {Name: "GigabitEthernet1", AllowedVLANs: []int{}},
		"VLAN 4095":          {Name: "GigabitEthernet1", AccessVLAN: 4095},
		"mtu":                {Name: "GigabitEthernet1", MTU: 9217},
		"two-line desc":      {Name: "GigabitEthernet1", Description: ptr("a\nb")},
	} {
		if err := bad.Validate(); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}
