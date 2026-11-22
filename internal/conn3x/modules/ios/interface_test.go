// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ios

import (
	"maps"
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

// trunkModel applies trunk commands one at a time, as IOS does, and fails
// if any step leaves out a VLAN that both the old and the new list hold.
func trunkModel(t *testing.T, name string, old map[int]bool, want []int, cmds []string) {
	t.Helper()
	keep := map[int]bool{}
	for _, v := range want {
		if old[v] {
			keep[v] = true
		}
	}
	have := maps.Clone(old)
	for n, c := range cmds[1:] {
		c = strings.TrimPrefix(c, " ")
		if len(c) > len(allowedPrefix+"remove ")+trunkLine || strings.HasSuffix(c, ",") {
			t.Errorf("%s: line of %d bytes: %q", name, len(c), c)
		}
		rest, _ := strings.CutPrefix(c, allowedPrefix)
		verb, list, _ := strings.Cut(rest, " ")
		if verb != "add" && verb != "remove" {
			verb, list = "replace", rest
		}
		vlans, err := parseVLANs(list)
		if err != nil {
			t.Fatalf("%s: %q: %v", name, c, err)
		}
		if verb == "replace" {
			clear(have)
		}
		for _, v := range vlans {
			have[v] = verb != "remove"
		}
		for v := range keep {
			if !have[v] {
				t.Fatalf("%s: after line %d, %q, the trunk lacks VLAN %d, which both lists hold", name, n+1, c, v)
			}
		}
	}
	got := []int{}
	for v, in := range have {
		if in {
			got = append(got, v)
		}
	}
	if vlanRanges(got) != vlanRanges(want) {
		t.Errorf("%s: ends with %s, want %s", name, vlanRanges(got), vlanRanges(want))
	}
}

// A list too long for one command goes as adds, then removes, so a VLAN in
// both lists never leaves the trunk; one that fits replaces it at once.
func TestInterfaceTrunkChangeNeverDropsAKeptVLAN(t *testing.T) {
	set := func(vlans []int) map[int]bool {
		m := map[int]bool{}
		for _, v := range vlans {
			m[v] = true
		}
		return m
	}
	span := func(lo, hi int, skip func(int) bool) []int {
		var v []int
		for n := lo; n <= hi; n++ {
			if !skip(n) {
				v = append(v, n)
			}
		}
		return v
	}
	all := span(1, 4094, func(int) bool { return false })
	notSevens := span(1, 4000, func(n int) bool { return n%7 == 0 })
	odd := span(1, 4093, func(n int) bool { return n%2 == 0 })
	notFives := span(1, 4094, func(n int) bool { return n%5 == 0 })
	for name, tc := range map[string]struct {
		running string
		old     []int
		want    []int
	}{
		"from no list, which is every VLAN": {"", all, notSevens},
		"from one long list to another":     {" switchport trunk allowed vlan " + vlanRanges(odd), odd, notFives},
		"from a list it can't read":         {" switchport trunk allowed vlan all", all, notSevens},
	} {
		i := Interface{Name: "GigabitEthernet1/0/9", AllowedVLANs: tc.want}
		running := "interface GigabitEthernet1/0/9\n" + tc.running + "\n"
		cmds := i.Commands(running)
		trunkModel(t, name, set(tc.old), tc.want, cmds)
		if !i.InSync("interface GigabitEthernet1/0/9\n " + allowedPrefix + vlanRanges(tc.want) + "\n") {
			t.Errorf("%s: the wanted list doesn't read as in sync", name)
		}
	}
	short := Interface{Name: "GigabitEthernet1/0/2", AllowedVLANs: []int{10, 20}}
	if got := short.Commands(interfaces); !slices.Equal(got, []string{"interface GigabitEthernet1/0/2", " switchport trunk allowed vlan 10,20"}) {
		t.Errorf("a short list: %q", got)
	}
}
