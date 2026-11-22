// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package eos

import (
	"slices"
	"strings"
	"testing"
)

const l3 = `interface Ethernet1
   no switchport
   ip address 192.0.2.1/24
   ip address 198.51.100.1/24 secondary
   ipv6 address 2001:DB8::1/64
!
interface Ethernet2
   description access
!
interface Management1
   ip address 10.0.0.5/24
!
interface Vlan10
!
`

func TestInterfaceAddressCommands(t *testing.T) {
	for name, tc := range map[string]struct {
		addrs []string
		want  []string
	}{
		"in sync, IPv6 written in lower case": {[]string{"192.0.2.1/24", "198.51.100.1/24", "2001:db8::1/64"}, nil},
		"a secondary swapped, the new one first": {[]string{"192.0.2.1/24", "203.0.113.1/24", "2001:db8::1/64"},
			[]string{"interface Ethernet1", "ip address 203.0.113.1/24 secondary", "no ip address 198.51.100.1/24 secondary"}},
		"a new primary replaces the old": {[]string{"192.0.2.9/24", "198.51.100.1/24", "2001:db8::1/64"},
			[]string{"interface Ethernet1", "ip address 192.0.2.9/24"}},
		"IPv4 only, IPv6 goes": {[]string{"192.0.2.1/24", "198.51.100.1/24"},
			[]string{"interface Ethernet1", "no ipv6 address 2001:db8::1/64"}},
		"none, secondaries before the primary": {[]string{},
			[]string{"interface Ethernet1", "no ip address 198.51.100.1/24 secondary", "no ipv6 address 2001:db8::1/64", "no ip address 192.0.2.1/24"}},
	} {
		i := Interface{Name: "Ethernet1", Addresses: tc.addrs}
		if got := i.Commands(l3); !slices.Equal(got, tc.want) {
			t.Errorf("%s: Commands = %q, want %q", name, got, tc.want)
		}
		if got := i.InSync(l3); got != (tc.want == nil) {
			t.Errorf("%s: InSync = %v", name, got)
		}
	}
	if got := (Interface{Name: "Vlan10", Addresses: []string{"192.0.2.254/24"}}).Commands(l3); !slices.Equal(got, []string{"interface Vlan10", "ip address 192.0.2.254/24"}) {
		t.Errorf("an SVI: %q", got)
	}
	if got := (Interface{Name: "Ethernet1"}).Commands(l3); got != nil {
		t.Errorf("addresses unset are left alone: %q", got)
	}
}

func TestInterfaceAddressRemoveCommands(t *testing.T) {
	i := Interface{Name: "Ethernet1", Addresses: []string{"192.0.2.1/24", "198.51.100.1/24"}}
	want := []string{"interface Ethernet1", "no ip address 198.51.100.1/24 secondary", "no ip address 192.0.2.1/24"}
	if got := i.RemoveCommands(l3); !slices.Equal(got, want) {
		t.Errorf("RemoveCommands = %q, want %q", got, want)
	}
}

func TestInterfaceAddressGuard(t *testing.T) {
	mgmt := Interface{Name: "Management1", Addresses: []string{"10.0.0.6/24"}}
	if err := mgmt.Guard(l3, "10.0.0.5"); err == nil || !strings.Contains(err.Error(), "cut it off") {
		t.Errorf("taking off the connect address: %v", err)
	}
	if err := (Interface{Name: "Management1", Addresses: []string{"10.0.0.5/24"}}).Guard(l3, "10.0.0.5"); err != nil {
		t.Errorf("keeping it: %v", err)
	}
	if err := mgmt.Guard(l3, "192.0.2.50"); err != nil {
		t.Errorf("connected elsewhere: %v", err)
	}
	if err := (Interface{Name: "Ethernet2", Addresses: []string{"192.0.2.1/24"}}).Guard(l3, "10.0.0.5"); err == nil || !strings.Contains(err.Error(), "no switchport") {
		t.Errorf("a switched port: %v", err)
	}
	if err := (Interface{Name: "Ethernet1", Addresses: []string{"192.0.2.1/24"}}).Guard(l3, "10.0.0.5"); err != nil {
		t.Errorf("a routed port: %v", err)
	}
}

func TestInterfaceAddressValidate(t *testing.T) {
	if err := (Interface{Name: "Vlan10", Addresses: []string{"192.0.2.1/24", "2001:db8::1/64"}}).Validate(); err != nil {
		t.Error(err)
	}
	for name, bad := range map[string]Interface{
		"no length":      {Name: "Vlan10", Addresses: []string{"192.0.2.1"}},
		"with a mode":    {Name: "Ethernet1", Mode: "access", Addresses: []string{"192.0.2.1/24"}},
		"with a zone":    {Name: "Vlan10", Addresses: []string{"fe80::1%eth0/64"}},
		"not an address": {Name: "Vlan10", Addresses: []string{"dhcp"}},
	} {
		if err := bad.Validate(); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}
