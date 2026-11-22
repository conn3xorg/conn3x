// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package junos

import (
	"slices"
	"strings"
	"testing"
)

const l3 = `set interfaces irb unit 10 family inet address 192.0.2.1/24
set interfaces irb unit 10 family inet6 address 2001:DB8:10::1/64
set interfaces irb unit 20 family inet address 198.51.100.1/24
set interfaces fxp0 unit 0 family inet address 10.0.0.5/24
set interfaces lo0 unit 0 family inet address 192.0.2.254/32
`

func TestInterfaceAddressCommands(t *testing.T) {
	for name, tc := range map[string]struct {
		i    Interface
		want []string
	}{
		"in sync, IPv6 in lower case": {Interface{Name: "irb", Unit: 10, Addresses: []string{"192.0.2.1/24", "2001:db8:10::1/64"}}, nil},
		"one swapped, the new one first": {Interface{Name: "irb", Unit: 10, Addresses: []string{"192.0.2.2/24", "2001:db8:10::1/64"}},
			[]string{"set interfaces irb unit 10 family inet address 192.0.2.2/24", "delete interfaces irb unit 10 family inet address 192.0.2.1/24"}},
		"IPv6 goes": {Interface{Name: "irb", Unit: 10, Addresses: []string{"192.0.2.1/24"}},
			[]string{"delete interfaces irb unit 10 family inet6 address 2001:DB8:10::1/64"}},
		"another unit is left alone": {Interface{Name: "irb", Unit: 30, Addresses: []string{"203.0.113.1/24"}},
			[]string{"set interfaces irb unit 30 family inet address 203.0.113.1/24"}},
		"unit 0 by default":   {Interface{Name: "lo0", Addresses: []string{"192.0.2.254/32"}}, nil},
		"unset is left alone": {Interface{Name: "irb", Unit: 10}, nil},
	} {
		if got := tc.i.Commands(l3); !slices.Equal(got, tc.want) {
			t.Errorf("%s: Commands = %q, want %q", name, got, tc.want)
		}
	}
}

func TestInterfaceAddressRemoveCommands(t *testing.T) {
	i := Interface{Name: "irb", Unit: 10, Addresses: []string{"192.0.2.1/24", "2001:db8:10::1/64"}}
	want := []string{"delete interfaces irb unit 10 family inet address 192.0.2.1/24", "delete interfaces irb unit 10 family inet6 address 2001:DB8:10::1/64"}
	if got := i.RemoveCommands(l3); !slices.Equal(got, want) {
		t.Errorf("RemoveCommands = %q, want %q", got, want)
	}
}

func TestInterfaceAddressGuard(t *testing.T) {
	if err := (Interface{Name: "fxp0", Addresses: []string{"10.0.0.6/24"}}).Guard(l3, "10.0.0.5"); err == nil || !strings.Contains(err.Error(), "cut it off") {
		t.Errorf("taking off the connect address: %v", err)
	}
	if err := (Interface{Name: "fxp0", Addresses: []string{"10.0.0.5/24", "10.0.1.5/24"}}).Guard(l3, "10.0.0.5"); err != nil {
		t.Errorf("keeping it: %v", err)
	}
	if err := (Interface{Name: "irb", Unit: 10, Addresses: []string{}}).Guard(l3, "10.0.0.5"); err != nil {
		t.Errorf("connected elsewhere: %v", err)
	}
}

func TestInterfaceAddressValidate(t *testing.T) {
	if err := (Interface{Name: "irb", Unit: 10, Addresses: []string{"192.0.2.1/24", "2001:db8::1/64"}}).Validate(); err != nil {
		t.Error(err)
	}
	for name, bad := range map[string]Interface{
		"no length":           {Name: "irb", Unit: 10, Addresses: []string{"192.0.2.1"}},
		"with a mode":         {Name: "ge-0/0/1", Mode: "access", Addresses: []string{"192.0.2.1/24"}},
		"switching on unit 5": {Name: "ge-0/0/1", Unit: 5, Mode: "access"},
		"unit too big":        {Name: "irb", Unit: 20000},
	} {
		if err := bad.Validate(); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}
