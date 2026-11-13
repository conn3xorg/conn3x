// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package junos

import (
	"slices"
	"testing"
)

const ifaceConfig = `set interfaces ge-0/0/1 description "old uplink"
set interfaces ge-0/0/1 mtu 1514
set interfaces ge-0/0/1 unit 0 family ethernet-switching interface-mode trunk
set interfaces ge-0/0/1 unit 0 family ethernet-switching vlan members v10
set interfaces ge-0/0/1 unit 0 family ethernet-switching vlan members 20
set interfaces ge-0/0/2 disable
set interfaces ge-0/0/3 unit 0 family inet address 192.168.122.10/24
`

func ptr[T any](v T) *T { return &v }

func TestInterfaceCommands(t *testing.T) {
	i := Interface{Name: "ge-0/0/1", Description: ptr("uplink to core"), MTU: 9216, Mode: "trunk", AllowedVLANs: []string{"20", "30"}}
	want := []string{
		"delete interfaces ge-0/0/1 description",
		`set interfaces ge-0/0/1 description "uplink to core"`,
		"delete interfaces ge-0/0/1 mtu",
		"set interfaces ge-0/0/1 mtu 9216",
		"delete interfaces ge-0/0/1 unit 0 family ethernet-switching vlan members v10",
		"set interfaces ge-0/0/1 unit 0 family ethernet-switching vlan members 30",
	}
	if got := i.Commands(ifaceConfig); !slices.Equal(got, want) {
		t.Errorf("Commands:\n%q\nwant\n%q", got, want)
	}
	if !i.InSync(WithLines(ifaceConfig, want)) {
		t.Error("not in sync once its commands are in")
	}
	enable := Interface{Name: "ge-0/0/2", Enabled: ptr(true)}
	if got := enable.Commands(ifaceConfig); !slices.Equal(got, []string{"delete interfaces ge-0/0/2 disable"}) {
		t.Errorf("enable: %q", got)
	}
	untouched := Interface{Name: "ge-0/0/1"}
	if untouched.Commands(ifaceConfig) != nil {
		t.Error("an interface that owns nothing changes something")
	}
}

func TestInterfaceRemoveCommands(t *testing.T) {
	i := Interface{Name: "ge-0/0/1", MTU: 1514, Mode: "trunk", AllowedVLANs: []string{"v10"}}
	want := []string{
		"delete interfaces ge-0/0/1 mtu",
		"delete interfaces ge-0/0/1 unit 0 family ethernet-switching interface-mode",
		"delete interfaces ge-0/0/1 unit 0 family ethernet-switching vlan members v10",
	}
	if got := i.RemoveCommands(ifaceConfig); !slices.Equal(got, want) {
		t.Errorf("RemoveCommands:\n%q\nwant\n%q", got, want)
	}
}

func TestInterfaceGuard(t *testing.T) {
	off := ptr(false)
	if err := (Interface{Name: "ge-0/0/3", Enabled: off}).Guard(ifaceConfig, "192.168.122.10"); err == nil {
		t.Error("disabled the interface Conn3x connects through")
	}
	if err := (Interface{Name: "fxp0", Enabled: off}).Guard(ifaceConfig, "10.9.9.9"); err == nil {
		t.Error("disabled fxp0")
	}
	if err := (Interface{Name: "ge-0/0/1", Enabled: off}).Guard(ifaceConfig, "192.168.122.10"); err != nil {
		t.Errorf("another interface: %v", err)
	}
}

func TestInterfaceValidate(t *testing.T) {
	for name, i := range map[string]Interface{
		"name":            {Name: "Ethernet1"},
		"mode":            {Name: "ge-0/0/1", Mode: "hybrid"},
		"switching on lo": {Name: "lo0", Mode: "access"},
		"access on trunk": {Name: "ge-0/0/1", Mode: "trunk", AccessVLAN: "10"},
		"empty trunk":     {Name: "ge-0/0/1", Mode: "trunk", AllowedVLANs: []string{}},
		"bad vlan":        {Name: "ge-0/0/1", AccessVLAN: "10 20"},
		"quote":           {Name: "ge-0/0/1", Description: ptr(`a "b"`)},
		"mtu":             {Name: "ge-0/0/1", MTU: 20000},
	} {
		if i.Validate() == nil {
			t.Errorf("%s: Validate passed", name)
		}
	}
	if err := (Interface{Name: "ae0", Mode: "trunk", AllowedVLANs: []string{"users", "20-22"}}).Validate(); err != nil {
		t.Errorf("a trunk on ae0: %v", err)
	}
}
