// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package eos

import (
	"slices"
	"strings"
	"testing"
)

const ifRunning = `! Command: show running-config
interface Ethernet1
   description old
   switchport mode trunk
   switchport trunk allowed vlan 10,20
!
interface Ethernet2
   shutdown
!
interface Management0
   ip address 10.88.0.50/24
!
`

func ptr[T any](v T) *T { return &v }

func TestInterfaceCommands(t *testing.T) {
	for name, tc := range map[string]struct {
		i    Interface
		want []string // nil: in sync
	}{
		"in sync":           {Interface{Name: "Ethernet1", Description: ptr("old"), Mode: "trunk", AllowedVLANs: []int{20, 10}}, nil},
		"new description":   {Interface{Name: "Ethernet1", Description: ptr("to spine1")}, []string{"interface Ethernet1", "description to spine1"}},
		"more vlans":        {Interface{Name: "Ethernet1", AllowedVLANs: []int{10, 20, 21, 22}}, []string{"interface Ethernet1", "switchport trunk allowed vlan 10,20-22"}},
		"trunk to access":   {Interface{Name: "Ethernet1", Mode: "access", AccessVLAN: 30}, []string{"interface Ethernet1", "no switchport mode trunk", "switchport access vlan 30"}},
		"enable":            {Interface{Name: "Ethernet2", Enabled: ptr(true)}, []string{"interface Ethernet2", "no shutdown"}},
		"already enabled":   {Interface{Name: "Ethernet1", Enabled: ptr(true)}, nil},
		"disable":           {Interface{Name: "Ethernet1", Enabled: ptr(false), MTU: 9214}, []string{"interface Ethernet1", "shutdown", "mtu 9214"}},
		"new loopback":      {Interface{Name: "Loopback3", Description: ptr("router id")}, []string{"interface Loopback3", "description router id"}},
		"access vlan 1 too": {Interface{Name: "Ethernet2", AccessVLAN: 1}, nil},
	} {
		if got := tc.i.Commands(ifRunning); !slices.Equal(got, tc.want) {
			t.Errorf("%s: commands %q, want %q", name, got, tc.want)
		}
		if got := tc.i.InSync(ifRunning); got != (tc.want == nil) {
			t.Errorf("%s: in sync = %v", name, got)
		}
	}
}

func TestInterfaceRemoveCommands(t *testing.T) {
	i := Interface{Name: "Ethernet1", Description: ptr("old"), Mode: "trunk", AllowedVLANs: []int{10, 20}}
	want := []string{"interface Ethernet1", "no description old", "no switchport mode trunk", "no switchport trunk allowed vlan 10,20"}
	if got := i.RemoveCommands(ifRunning); !slices.Equal(got, want) {
		t.Errorf("got %q", got)
	}
	if got := (Interface{Name: "Ethernet1", Description: ptr("someone else's")}).RemoveCommands(ifRunning); got != nil {
		t.Errorf("removed a description it didn't set: %q", got)
	}
}

func TestInterfaceValidate(t *testing.T) {
	for want, i := range map[string]Interface{
		"not an interface name":           {Name: "eth1"},
		"switchport settings":             {Name: "Loopback0", Mode: "trunk"},
		"access_vlan is for mode":         {Name: "Ethernet1", Mode: "trunk", AccessVLAN: 10},
		"allowed_vlans is for mode":       {Name: "Ethernet1", Mode: "access", AllowedVLANs: []int{10}},
		"between 1 and 4094":              {Name: "Ethernet1", AllowedVLANs: []int{5000}},
		"mtu must be between":             {Name: "Ethernet1", MTU: 20000},
		"must be one line":                {Name: "Ethernet1", Description: ptr("a\nb")},
		"must name at least one VLAN":     {Name: "Ethernet1", AllowedVLANs: []int{}},
		"mode must be \"access\" or \"tr": {Name: "Ethernet1", Mode: "routed"},
	} {
		if err := i.Validate(); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%+v: err = %v, want %q", i, err, want)
		}
	}
	if err := (Interface{Name: "Ethernet1/2", Description: ptr("ok"), Mode: "access", AccessVLAN: 10, MTU: 1500}).Validate(); err != nil {
		t.Error(err)
	}
}

// Shutting down the interface Conn3x connects through is refused.
func TestInterfaceGuard(t *testing.T) {
	off := Interface{Name: "Management0", Enabled: ptr(false)}
	if err := off.Guard(ifRunning, "10.88.0.50"); err == nil || !strings.Contains(err.Error(), "cut it off") {
		t.Errorf("err = %v", err)
	}
	if err := off.Guard(ifRunning, "10.88.0.51"); err != nil {
		t.Errorf("another address: %v", err)
	}
	if err := (Interface{Name: "Management0", Description: ptr("mgmt")}).Guard(ifRunning, "10.88.0.50"); err != nil {
		t.Errorf("a description change: %v", err)
	}
}
