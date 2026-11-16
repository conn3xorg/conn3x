// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package junos

import (
	"slices"
	"strings"
	"testing"
)

// An access port owns one member: the others go, and a description with
// no space is written bare.
func TestInterfaceAccessAndDisable(t *testing.T) {
	i := Interface{Name: "ge-0/0/1", Description: ptr("uplink"), Enabled: ptr(false), Mode: "access", AccessVLAN: "v10"}
	if err := i.Validate(); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"delete interfaces ge-0/0/1 description",
		"set interfaces ge-0/0/1 description uplink",
		"set interfaces ge-0/0/1 disable",
		"delete interfaces ge-0/0/1 unit 0 family ethernet-switching interface-mode",
		"set interfaces ge-0/0/1 unit 0 family ethernet-switching interface-mode access",
		"delete interfaces ge-0/0/1 unit 0 family ethernet-switching vlan members 20",
	}
	if got := i.Commands(ifaceConfig); !slices.Equal(got, want) {
		t.Errorf("Commands:\n%q\nwant\n%q", got, want)
	}
	// Nothing it owns is there yet: nothing to remove.
	if got := (Interface{Name: "ge-0/0/9", Description: ptr("x"), AllowedVLANs: []string{"30"}, Mode: "trunk"}).RemoveCommands(ifaceConfig); got != nil {
		t.Errorf("remove: %q", got)
	}
	// Enabling, or an interface without the address, is never refused.
	if err := (Interface{Name: "fxp0", Enabled: ptr(true)}).Guard(ifaceConfig, "10.0.0.1"); err != nil {
		t.Error(err)
	}
	for name, bad := range map[string]Interface{
		"trunk on access": {Name: "ge-0/0/1", Mode: "access", AllowedVLANs: []string{"10"}},
		"empty":           {Name: "ge-0/0/1", Description: ptr("")},
		"control":         {Name: "ge-0/0/1", Description: ptr("a\tb")},
	} {
		if bad.Validate() == nil {
			t.Errorf("%s passed", name)
		}
	}
}

func TestStaticRouteMore(t *testing.T) {
	v6 := StaticRoute{Prefix: "2001:db8:20::/48", NextHops: []string{"2001:db8::1"}}
	if err := v6.Validate(); err != nil {
		t.Fatal(err)
	}
	if got := v6.Commands(""); !slices.Equal(got, []string{"set routing-options rib inet6.0 static route 2001:db8:20::/48 next-hop 2001:db8::1"}) {
		t.Errorf("v6: %q", got)
	}
	if v6.RemoveCommands("set system host-name sw1\n") != nil {
		t.Error("removed a route that isn't there")
	}
	for want, bad := range map[string]StaticRoute{
		"must be a network":     {Prefix: "10.20.0.0", NextHops: []string{"10.0.0.1"}},
		"must be an address":    {Prefix: "2001:db8::/32", NextHops: []string{"fe80::1%eth0"}},
		"isn't the same family": {Prefix: "10.0.0.0/8", NextHops: []string{"2001:db8::1"}},
	} {
		if err := bad.Validate(); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%+v: %v, want %q", bad, err, want)
		}
	}
}
