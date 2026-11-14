// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package junos

import (
	"slices"
	"testing"
)

// The configuration as vJunos-switch 26.2R1.7 prints it with display set.
const routes = `set routing-options rib inet6.0 static route 2001:db8:20::/48 next-hop 2001:db8::1
set routing-options static route 10.20.0.0/16 next-hop 192.0.2.1
set routing-options static route 10.20.0.0/16 next-hop 192.0.2.2
set routing-options static route 10.20.0.0/16 preference 10
set routing-options static route 10.30.0.0/16 discard
`

func TestStaticRoute(t *testing.T) {
	ten := int64(10)
	r := StaticRoute{Prefix: "10.20.0.0/16", NextHops: []string{"192.0.2.1", "192.0.2.2"}, Preference: &ten}
	if err := r.Validate(); err != nil || !r.InSync(routes) {
		t.Fatalf("validate %v, in sync %v", err, r.InSync(routes))
	}
	one := StaticRoute{Prefix: "10.20.0.0/16", NextHops: []string{"192.0.2.1"}}
	if got := one.Commands(routes); !slices.Equal(got, []string{
		"delete routing-options static route 10.20.0.0/16 next-hop 192.0.2.2",
		"delete routing-options static route 10.20.0.0/16 preference",
	}) {
		t.Errorf("one hop, no preference: %q", got)
	}
	discard := StaticRoute{Prefix: "10.30.0.0/16", NextHops: []string{"192.0.2.1"}}
	if got := discard.Commands(routes); !slices.Equal(got, []string{
		"delete routing-options static route 10.30.0.0/16 discard",
		"set routing-options static route 10.30.0.0/16 next-hop 192.0.2.1",
	}) {
		t.Errorf("discard to a next hop: %q", got)
	}
	v6 := StaticRoute{Prefix: "2001:db8:20::/48", NextHops: []string{"2001:db8::1"}}
	if !v6.InSync(routes) || !slices.Equal(v6.RemoveCommands(routes), []string{"delete routing-options rib inet6.0 static route 2001:db8:20::/48"}) {
		t.Errorf("v6: in sync %v, remove %q", v6.InSync(routes), v6.RemoveCommands(routes))
	}
	big := int64(4294967296)
	for _, bad := range []StaticRoute{
		{Prefix: "10.20.0.1/16", NextHops: []string{"192.0.2.1"}},
		{Prefix: "10.20.0.0/16"},
		{Prefix: "10.20.0.0/16", NextHops: []string{"2001:db8::1"}},
		{Prefix: "10.20.0.0/16", NextHops: []string{"192.0.2.1"}, Preference: &big},
	} {
		if bad.Validate() == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}
