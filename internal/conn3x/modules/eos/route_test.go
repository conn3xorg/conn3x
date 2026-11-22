// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package eos

import (
	"slices"
	"testing"

	"github.com/opentofu/opentofu/internal/conn3x/modules/netroute"
)

const routes = `hostname leaf1
!
ip route 0.0.0.0/0 192.0.2.254
ip route 10.20.0.0/16 192.0.2.1 name core
ip route 10.20.0.0/16 192.0.2.2 5
ip route 10.30.0.0 255.255.255.0 Null0
ip route vrf blue 0.0.0.0/0 198.51.100.1
ipv6 route 2001:db8:20::/48 2001:db8::1
!
`

func TestStaticRouteCommands(t *testing.T) {
	for name, tc := range map[string]struct {
		r    StaticRoute
		want []string
	}{
		"default route in sync": {StaticRoute{netroute.StaticRoute{Prefix: "0.0.0.0/0", NextHops: []string{"192.0.2.254"}}}, nil},
		"name kept, distances match": {StaticRoute{netroute.StaticRoute{Prefix: "10.20.0.0/16", NextHops: []string{"192.0.2.1", "192.0.2.2"}, Distance: 5}},
			[]string{"ip route 10.20.0.0/16 192.0.2.1 5"}},
		"a hop goes, after the new one": {StaticRoute{netroute.StaticRoute{Prefix: "10.20.0.0/16", NextHops: []string{"192.0.2.1", "192.0.2.3"}}},
			[]string{"ip route 10.20.0.0/16 192.0.2.3", "no ip route 10.20.0.0/16 192.0.2.2 5"}},
		"a dotted mask is read too": {StaticRoute{netroute.StaticRoute{Prefix: "10.30.0.0/24", NextHops: []string{"192.0.2.9"}}},
			[]string{"ip route 10.30.0.0/24 192.0.2.9", "no ip route 10.30.0.0 255.255.255.0 Null0"}},
		"new, with a distance": {StaticRoute{netroute.StaticRoute{Prefix: "172.16.0.0/12", NextHops: []string{"192.0.2.1"}, Distance: 200}},
			[]string{"ip route 172.16.0.0/12 192.0.2.1 200"}},
		"ipv6 in sync": {StaticRoute{netroute.StaticRoute{Prefix: "2001:db8:20::/48", NextHops: []string{"2001:db8::1"}}}, nil},
	} {
		if got := tc.r.Commands(routes); !slices.Equal(got, tc.want) {
			t.Errorf("%s: Commands = %q, want %q", name, got, tc.want)
		}
		if got := tc.r.InSync(routes); got != (tc.want == nil) {
			t.Errorf("%s: InSync = %v", name, got)
		}
	}
}

func TestStaticRouteRemoveCommands(t *testing.T) {
	r := StaticRoute{netroute.StaticRoute{Prefix: "10.20.0.0/16", NextHops: []string{"192.0.2.1"}}}
	want := []string{"no ip route 10.20.0.0/16 192.0.2.1 name core", "no ip route 10.20.0.0/16 192.0.2.2 5"}
	if got := r.RemoveCommands(routes); !slices.Equal(got, want) {
		t.Errorf("RemoveCommands = %q, want %q", got, want)
	}
}

func TestStaticRouteValidate(t *testing.T) {
	if err := (StaticRoute{netroute.StaticRoute{Prefix: "0.0.0.0/0", NextHops: []string{"192.0.2.1"}}}).Validate(); err != nil {
		t.Error(err)
	}
	for _, bad := range []StaticRoute{
		{Prefix: "10.0.0.1/8", NextHops: []string{"192.0.2.1"}},
		{Prefix: "10.0.0.0/8"},
		{Prefix: "10.0.0.0/8", NextHops: []string{"2001:db8::1"}},
		{Prefix: "10.0.0.0/8", NextHops: []string{"192.0.2.1"}, Distance: 256},
	} {
		if err := bad.Validate(); err == nil {
			t.Errorf("%+v: no error", bad)
		}
	}
}
