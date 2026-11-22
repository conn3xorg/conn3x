// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ios

import (
	"slices"
	"testing"

	"github.com/opentofu/opentofu/internal/conn3x/modules/netroute"
)

const routes = `hostname r1
!
ip route 0.0.0.0 0.0.0.0 192.0.2.254
ip route 10.20.0.0 255.255.0.0 192.0.2.1 name core
ip route 10.20.0.0 255.255.0.0 192.0.2.2 5
ip route 10.30.0.0 255.255.255.0 Null0
ip route vrf blue 0.0.0.0 0.0.0.0 198.51.100.1
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
			[]string{"ip route 10.20.0.0 255.255.0.0 192.0.2.1 5"}},
		"a hop goes, after the new one": {StaticRoute{netroute.StaticRoute{Prefix: "10.20.0.0/16", NextHops: []string{"192.0.2.1", "192.0.2.3"}}},
			[]string{"ip route 10.20.0.0 255.255.0.0 192.0.2.3", "no ip route 10.20.0.0 255.255.0.0 192.0.2.2 5"}},
		"an interface hop is replaced": {StaticRoute{netroute.StaticRoute{Prefix: "10.30.0.0/24", NextHops: []string{"192.0.2.9"}}},
			[]string{"ip route 10.30.0.0 255.255.255.0 192.0.2.9", "no ip route 10.30.0.0 255.255.255.0 Null0"}},
		"vrf routes aren't this one": {StaticRoute{netroute.StaticRoute{Prefix: "0.0.0.0/0", NextHops: []string{"192.0.2.254"}, Distance: 1}}, nil},
		"new, with a distance": {StaticRoute{netroute.StaticRoute{Prefix: "172.16.0.0/12", NextHops: []string{"192.0.2.1"}, Distance: 200}},
			[]string{"ip route 172.16.0.0 255.240.0.0 192.0.2.1 200"}},
		"ipv6 in sync":  {StaticRoute{netroute.StaticRoute{Prefix: "2001:db8:20::/48", NextHops: []string{"2001:db8::1"}}}, nil},
		"ipv6 new hop":  {StaticRoute{netroute.StaticRoute{Prefix: "2001:db8:20::/48", NextHops: []string{"2001:db8::2"}}}, []string{"ipv6 route 2001:db8:20::/48 2001:db8::2", "no ipv6 route 2001:db8:20::/48 2001:db8::1"}},
		"odd mask bits": {StaticRoute{netroute.StaticRoute{Prefix: "10.0.0.0/9", NextHops: []string{"192.0.2.1"}}}, []string{"ip route 10.0.0.0 255.128.0.0 192.0.2.1"}},
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
	want := []string{"no ip route 10.20.0.0 255.255.0.0 192.0.2.1 name core", "no ip route 10.20.0.0 255.255.0.0 192.0.2.2 5"}
	if got := r.RemoveCommands(routes); !slices.Equal(got, want) {
		t.Errorf("RemoveCommands = %q, want %q", got, want)
	}
	if got := (StaticRoute{netroute.StaticRoute{Prefix: "10.99.0.0/16", NextHops: []string{"192.0.2.1"}}}).RemoveCommands(routes); got != nil {
		t.Errorf("missing route: %q", got)
	}
}

func TestStaticRouteValidate(t *testing.T) {
	for _, ok := range []StaticRoute{
		{Prefix: "0.0.0.0/0", NextHops: []string{"192.0.2.1"}},
		{Prefix: "2001:db8::/32", NextHops: []string{"2001:db8::1"}, Distance: 255},
	} {
		if err := ok.Validate(); err != nil {
			t.Errorf("%+v: %v", ok, err)
		}
	}
	for _, bad := range []StaticRoute{
		{Prefix: "10.0.0.1/8", NextHops: []string{"192.0.2.1"}},
		{Prefix: "10.0.0.0", NextHops: []string{"192.0.2.1"}},
		{Prefix: "10.0.0.0/8"},
		{Prefix: "10.0.0.0/8", NextHops: []string{"2001:db8::1"}},
		{Prefix: "10.0.0.0/8", NextHops: []string{"GigabitEthernet1"}},
		{Prefix: "10.0.0.0/8", NextHops: []string{"192.0.2.1"}, Distance: 256},
	} {
		if err := bad.Validate(); err == nil {
			t.Errorf("%+v: no error", bad)
		}
	}
}

// IOS prints IPv6 addresses in upper case, as cisco.ios's tests show, so
// lines are matched on what they parse to, not on their text.
func TestStaticRouteIPv6UpperCase(t *testing.T) {
	running := "ipv6 route 2001:DB8:20::/48 2001:DB8::1\nipv6 route 2001:DB8:20::/48 2001:DB8::9 name stale\n"
	r := StaticRoute{netroute.StaticRoute{Prefix: "2001:db8:20::/48", NextHops: []string{"2001:db8::1"}}}
	if got, want := r.Commands(running), []string{"no ipv6 route 2001:DB8:20::/48 2001:DB8::9 name stale"}; !slices.Equal(got, want) {
		t.Errorf("Commands = %q, want %q", got, want)
	}
	in := StaticRoute{netroute.StaticRoute{Prefix: "2001:db8:20::/48", NextHops: []string{"2001:db8::1", "2001:db8:0::9"}}}
	if !in.InSync(running) {
		t.Errorf("both hops, one written with a zero: %q", in.Commands(running))
	}
	if got := r.RemoveCommands(running); len(got) != 2 {
		t.Errorf("RemoveCommands = %q", got)
	}
}
