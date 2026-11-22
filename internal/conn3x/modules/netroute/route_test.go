// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package netroute

import (
	"strconv"
	"testing"
)

func TestParseLine(t *testing.T) {
	for line, want := range map[string]string{
		"ip route 10.20.0.0 255.255.0.0 192.0.2.1":           "10.20.0.0/16 192.0.2.1 1",
		"ip route 10.20.0.0/16 192.0.2.1 5":                  "10.20.0.0/16 192.0.2.1 5",
		"ip route 0.0.0.0 0.0.0.0 192.0.2.254":               "0.0.0.0/0 192.0.2.254 1",
		"ip route 10.30.0.0 255.255.255.0 Null0":             "10.30.0.0/24 Null0 1",
		"ip route 10.30.0.0 255.255.255.0 Gi1 192.0.2.1 10":  "10.30.0.0/24 Gi1 192.0.2.1 10",
		"ipv6 route 2001:DB8:0:3::/64 2001:DB8:0:3::2 tag 1": "2001:db8:0:3::/64 2001:db8:0:3::2 1",
		"ip route 10.20.0.0 255.255.0.0 192.0.2.1 name core": "10.20.0.0/16 192.0.2.1 1",
	} {
		h, ok := parseLine(line)
		if got := h.prefix.String() + " " + h.to + " " + strconv.Itoa(h.distance); !ok || got != want {
			t.Errorf("%q: %q, %v; want %q", line, got, ok, want)
		}
	}
	for _, line := range []string{"ip route vrf blue 0.0.0.0 0.0.0.0 192.0.2.1", "ip route static bfd x", "ip routing", "ipv6 route"} {
		if _, ok := parseLine(line); ok {
			t.Errorf("%q read as a route", line)
		}
	}
}

func TestFormsAndOrder(t *testing.T) {
	top := []string{"ip route 10.20.0.0/16 192.0.2.2"}
	r := StaticRoute{Prefix: "10.20.0.0/16", NextHops: []string{"192.0.2.3"}}
	for form, want := range map[Form][]string{
		DottedMask: {"ip route 10.20.0.0 255.255.0.0 192.0.2.3", "no ip route 10.20.0.0/16 192.0.2.2"},
		CIDR:       {"ip route 10.20.0.0/16 192.0.2.3", "no ip route 10.20.0.0/16 192.0.2.2"},
	} {
		got := r.Commands(top, form)
		if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
			t.Errorf("form %d: %q, want %q", form, got, want)
		}
	}
}
