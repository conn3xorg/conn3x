// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ios

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// StaticRoute is one static route, which ios_static_route owns whole: the
// next hops listed, each at Distance, and no others for the prefix.
type StaticRoute struct {
	Prefix   string   // such as 10.20.0.0/16 or 2001:db8:20::/48
	NextHops []string // addresses of the prefix's family
	Distance int      // 1 to 255; 0 is IOS's default, 1
}

// Validate checks a route before anything reaches the device.
func (r StaticRoute) Validate() error {
	p, err := netip.ParsePrefix(r.Prefix)
	if err != nil {
		return fmt.Errorf("prefix %q must be a network with its length, such as 10.20.0.0/16", r.Prefix)
	}
	if p.Masked() != p {
		return fmt.Errorf("prefix %q has host bits set; the network is %s", r.Prefix, p.Masked())
	}
	if len(r.NextHops) == 0 {
		return errors.New("next_hops must list at least one address")
	}
	for _, h := range r.NextHops {
		a, err := netip.ParseAddr(h)
		if err != nil || a.Zone() != "" {
			return fmt.Errorf("next hop %q must be an address, such as 192.0.2.1", h)
		}
		if a.Is4() != p.Addr().Is4() {
			return fmt.Errorf("next hop %s isn't the same family as %s", h, r.Prefix)
		}
	}
	if r.Distance < 0 || r.Distance > 255 {
		return fmt.Errorf("distance must be from 1 to 255, not %d", r.Distance)
	}
	return nil
}

// head is the start of the route's lines as show running-config prints
// them: "ip route 10.20.0.0 255.255.0.0" for IPv4, with a dotted mask, and
// "ipv6 route 2001:db8:20::/48" for IPv6.
func (r StaticRoute) head() string {
	p, err := netip.ParsePrefix(r.Prefix)
	if err != nil {
		return ""
	}
	if p.Addr().Is6() {
		return "ipv6 route " + p.String()
	}
	mask := netip.AddrFrom4([4]byte(maskBytes(p.Bits())))
	return "ip route " + p.Addr().String() + " " + mask.String()
}

func maskBytes(bits int) []byte {
	m := make([]byte, 4)
	for i := range m {
		switch {
		case bits >= 8:
			m[i], bits = 0xff, bits-8
		case bits > 0:
			m[i], bits = byte(0xff<<(8-bits)), 0
		}
	}
	return m
}

func (r StaticRoute) distance() int {
	if r.Distance == 0 {
		return 1
	}
	return r.Distance
}

// hop is one of the route's lines: its next hop, which is an address or,
// for a route out an interface, the interface's name, and its distance.
type hop struct {
	line, to string
	distance int
}

// hops are the route's lines in config. Options after the distance, such
// as name or tag, are kept with the line but don't change what it is.
func (r StaticRoute) hops(config string) []hop {
	head := r.head() + " "
	var hs []hop
	for _, k := range parse(config).kids {
		rest, ok := strings.CutPrefix(k.text, head)
		if !ok {
			continue
		}
		f := strings.Fields(rest)
		if len(f) == 0 {
			continue
		}
		h := hop{line: k.text, to: f[0], distance: 1}
		// A route out an interface can name a gateway after it.
		if _, err := netip.ParseAddr(f[0]); err != nil && len(f) > 1 {
			if _, err := netip.ParseAddr(f[1]); err == nil {
				h.to, f = f[0]+" "+f[1], f[1:]
			}
		}
		if len(f) > 1 {
			if d, err := strconv.Atoi(f[1]); err == nil {
				h.distance = d
			}
		}
		hs = append(hs, h)
	}
	return hs
}

func (r StaticRoute) want(h string) string {
	if r.distance() == 1 {
		return r.head() + " " + h
	}
	return fmt.Sprintf("%s %s %d", r.head(), h, r.distance())
}

// InSync reports whether the device has the route as r has it.
func (r StaticRoute) InSync(config string) bool { return r.Commands(config) == nil }

// Commands make the route r's, or nil. IOS applies each line as it comes,
// so the wanted next hops go in first and the others come out after: a
// next hop in both the old and the new route never leaves it, and the
// prefix always has a route.
func (r StaticRoute) Commands(config string) []string {
	have := r.hops(config)
	var add, del []string
	for _, w := range r.NextHops {
		i := slices.IndexFunc(have, func(h hop) bool { return h.to == w })
		if i < 0 || have[i].distance != r.distance() {
			add = append(add, r.want(w))
		}
	}
	for _, h := range have {
		if !slices.Contains(r.NextHops, h.to) {
			del = append(del, "no "+h.line)
		}
	}
	return append(add, del...)
}

// RemoveCommands take the route away, every next hop of it, for on_remove
// = "delete".
func (r StaticRoute) RemoveCommands(config string) []string {
	var cmds []string
	for _, h := range r.hops(config) {
		cmds = append(cmds, "no "+h.line)
	}
	return cmds
}
