// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package netroute is a static route as a CLI device's running
// configuration holds it, in "ip route" and "ipv6 route" lines, shared by
// the IOS and EOS steps.
package netroute

import (
	"errors"
	"fmt"
	"math/bits"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// Form is how a device writes an IPv4 route's network.
type Form int

const (
	DottedMask Form = iota // ip route 10.20.0.0 255.255.0.0, as IOS does
	CIDR                   // ip route 10.20.0.0/16, as EOS does
)

// StaticRoute is one static route, owned whole: the next hops listed, each
// at Distance, and no others for the prefix.
type StaticRoute struct {
	Prefix   string   // such as 10.20.0.0/16 or 2001:db8:20::/48
	NextHops []string // addresses of the prefix's family
	Distance int      // 1 to 255; 0 is the default, 1
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

func (r StaticRoute) distance() int {
	if r.Distance == 0 {
		return 1
	}
	return r.Distance
}

// hop is one route line: the network it's for, where it goes, and at
// what distance. to is the next hop's address as Go writes it, so case and
// zero compression don't matter, or the line's own words for a route out
// an interface.
type hop struct {
	line     string
	prefix   netip.Prefix
	to       string
	distance int
}

// parseLine reads an "ip route" or "ipv6 route" line in either form. A
// line in a VRF, or one it can't read, isn't a route of the global table.
func parseLine(line string) (hop, bool) {
	f := strings.Fields(line)
	if len(f) < 4 || f[1] != "route" || (f[0] != "ip" && f[0] != "ipv6") {
		return hop{}, false
	}
	h := hop{line: line, distance: 1}
	i := 2
	if p, err := netip.ParsePrefix(f[i]); err == nil {
		h.prefix, i = p.Masked(), i+1
	} else if a, err := netip.ParseAddr(f[i]); err == nil && a.Is4() && len(f) > i+2 {
		m, err := netip.ParseAddr(f[i+1])
		if err != nil || !m.Is4() {
			return hop{}, false
		}
		b := m.As4()
		n := bits.LeadingZeros32(^(uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])))
		h.prefix, i = netip.PrefixFrom(a, n).Masked(), i+2
	} else {
		return hop{}, false
	}
	if i >= len(f) {
		return hop{}, false
	}
	if a, err := netip.ParseAddr(f[i]); err == nil {
		h.to, i = a.String(), i+1
	} else {
		// Out an interface, perhaps with a gateway after it.
		h.to, i = f[i], i+1
		if i < len(f) {
			if _, err := netip.ParseAddr(f[i]); err == nil {
				h.to, i = h.to+" "+f[i], i+1
			}
		}
	}
	if i < len(f) {
		if d, err := strconv.Atoi(f[i]); err == nil {
			h.distance = d
		}
	}
	return h, true
}

// hops are the route's lines among a running configuration's top-level
// lines.
func (r StaticRoute) hops(top []string) []hop {
	want, err := netip.ParsePrefix(r.Prefix)
	if err != nil {
		return nil
	}
	var hs []hop
	for _, l := range top {
		if h, ok := parseLine(l); ok && h.prefix == want.Masked() {
			hs = append(hs, h)
		}
	}
	return hs
}

func (r StaticRoute) line(form Form, nextHop string) string {
	p, _ := netip.ParsePrefix(r.Prefix)
	head := "ipv6 route " + p.String()
	if p.Addr().Is4() {
		head = "ip route " + p.String()
		if form == DottedMask {
			mask := netip.AddrFrom4([4]byte{})
			if p.Bits() > 0 {
				v := ^uint32(0) << (32 - p.Bits())
				mask = netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
			}
			head = "ip route " + p.Addr().String() + " " + mask.String()
		}
	}
	if r.distance() == 1 {
		return head + " " + nextHop
	}
	return fmt.Sprintf("%s %s %d", head, nextHop, r.distance())
}

func canonical(addr string) string {
	if a, err := netip.ParseAddr(addr); err == nil {
		return a.String()
	}
	return addr
}

// Commands make the route r's among top, the configuration's top-level
// lines, or nil. Wanted next hops go in first and the others come out
// after: a device that applies each line as it comes, as IOS does, keeps
// a next hop that's in both lists, and the prefix keeps a route.
func (r StaticRoute) Commands(top []string, form Form) []string {
	have := r.hops(top)
	var add, del []string
	wanted := make([]string, len(r.NextHops))
	for i, w := range r.NextHops {
		wanted[i] = canonical(w)
		j := slices.IndexFunc(have, func(h hop) bool { return h.to == wanted[i] })
		if j < 0 || have[j].distance != r.distance() {
			add = append(add, r.line(form, w))
		}
	}
	for _, h := range have {
		if !slices.Contains(wanted, h.to) {
			del = append(del, "no "+h.line)
		}
	}
	return append(add, del...)
}

// RemoveCommands take every next hop of the route away, as the device
// wrote each line.
func (r StaticRoute) RemoveCommands(top []string) []string {
	var cmds []string
	for _, h := range r.hops(top) {
		cmds = append(cmds, "no "+h.line)
	}
	return cmds
}
