// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package eos

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

// addrs is an interface's addresses as running-config holds them: the
// primary IPv4 address, the secondary ones, and the IPv6 ones. Each is
// written as netip writes it, so case and zero compression don't matter.
type addrs struct {
	primary string
	second  []string
	v6      []string
}

func readAddrs(lines []string) addrs {
	var a addrs
	for _, l := range lines {
		f := strings.Fields(l)
		switch {
		case len(f) >= 3 && f[0] == "ip" && f[1] == "address":
			p, err := netip.ParsePrefix(f[2])
			if err != nil {
				continue
			}
			if len(f) == 4 && f[3] == "secondary" {
				a.second = append(a.second, p.String())
			} else if len(f) == 3 {
				a.primary = p.String()
			}
		case len(f) == 3 && f[0] == "ipv6" && f[1] == "address":
			if p, err := netip.ParsePrefix(f[2]); err == nil {
				a.v6 = append(a.v6, p.String())
			}
		}
	}
	return a
}

// wantAddrs is i.Addresses split the same way: the first IPv4 address is
// the primary, and the rest are secondaries.
func (i Interface) wantAddrs() addrs {
	var a addrs
	for _, s := range i.Addresses {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			continue
		}
		switch {
		case p.Addr().Is6():
			a.v6 = append(a.v6, p.String())
		case a.primary == "":
			a.primary = p.String()
		default:
			a.second = append(a.second, p.String())
		}
	}
	return a
}

func sameSet(a, b []string) bool {
	return len(a) == len(b) && !slices.ContainsFunc(a, func(s string) bool { return !slices.Contains(b, s) })
}

func (i Interface) addrsInSync(lines []string) bool {
	if i.Addresses == nil {
		return true
	}
	have, want := readAddrs(lines), i.wantAddrs()
	return have.primary == want.primary && sameSet(have.second, want.second) && sameSet(have.v6, want.v6)
}

// addrCommands bring the interface's addresses to i's: new ones first,
// then the ones going, so an address in both never leaves. A new primary
// replaces the old one in one command, and EOS needs a primary before a
// secondary, so the primary goes first.
func (i Interface) addrCommands(lines []string) []string {
	if i.Addresses == nil || i.addrsInSync(lines) {
		return nil
	}
	have, want := readAddrs(lines), i.wantAddrs()
	var add, del []string
	if want.primary != "" && want.primary != have.primary {
		add = append(add, "ip address "+want.primary)
	}
	for _, s := range want.second {
		if !slices.Contains(have.second, s) {
			add = append(add, "ip address "+s+" secondary")
		}
	}
	for _, s := range want.v6 {
		if !slices.Contains(have.v6, s) {
			add = append(add, "ipv6 address "+s)
		}
	}
	for _, s := range have.second {
		if !slices.Contains(want.second, s) {
			del = append(del, "no ip address "+s+" secondary")
		}
	}
	for _, s := range have.v6 {
		if !slices.Contains(want.v6, s) {
			del = append(del, "no ipv6 address "+s)
		}
	}
	if want.primary == "" && have.primary != "" {
		del = append(del, "no ip address "+have.primary)
	}
	return append(add, del...)
}

// addrRemoveCommands take away the addresses i owns, secondaries before
// the primary.
func (i Interface) addrRemoveCommands(lines []string) []string {
	if i.Addresses == nil {
		return nil
	}
	have, want := readAddrs(lines), i.wantAddrs()
	var cmds []string
	for _, s := range want.second {
		if slices.Contains(have.second, s) {
			cmds = append(cmds, "no ip address "+s+" secondary")
		}
	}
	for _, s := range want.v6 {
		if slices.Contains(have.v6, s) {
			cmds = append(cmds, "no ipv6 address "+s)
		}
	}
	if want.primary != "" && have.primary == want.primary {
		cmds = append(cmds, "no ip address "+want.primary)
	}
	return cmds
}

// addrGuard refuses taking off the address Conn3x connects to, and putting
// an address on a switched port, which EOS needs "no switchport" for.
func (i Interface) addrGuard(lines []string, address string) error {
	if i.Addresses == nil {
		return nil
	}
	if (strings.HasPrefix(i.Name, "Ethernet") || strings.HasPrefix(i.Name, "Port-Channel")) && !slices.Contains(lines, "no switchport") {
		return fmt.Errorf("%s is a switched port, which can't take an address. Make it a routed port with \"no switchport\" first, for example with an eos_config step before this one; Conn3x doesn't do it for you, since it takes the port out of its VLANs", i.Name)
	}
	at, err := netip.ParseAddr(address)
	if err != nil {
		return nil
	}
	have := readAddrs(lines)
	want := i.wantAddrs()
	for _, s := range append(append([]string{have.primary}, have.second...), have.v6...) {
		p, err := netip.ParsePrefix(s)
		if err != nil || p.Addr() != at {
			continue
		}
		if !slices.Contains(append(append([]string{want.primary}, want.second...), want.v6...), s) {
			return fmt.Errorf("Conn3x reaches this switch at %s, which is %s's address %s, so taking it off would cut it off. Change it from another address, or by hand", address, i.Name, s)
		}
	}
	return nil
}
