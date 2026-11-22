// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package junos

import (
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// addrPath is where a family's addresses live on the interface's unit, as
// in "interfaces irb unit 10 family inet address".
func (i Interface) addrPath(v6 bool) string {
	fam := "inet"
	if v6 {
		fam = "inet6"
	}
	return i.path() + " unit " + strconv.Itoa(i.Unit) + " family " + fam + " address"
}

// haveAddr is one address line: the address as netip writes it, so case
// and zero compression don't matter, and as the line has it.
type haveAddr struct{ addr, text string }

func (i Interface) haveAddrs(lines []string) []haveAddr {
	var have []haveAddr
	for _, v6 := range []bool{false, true} {
		prefix := "set " + i.addrPath(v6) + " "
		for _, l := range lines {
			rest, ok := strings.CutPrefix(l, prefix)
			if !ok {
				continue
			}
			text := strings.Fields(rest)[0]
			if p, err := netip.ParsePrefix(text); err == nil && slices.IndexFunc(have, func(h haveAddr) bool { return h.text == text }) < 0 {
				have = append(have, haveAddr{p.String(), text})
			}
		}
	}
	return have
}

func (i Interface) wantAddrs() []string {
	var want []string
	for _, a := range i.Addresses {
		if p, err := netip.ParsePrefix(a); err == nil {
			want = append(want, p.String())
		}
	}
	return want
}

// addrCommands bring the unit's addresses to i's: new ones are set first,
// then the ones going are deleted. A commit applies them together, but
// the order still keeps an address in both lists in place throughout.
func (i Interface) addrCommands(lines []string) []string {
	if i.Addresses == nil {
		return nil
	}
	have, want := i.haveAddrs(lines), i.wantAddrs()
	var add, del []string
	for n, w := range want {
		if slices.IndexFunc(have, func(h haveAddr) bool { return h.addr == w }) < 0 {
			p, _ := netip.ParsePrefix(i.Addresses[n])
			add = append(add, "set "+i.addrPath(p.Addr().Is6())+" "+w)
		}
	}
	for _, h := range have {
		if !slices.Contains(want, h.addr) {
			p, _ := netip.ParsePrefix(h.text)
			del = append(del, "delete "+i.addrPath(p.Addr().Is6())+" "+h.text)
		}
	}
	return append(add, del...)
}

// addrRemoveCommands delete the addresses i owns.
func (i Interface) addrRemoveCommands(lines []string) []string {
	if i.Addresses == nil {
		return nil
	}
	want := i.wantAddrs()
	var cmds []string
	for _, h := range i.haveAddrs(lines) {
		if slices.Contains(want, h.addr) {
			p, _ := netip.ParsePrefix(h.text)
			cmds = append(cmds, "delete "+i.addrPath(p.Addr().Is6())+" "+h.text)
		}
	}
	return cmds
}

// addrGuard refuses taking off the address Conn3x connects to.
func (i Interface) addrGuard(lines []string, address string) error {
	if i.Addresses == nil {
		return nil
	}
	at, err := netip.ParseAddr(address)
	if err != nil {
		return nil
	}
	want := i.wantAddrs()
	for _, h := range i.haveAddrs(lines) {
		if p, err := netip.ParsePrefix(h.addr); err == nil && p.Addr() == at && !slices.Contains(want, h.addr) {
			return fmt.Errorf("Conn3x reaches this device at %s, which is %s.%d's address %s, so taking it off would cut it off. Change it from another address, or by hand", address, i.Name, i.Unit, h.text)
		}
	}
	return nil
}
