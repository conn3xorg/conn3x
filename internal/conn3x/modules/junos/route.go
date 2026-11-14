// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package junos

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

// StaticRoute is one static route, which junos_static_route owns whole:
// every statement under it is one of these next hops or its preference.
type StaticRoute struct {
	Prefix     string   // such as 10.20.0.0/16 or 2001:db8:20::/48
	NextHops   []string // addresses of the prefix's family
	Preference *int64   // 0 to 4294967295; nil leaves Junos's default, 5
}

// Validate checks a route before anything reaches the device.
func (r StaticRoute) Validate() error {
	p, err := netip.ParsePrefix(r.Prefix)
	if err != nil {
		return fmt.Errorf("prefix %q must be a network with its length, such as 10.20.0.0/16", r.Prefix)
	}
	// Junos takes 10.20.0.1/16 as a route of its own, beside 10.20.0.0/16.
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
	if r.Preference != nil && (*r.Preference < 0 || *r.Preference > 4294967295) {
		return fmt.Errorf("preference must be from 0 to 4294967295, not %d", *r.Preference)
	}
	return nil
}

// path is where the route lives: IPv6 routes are in the inet6.0 table.
func (r StaticRoute) path() string {
	if p, err := netip.ParsePrefix(r.Prefix); err == nil && p.Addr().Is6() {
		return "routing-options rib inet6.0 static route " + r.Prefix
	}
	return "routing-options static route " + r.Prefix
}

// Config owns the route as a block. Junos keeps next hops as a list and
// preference as one value, so deleting a line takes just that line.
func (r StaticRoute) Config() Config {
	var lines []string
	for _, h := range r.NextHops {
		lines = append(lines, "set "+r.path()+" next-hop "+h)
	}
	if r.Preference != nil {
		lines = append(lines, fmt.Sprintf("set %s preference %d", r.path(), *r.Preference))
	}
	return Config{Prefix: r.path(), Lines: lines, Match: MatchBlock}
}

// InSync reports whether the device has the route as r has it.
func (r StaticRoute) InSync(config string) bool { return r.Config().InSync(config) }

// Commands are what makes the route r, deleting what else is under it.
// preference holds more than its value, so deleting "preference 10"
// leaves an empty preference, which Junos refuses at commit ("Missing
// mandatory statement: <metric_value>"); it's deleted whole instead.
func (r StaticRoute) Commands(config string) []string {
	cmds := r.Config().Commands(config)
	pref := "delete " + r.path() + " preference "
	for i, c := range cmds {
		if strings.HasPrefix(c, pref) {
			cmds[i] = strings.TrimSuffix(pref, " ")
		}
	}
	return cmds
}

// RemoveCommands delete the whole route, when it's there.
func (r StaticRoute) RemoveCommands(config string) []string {
	if !slices.ContainsFunc(SetLines(config), func(l string) bool { return under(l, r.path()) }) {
		return nil
	}
	return []string{"delete " + r.path()}
}
