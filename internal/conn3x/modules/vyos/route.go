// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package vyos

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/opentofu/opentofu/internal/conn3x/modules/setcfg"
)

// StaticRoute is one static route, which vyos_static_route owns whole:
// every statement under it is one of these next hops.
type StaticRoute struct {
	Prefix   string   // such as 10.20.0.0/16 or 2001:db8:20::/48
	NextHops []string // addresses of the prefix's family
	Distance int      // 1 to 255; 0 leaves VyOS's default, 1
}

// Validate checks a route before anything reaches the router.
func (r StaticRoute) Validate() error {
	p, err := netip.ParsePrefix(r.Prefix)
	if err != nil {
		return fmt.Errorf("prefix %q must be a network with its length, such as 10.20.0.0/16", r.Prefix)
	}
	if p.Masked() != p {
		return fmt.Errorf("prefix %q has host bits set; the network is %s", r.Prefix, p.Masked())
	}
	if len(r.NextHops) == 0 {
		return fmt.Errorf("next_hops must list at least one address")
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
	if r.Distance != 0 && (r.Distance < 1 || r.Distance > 255) {
		return fmt.Errorf("distance must be from 1 to 255, not %d", r.Distance)
	}
	return nil
}

func (r StaticRoute) path() string {
	node := "route"
	if p, err := netip.ParsePrefix(r.Prefix); err == nil && p.Addr().Is6() {
		node = "route6"
	}
	return "protocols static " + node + " " + r.Prefix
}

// InSync reports whether the router has the route as r has it.
func (r StaticRoute) InSync(config string) bool { return r.Commands(config) == nil }

// Commands are what makes the route r. A next hop is a tag node, and
// deleting its distance leaves the hop there, so a hop that's not wanted
// is deleted whole, and anything else under the route, such as blackhole,
// goes too.
func (r StaticRoute) Commands(config string) []string {
	hop := "set " + r.path() + " next-hop "
	have := map[string]string{} // next hop: its distance, "" for none
	var cmds []string
	for _, l := range setcfg.SetLines(config) {
		if !setcfg.Under(l, r.path()) {
			continue
		}
		rest, ok := strings.CutPrefix(l, hop)
		if !ok {
			// A bare "set ... route PREFIX" is the node itself.
			if l != "set "+r.path() {
				cmds = append(cmds, setcfg.DeleteOf(l))
			}
			continue
		}
		f := strings.Fields(rest)
		if _, seen := have[f[0]]; !seen {
			have[f[0]] = ""
		}
		if len(f) == 3 && f[1] == "distance" {
			have[f[0]] = f[2]
		} else if len(f) > 1 && !slices.Contains(r.NextHops, f[0]) {
			continue // the hop goes whole below
		} else if len(f) > 1 {
			cmds = append(cmds, setcfg.DeleteOf(l))
		}
	}
	for _, h := range sortedKeys(have) {
		if !slices.Contains(r.NextHops, h) {
			cmds = append(cmds, "delete "+r.path()+" next-hop "+h)
		}
	}
	want := ""
	if r.Distance != 0 {
		want = fmt.Sprint(r.Distance)
	}
	for _, h := range r.NextHops {
		got, ok := have[h]
		switch {
		case !ok && want == "":
			cmds = append(cmds, hop+h)
		case got != want && want != "":
			cmds = append(cmds, hop+h+" distance "+want)
		case ok && got != want:
			cmds = append(cmds, "delete "+r.path()+" next-hop "+h+" distance")
		}
	}
	return cmds
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// RemoveCommands delete the route, for on_remove = "delete".
func (r StaticRoute) RemoveCommands(config string) []string {
	if slices.ContainsFunc(setcfg.SetLines(config), func(l string) bool { return setcfg.Under(l, r.path()) }) {
		return []string{"delete " + r.path()}
	}
	return nil
}
