// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package eos

import "github.com/opentofu/opentofu/internal/conn3x/modules/netroute"

// StaticRoute is one static route, which eos_static_route owns whole. EOS
// writes a network with its length, as in "ip route 10.20.0.0/16".
type StaticRoute struct{ netroute.StaticRoute }

func top(config string) []string {
	var lines []string
	for _, k := range parse(config).kids {
		lines = append(lines, k.text)
	}
	return lines
}

// InSync reports whether the switch has the route as r has it.
func (r StaticRoute) InSync(config string) bool { return r.Commands(config) == nil }

// Commands make the route r's, or nil, wanted next hops first.
func (r StaticRoute) Commands(config string) []string {
	return r.StaticRoute.Commands(top(config), netroute.CIDR)
}

// RemoveCommands take every next hop of the route away.
func (r StaticRoute) RemoveCommands(config string) []string {
	return r.StaticRoute.RemoveCommands(top(config))
}
