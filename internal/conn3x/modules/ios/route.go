// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ios

import "github.com/opentofu/opentofu/internal/conn3x/modules/netroute"

// StaticRoute is one static route, which ios_static_route owns whole. IOS
// writes an IPv4 route's network with a dotted mask, and IPv6 addresses in
// upper case, so lines are matched on what they parse to.
type StaticRoute struct{ netroute.StaticRoute }

func top(config string) []string {
	var lines []string
	for _, k := range parse(config).kids {
		lines = append(lines, k.text)
	}
	return lines
}

// InSync reports whether the device has the route as r has it.
func (r StaticRoute) InSync(config string) bool { return r.Commands(config) == nil }

// Commands make the route r's, or nil: wanted next hops first, the others
// out after, since IOS applies each line as it comes.
func (r StaticRoute) Commands(config string) []string {
	return r.StaticRoute.Commands(top(config), netroute.DottedMask)
}

// RemoveCommands take every next hop of the route away.
func (r StaticRoute) RemoveCommands(config string) []string {
	return r.StaticRoute.RemoveCommands(top(config))
}
