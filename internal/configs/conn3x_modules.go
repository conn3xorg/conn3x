// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package configs

// CircuitModules returns each module a step can use and the resource type
// it lowers to, for tools that describe modules, such as conn3x mcp.
// template isn't in it, since it lowers to conn3x_file with arguments of
// its own: see TemplateArguments.
func CircuitModules() map[string]string {
	out := make(map[string]string, len(circuitModules))
	for m, t := range circuitModules {
		out[m] = t
	}
	return out
}

// TemplateArguments are the template module's arguments, and whether each
// is required.
func TemplateArguments() map[string]bool {
	out := map[string]bool{}
	for _, a := range templateSchema.Attributes {
		out[a.Name] = a.Required
	}
	return out
}
