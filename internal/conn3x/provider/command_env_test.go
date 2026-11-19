// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"strings"
	"testing"

	"github.com/zclconf/go-cty/cty"
)

// The environment is exported in name order, each value quoted, and a name
// the shell can't export is refused.
func TestCommandEnvironment(t *testing.T) {
	v := cty.ObjectVal(map[string]cty.Value{"environment": cty.MapVal(map[string]cty.Value{
		"PREFIX": cty.StringVal("/usr/local"), "A_NOTE": cty.StringVal("it's a b"),
	})})
	if got, want := commandExports(v), "export A_NOTE='it'\\''s a b'\nexport PREFIX='/usr/local'\n"; got != want {
		t.Errorf("exports = %q, want %q", got, want)
	}
	if got := commandExports(cty.ObjectVal(map[string]cty.Value{"environment": cty.NullVal(cty.Map(cty.String))})); got != "" {
		t.Errorf("no environment gave %q", got)
	}
	for _, bad := range []string{"1X", "A-B", "A B", "A;id"} {
		vals := commandSchema().Block.EmptyValue().AsValueMap()
		vals["command"] = cty.StringVal("true")
		vals["environment"] = cty.MapVal(map[string]cty.Value{bad: cty.StringVal("x")})
		cfg := cty.ObjectVal(vals)
		if d := validateCommand(cfg); !d.HasErrors() || !strings.Contains(d.Err().Error(), "variable name") {
			t.Errorf("%q: %v", bad, d.Err())
		}
	}
}
