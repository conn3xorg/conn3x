// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"strings"
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/providers"
)

// A recursive directory takes a symbolic mode only, plans changes_under
// to 0, and keeps its symbolic mode as written.
func TestDirectoryRecurse(t *testing.T) {
	r := resourceTypes["conn3x_directory"]
	cfg := func(mode string, recurse bool) cty.Value {
		attrs := map[string]cty.Value{"path": cty.StringVal("/srv/app"), "owner": cty.StringVal("deploy"), "recurse": cty.BoolVal(recurse)}
		if mode != "" {
			attrs["mode"] = cty.StringVal(mode)
		}
		return objFor(r.schema(), attrs)
	}
	for _, tc := range []struct {
		mode    string
		recurse bool
		err     string
	}{
		{"0750", true, "must be symbolic"},
		{"u=rwX", false, "only goes with recurse"},
		{"u+s", true, "must be symbolic"},
		{"u=rwX,g=rX,o=", true, ""},
		{"", true, ""},
	} {
		diags := r.validate(cfg(tc.mode, tc.recurse))
		if tc.err == "" && diags.HasErrors() || tc.err != "" && (!diags.HasErrors() || !strings.Contains(diags.Err().Error(), tc.err)) {
			t.Errorf("mode %q recurse %v: %v", tc.mode, tc.recurse, diags.Err())
		}
	}

	c := cfg("u=rwX,g=rX,o=", true)
	planned := r.plan(providers.PlanResourceChangeRequest{PriorState: cty.NullVal(c.Type()), ProposedNewState: c, Config: c}).PlannedState
	if got := planned.GetAttr("mode"); !got.RawEquals(cty.StringVal("u=rwX,g=rX,o=")) {
		t.Errorf("mode planned as %#v", got)
	}
	if got := planned.GetAttr("changes_under"); !got.RawEquals(cty.Zero) {
		t.Errorf("changes_under planned as %#v", got)
	}
	plain := cfg("0750", false)
	if got := r.plan(providers.PlanResourceChangeRequest{PriorState: cty.NullVal(plain.Type()), ProposedNewState: plain, Config: plain}).PlannedState.GetAttr("changes_under"); !got.IsNull() {
		t.Errorf("changes_under without recurse: %#v", got)
	}
}
