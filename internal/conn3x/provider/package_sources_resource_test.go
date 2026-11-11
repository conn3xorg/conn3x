// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/providers"
)

// A package_sources step plans its unlisted files away, updates in place
// when keep changes, and refuses a file name that isn't one.
func TestPlanPackageSources(t *testing.T) {
	r := resourceTypes["conn3x_package_sources"]
	cfg := objFor(r.schema(), map[string]cty.Value{"keep": cty.ListVal([]cty.Value{cty.StringVal("ubuntu-esm-apps.sources")})})
	if diags := r.validate(cfg); diags.HasErrors() {
		t.Fatal(diags.Err())
	}
	created := r.plan(providers.PlanResourceChangeRequest{PriorState: cty.NullVal(cfg.Type()), ProposedNewState: cfg, Config: cfg}).PlannedState
	if got := created.GetAttr("unlisted"); !got.RawEquals(cty.ListValEmpty(cty.String)) {
		t.Errorf("unlisted planned as %#v", got)
	}
	prior := created.AsValueMap()
	prior["id"], prior["in_sync"] = cty.StringVal("203.0.113.10:package_sources"), cty.True
	prior["unlisted"] = cty.ListValEmpty(cty.String)
	if resp := r.plan(providers.PlanResourceChangeRequest{PriorState: cty.ObjectVal(prior), ProposedNewState: cfg, Config: cfg}); !resp.PlannedState.GetAttr("in_sync").RawEquals(cty.True) {
		t.Errorf("nothing unlisted plans a change: %#v", resp.PlannedState.GetAttr("in_sync"))
	}

	none := objFor(r.schema(), map[string]cty.Value{})
	resp := r.plan(providers.PlanResourceChangeRequest{PriorState: cty.ObjectVal(prior), ProposedNewState: none, Config: none})
	if len(resp.RequiresReplace) != 0 || resp.PlannedState.GetAttr("in_sync").IsKnown() {
		t.Errorf("a new keep: replace %v, in_sync %#v", resp.RequiresReplace, resp.PlannedState.GetAttr("in_sync"))
	}
	prior["unlisted"] = cty.ListVal([]cty.Value{cty.StringVal("old.list")})
	if resp := r.plan(providers.PlanResourceChangeRequest{PriorState: cty.ObjectVal(prior), ProposedNewState: cfg, Config: cfg}); resp.PlannedState.GetAttr("in_sync").IsKnown() {
		t.Error("an unlisted file plans no change")
	}

	bad := objFor(r.schema(), map[string]cty.Value{"keep": cty.ListVal([]cty.Value{cty.StringVal("../apt.conf")})})
	if diags := r.validate(bad); !diags.HasErrors() {
		t.Error("a path in keep passed")
	}
}
