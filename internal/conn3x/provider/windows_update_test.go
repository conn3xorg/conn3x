// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/providers"
)

// Updates found waiting at refresh plan an install, with pending going to
// empty, so the plan lists each KB that will install. Nothing waiting plans
// nothing.
func TestWinUpdatePlansWhatIsWaiting(t *testing.T) {
	waiting := cty.ListVal([]cty.Value{cty.StringVal("KB5034441 2026-11 Cumulative Update")})
	prior := eosStep("conn3x_windows_update", map[string]cty.Value{
		"id": cty.StringVal("x"), "revision": cty.StringVal("r1"), "in_sync": cty.False,
		"pending": waiting, "reboot_required": cty.False,
	}, nil)
	config := eosStep("conn3x_windows_update", nil, nil)
	plan := func(prior cty.Value) providers.PlanResourceChangeResponse {
		vals := config.AsValueMap()
		for _, k := range []string{"id", "revision", "in_sync", "pending", "reboot_required"} {
			vals[k] = prior.GetAttr(k)
		}
		return planWinUpdate(providers.PlanResourceChangeRequest{PriorState: prior, ProposedNewState: cty.ObjectVal(vals), Config: config})
	}
	resp := plan(prior)
	if resp.Diagnostics.HasErrors() {
		t.Fatal(resp.Diagnostics.Err())
	}
	if p := resp.PlannedState; p.GetAttr("pending").LengthInt() != 0 || p.GetAttr("in_sync").IsKnown() || p.GetAttr("reboot_required").IsKnown() {
		t.Errorf("planned %#v", p)
	}

	vals := prior.AsValueMap()
	vals["in_sync"], vals["pending"] = cty.True, cty.ListValEmpty(cty.String)
	if p := plan(cty.ObjectVal(vals)).PlannedState; !p.GetAttr("in_sync").RawEquals(cty.True) {
		t.Errorf("nothing waiting still planned a change: %#v", p)
	}
}

func TestWinUpdateValidates(t *testing.T) {
	bad := eosStep("conn3x_windows_update", map[string]cty.Value{"categories": cty.ListVal([]cty.Value{cty.StringVal("Security")})}, nil)
	if !validateWinUpdate(bad).HasErrors() {
		t.Error("accepted an unknown category")
	}
	if diags := validateWinUpdate(eosStep("conn3x_windows_update", nil, nil)); diags.HasErrors() {
		t.Error(diags.Err())
	}
}
