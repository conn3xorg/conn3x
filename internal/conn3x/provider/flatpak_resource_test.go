// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/providers"
)

// An app in one installation is one object per host; changing where it comes
// from or what state it should be in is an update.
func TestFlatpakPlan(t *testing.T) {
	r := resourceTypes["conn3x_flatpak"]
	cfg := objFor(r.schema(), map[string]cty.Value{"name": cty.StringVal("org.gnome.Calculator")})
	created := r.plan(providers.PlanResourceChangeRequest{PriorState: cty.NullVal(cfg.Type()), ProposedNewState: cfg, Config: cfg}).PlannedState
	if got := created.GetAttr("id"); !got.RawEquals(cty.StringVal("203.0.113.10:flatpak:org.gnome.Calculator:")) {
		t.Errorf("id = %#v", got)
	}
	if d := desiredFlatpak(created); d.Remote != "flathub" || d.Method != "system" || d.State != "present" {
		t.Errorf("defaults = %+v", d)
	}
	prior := withSync(created, true)
	if resp := r.plan(providers.PlanResourceChangeRequest{PriorState: prior, ProposedNewState: cfg, Config: cfg}); !resp.PlannedState.GetAttr("in_sync").RawEquals(cty.True) {
		t.Errorf("unchanged step must plan no change: %#v", resp.PlannedState)
	}
	next := objFor(r.schema(), map[string]cty.Value{"name": cty.StringVal("org.gnome.Calculator"), "state": cty.StringVal("latest")})
	resp := r.plan(providers.PlanResourceChangeRequest{PriorState: prior, ProposedNewState: next, Config: next})
	if len(resp.RequiresReplace) != 0 || resp.PlannedState.GetAttr("in_sync").IsKnown() {
		t.Errorf("changing state must update in place: %v", resp.RequiresReplace)
	}
	moved := objFor(r.schema(), map[string]cty.Value{"name": cty.StringVal("org.gnome.Calculator"), "method": cty.StringVal("user")})
	if resp := r.plan(providers.PlanResourceChangeRequest{PriorState: prior, ProposedNewState: moved, Config: moved}); len(resp.RequiresReplace) != 1 {
		t.Errorf("changing method must replace: %v", resp.RequiresReplace)
	}
}

func TestFlatpakValidate(t *testing.T) {
	r := resourceTypes["conn3x_flatpak"]
	for _, cfg := range []map[string]cty.Value{
		{"name": cty.StringVal("calculator")},
		{"name": cty.StringVal("app/org.gnome.Calculator/x86_64/stable")},
		{"name": cty.StringVal("org.gnome.Calculator"), "remote": cty.StringVal("--user")},
		{"name": cty.StringVal("org.gnome.Calculator"), "method": cty.StringVal("global")},
		{"name": cty.StringVal("org.gnome.Calculator"), "state": cty.StringVal("installed")},
		{"name": cty.StringVal("org.gnome.Calculator"), "on_remove": cty.StringVal("explode")},
	} {
		if diags := r.validate(objFor(r.schema(), cfg)); !diags.HasErrors() {
			t.Errorf("accepted %v", cfg)
		}
	}
	if diags := r.validate(objFor(r.schema(), map[string]cty.Value{"name": cty.StringVal("org.gnome.Calculator"), "remote": cty.StringVal("flathub-beta"), "method": cty.StringVal("user"), "state": cty.StringVal("absent")})); diags.HasErrors() {
		t.Error(diags.Err())
	}
}
