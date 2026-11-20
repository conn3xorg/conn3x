// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"strings"
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/conn3x/modules/windows"
	"github.com/opentofu/opentofu/internal/providers"
)

func TestWinHostnamePlanAndRead(t *testing.T) {
	r := resourceTypes["conn3x_windows_hostname"]
	c := objFor(r.schema(), map[string]cty.Value{"name": cty.StringVal("WEB01")})
	p := r.plan(providers.PlanResourceChangeRequest{PriorState: cty.NullVal(c.Type()), ProposedNewState: c, Config: c}).PlannedState
	if p.GetAttr("reboot_required").IsKnown() {
		t.Fatal("a new step planned a known reboot_required")
	}
	vals := p.AsValueMap()
	vals["revision"], vals["id"] = cty.StringVal("r"), cty.StringVal("id")
	// What a read records: pending matches, so in sync, and a reboot waits.
	prior := withHostname(cty.ObjectVal(vals), windows.HostnameState{Running: "FV-AZ12", Pending: "WEB01"})
	if !prior.GetAttr("in_sync").True() || !prior.GetAttr("reboot_required").True() {
		t.Fatalf("after a rename: %#v", prior)
	}
	again := r.plan(providers.PlanResourceChangeRequest{PriorState: prior, ProposedNewState: prior, Config: c}).PlannedState
	if !again.GetAttr("reboot_required").RawEquals(cty.True) || !again.GetAttr("in_sync").RawEquals(cty.True) {
		t.Errorf("the plan before the reboot isn't clean: %#v", again)
	}
	if st := withHostname(prior, windows.HostnameState{Running: "WEB01", Pending: "WEB01"}); st.GetAttr("reboot_required").True() {
		t.Error("reboot_required after the reboot")
	}
}

func TestWinHostnameValidate(t *testing.T) {
	r := resourceTypes["conn3x_windows_hostname"]
	for name, want := range map[string]string{"web01.corp.example": "has a dot", "ABCDEFGHIJKLMNOP": "longer than 15", "12345": "all digits"} {
		diags := r.validate(objFor(r.schema(), map[string]cty.Value{"name": cty.StringVal(name)}))
		if !diags.HasErrors() || !strings.Contains(diags.Err().Error(), want) {
			t.Errorf("%s: %v", name, diags.Err())
		}
	}
	if diags := r.validate(objFor(r.schema(), map[string]cty.Value{"name": cty.StringVal("web-01")})); diags.HasErrors() {
		t.Error(diags.Err())
	}
}
