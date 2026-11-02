// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/providers"
)

func TestWinPackageValidate(t *testing.T) {
	r := resourceTypes["conn3x_windows_package"]
	code := cty.StringVal("{23170F69-40C1-2702-2409-000001000000}")
	sum := cty.StringVal("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if d := r.validate(objFor(r.schema(), map[string]cty.Value{"product_code": code, "url": cty.StringVal("https://example.com/a.msi"), "sha256": sum})); d.HasErrors() {
		t.Fatal(d.Err())
	}
	if d := r.validate(objFor(r.schema(), map[string]cty.Value{"product_code": code, "state": cty.StringVal("absent")})); d.HasErrors() {
		t.Fatal(d.Err())
	}
	for name, a := range map[string]map[string]cty.Value{
		"no sha":       {"product_code": code, "url": cty.StringVal("https://example.com/a.msi")},
		"absent + url": {"product_code": code, "state": cty.StringVal("absent"), "url": cty.StringVal("https://example.com/a.msi")},
		"bad timeout":  {"product_code": code, "state": cty.StringVal("absent"), "timeout": cty.StringVal("soon")},
	} {
		if d := r.validate(objFor(r.schema(), a)); !d.HasErrors() {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestWinPackagePlanKeepsRebootFlag(t *testing.T) {
	r := resourceTypes["conn3x_windows_package"]
	c := objFor(r.schema(), map[string]cty.Value{"product_code": cty.StringVal("{23170F69-40C1-2702-2409-000001000000}"), "state": cty.StringVal("absent")})
	p := r.plan(providers.PlanResourceChangeRequest{PriorState: cty.NullVal(c.Type()), ProposedNewState: c, Config: c}).PlannedState
	vals := p.AsValueMap()
	vals["revision"], vals["in_sync"], vals["reboot_required"] = cty.StringVal("r"), cty.True, cty.True
	prior := cty.ObjectVal(vals)
	if again := r.plan(providers.PlanResourceChangeRequest{PriorState: prior, ProposedNewState: prior, Config: c}).PlannedState; !again.GetAttr("reboot_required").RawEquals(cty.True) {
		t.Error("reboot_required was lost")
	}
}
