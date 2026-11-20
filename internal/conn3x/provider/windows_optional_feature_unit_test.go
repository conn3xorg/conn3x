// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"strings"
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/providers"
)

func TestWinOptionalFeaturePlanKeepsRebootFlag(t *testing.T) {
	f := resourceTypes["conn3x_windows_optional_feature"]
	c := objFor(f.schema(), map[string]cty.Value{"name": cty.StringVal("TelnetClient")})
	p := f.plan(providers.PlanResourceChangeRequest{PriorState: cty.NullVal(c.Type()), ProposedNewState: c, Config: c}).PlannedState
	if p.GetAttr("reboot_required").IsKnown() {
		t.Fatal("a new feature planned a known reboot_required")
	}
	vals := p.AsValueMap()
	vals["revision"], vals["in_sync"], vals["reboot_required"] = cty.StringVal("r"), cty.True, cty.True
	prior := cty.ObjectVal(vals)
	again := f.plan(providers.PlanResourceChangeRequest{PriorState: prior, ProposedNewState: prior, Config: c}).PlannedState
	if !again.GetAttr("reboot_required").RawEquals(cty.True) {
		t.Errorf("reboot_required = %#v", again.GetAttr("reboot_required"))
	}
}

func TestWinOptionalFeatureValidate(t *testing.T) {
	f := resourceTypes["conn3x_windows_optional_feature"]
	for want, attrs := range map[string]map[string]cty.Value{
		"not a feature name": {"name": cty.StringVal("Tel*")},
		"include_parent":     {"name": cty.StringVal("TelnetClient"), "state": cty.StringVal("absent"), "include_parent": cty.True},
		"source":             {"name": cty.StringVal("NetFx3"), "state": cty.StringVal("absent"), "source": cty.StringVal(`D:\sources\sxs`)},
		"timeout":            {"name": cty.StringVal("TelnetClient"), "timeout": cty.StringVal("soon")},
	} {
		diags := f.validate(objFor(f.schema(), attrs))
		if !diags.HasErrors() || !strings.Contains(diags.Err().Error(), want) {
			t.Errorf("%s: %v", want, diags.Err())
		}
	}
	ok := objFor(f.schema(), map[string]cty.Value{"name": cty.StringVal("NetFx3"), "include_parent": cty.True, "source": cty.StringVal(`\\files\sxs`), "timeout": cty.StringVal("45m")})
	if diags := f.validate(ok); diags.HasErrors() {
		t.Error(diags.Err())
	}
}
