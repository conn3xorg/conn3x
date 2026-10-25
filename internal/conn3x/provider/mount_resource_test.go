// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/providers"
)

func TestMountPlan(t *testing.T) {
	r := resourceTypes["conn3x_mount"]
	attrs := map[string]cty.Value{"path": cty.StringVal("/mnt/scratch"), "src": cty.StringVal("tmpfs"), "fstype": cty.StringVal("tmpfs")}
	cfg := objFor(r.schema(), attrs)
	created := r.plan(providers.PlanResourceChangeRequest{PriorState: cty.NullVal(cfg.Type()), ProposedNewState: cfg, Config: cfg}).PlannedState
	if got := created.GetAttr("id"); !got.RawEquals(cty.StringVal("203.0.113.10:mount:/mnt/scratch")) {
		t.Fatalf("id = %#v", got)
	}
	attrs["opts"] = cty.StringVal("size=16m")
	next := objFor(r.schema(), attrs)
	resp := r.plan(providers.PlanResourceChangeRequest{PriorState: withSync(created, true), ProposedNewState: next, Config: next})
	if len(resp.RequiresReplace) != 0 || resp.PlannedState.GetAttr("in_sync").IsKnown() {
		t.Fatalf("new options must update in place: %v", resp.RequiresReplace)
	}
	bad := objFor(r.schema(), map[string]cty.Value{"path": cty.StringVal("/"), "src": cty.StringVal("tmpfs"), "fstype": cty.StringVal("tmpfs")})
	if !r.validate(bad).HasErrors() {
		t.Fatal("accepted a mount over /")
	}
}
