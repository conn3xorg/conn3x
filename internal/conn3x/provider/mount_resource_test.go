// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/providers"
	"github.com/opentofu/opentofu/internal/tfdiags"
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

// Changing either of fstab's last two fields updates the entry in place, and
// each bad value points at the field it's about.
func TestMountDumpAndPassNo(t *testing.T) {
	r := resourceTypes["conn3x_mount"]
	attrs := map[string]cty.Value{"path": cty.StringVal("/data"), "src": cty.StringVal("LABEL=data"), "fstype": cty.StringVal("xfs")}
	cfg := objFor(r.schema(), attrs)
	created := r.plan(providers.PlanResourceChangeRequest{PriorState: cty.NullVal(cfg.Type()), ProposedNewState: cfg, Config: cfg}).PlannedState
	attrs["passno"] = cty.NumberIntVal(2)
	attrs["dump"] = cty.NumberIntVal(1)
	next := objFor(r.schema(), attrs)
	resp := r.plan(providers.PlanResourceChangeRequest{PriorState: withSync(created, true), ProposedNewState: next, Config: next})
	if len(resp.RequiresReplace) != 0 || resp.PlannedState.GetAttr("in_sync").IsKnown() {
		t.Fatalf("a new passno must update in place: %v", resp.RequiresReplace)
	}
	for _, c := range []struct {
		attr string
		val  cty.Value
	}{
		{"passno", cty.NumberIntVal(3)},
		{"passno", cty.NumberIntVal(-1)},
		{"passno", cty.NumberFloatVal(1.5)},
		{"dump", cty.NumberIntVal(2)},
		{"path", cty.StringVal("/")},
	} {
		attrs := map[string]cty.Value{"path": cty.StringVal("/data"), "src": cty.StringVal("LABEL=data"), "fstype": cty.StringVal("xfs"), c.attr: c.val}
		d := r.validate(objFor(r.schema(), attrs))
		if len(d) != 1 || !tfdiags.GetAttribute(d[0]).Equals(cty.GetAttrPath(c.attr)) {
			t.Errorf("%s = %#v: want one diagnostic on %s, got %v", c.attr, c.val, c.attr, d)
		}
	}
}
