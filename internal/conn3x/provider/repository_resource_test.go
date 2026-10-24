// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/providers"
)

const testKey = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nx\n-----END PGP PUBLIC KEY BLOCK-----\n"

func TestRepositoryPlan(t *testing.T) {
	r := resourceTypes["conn3x_repository"]
	attrs := map[string]cty.Value{"name": cty.StringVal("nginx"), "url": cty.StringVal("https://nginx.org/packages/ubuntu"), "key": cty.StringVal(testKey),
		"suites": cty.ListVal([]cty.Value{cty.StringVal("noble")})}
	cfg := objFor(r.schema(), attrs)
	created := r.plan(providers.PlanResourceChangeRequest{PriorState: cty.NullVal(cfg.Type()), ProposedNewState: cfg, Config: cfg}).PlannedState
	if got := created.GetAttr("id"); !got.RawEquals(cty.StringVal("203.0.113.10:repository:nginx")) {
		t.Fatalf("id = %#v", got)
	}
	attrs["suites"] = cty.ListVal([]cty.Value{cty.StringVal("jammy")})
	next := objFor(r.schema(), attrs)
	resp := r.plan(providers.PlanResourceChangeRequest{PriorState: withSync(created, true), ProposedNewState: next, Config: next})
	if len(resp.RequiresReplace) != 0 || resp.PlannedState.GetAttr("in_sync").IsKnown() {
		t.Fatalf("a changed suite must update in place: %v", resp.RequiresReplace)
	}
}

func TestRepositoryValidate(t *testing.T) {
	r := resourceTypes["conn3x_repository"]
	for _, attrs := range []map[string]cty.Value{
		{"name": cty.StringVal("x"), "url": cty.StringVal("ftp://example.com"), "key": cty.StringVal(testKey)},
		{"name": cty.StringVal("x"), "url": cty.StringVal("https://example.com"), "key": cty.StringVal("nope")},
		{"name": cty.StringVal("x"), "url": cty.StringVal("https://example.com"), "key": cty.StringVal(testKey),
			"suites": cty.ListVal([]cty.Value{cty.StringVal("noble\nTypes: deb-src")})},
	} {
		if !r.validate(objFor(r.schema(), attrs)).HasErrors() {
			t.Errorf("accepted %v", attrs)
		}
	}
}
