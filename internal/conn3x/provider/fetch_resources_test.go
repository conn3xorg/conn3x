// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/providers"
)

func TestFetchPlansKeyOnDest(t *testing.T) {
	for rt, attrs := range map[string][2]map[string]cty.Value{
		"conn3x_download": {
			{"dest": cty.StringVal("/opt/a"), "url": cty.StringVal("https://example.com/a"), "sha256": cty.StringVal(sum64)},
			{"dest": cty.StringVal("/opt/a"), "url": cty.StringVal("https://example.com/b"), "sha256": cty.StringVal(sum64)},
		},
		"conn3x_archive": {
			{"dest": cty.StringVal("/opt/a"), "src": cty.StringVal("/tmp/a.tgz"), "creates": cty.StringVal("/opt/a/x")},
			{"dest": cty.StringVal("/opt/a"), "src": cty.StringVal("/tmp/b.tgz"), "creates": cty.StringVal("/opt/a/x")},
		},
		"conn3x_git": {
			{"dest": cty.StringVal("/srv/app"), "repo": cty.StringVal("https://example.com/a.git")},
			{"dest": cty.StringVal("/srv/app"), "repo": cty.StringVal("https://example.com/a.git"), "ref": cty.StringVal("v2")},
		},
	} {
		r := resourceTypes[rt]
		cfg := objFor(r.schema(), attrs[0])
		created := r.plan(providers.PlanResourceChangeRequest{PriorState: cty.NullVal(cfg.Type()), ProposedNewState: cfg, Config: cfg}).PlannedState
		if got := created.GetAttr("id"); !got.RawEquals(cty.StringVal("203.0.113.10:" + rt[len("conn3x_"):] + ":" + attrs[0]["dest"].AsString())) {
			t.Errorf("%s: id = %#v", rt, got)
		}
		next := objFor(r.schema(), attrs[1])
		resp := r.plan(providers.PlanResourceChangeRequest{PriorState: withSync(created, true), ProposedNewState: next, Config: next})
		if len(resp.RequiresReplace) != 0 || resp.PlannedState.GetAttr("in_sync").IsKnown() {
			t.Errorf("%s: a changed setting must update in place: %v", rt, resp.RequiresReplace)
		}
	}
}

// The commit is only known once apply has resolved the ref.
func TestGitCommitIsUnknownUntilApplied(t *testing.T) {
	r := resourceTypes["conn3x_git"]
	cfg := objFor(r.schema(), map[string]cty.Value{"dest": cty.StringVal("/srv/app"), "repo": cty.StringVal("https://example.com/a.git")})
	created := r.plan(providers.PlanResourceChangeRequest{PriorState: cty.NullVal(cfg.Type()), ProposedNewState: cfg, Config: cfg}).PlannedState
	if created.GetAttr("commit").IsKnown() {
		t.Fatal("commit known before apply")
	}
	vals := withSync(created, true).AsValueMap()
	vals["id"], vals["commit"] = cty.StringVal("x"), cty.StringVal("7fd1a60b01f91b314f59955a4e4d4e80d8edf11d")
	prior := cty.ObjectVal(vals)
	same := r.plan(providers.PlanResourceChangeRequest{PriorState: prior, ProposedNewState: prior, Config: prior}).PlannedState
	if !same.GetAttr("commit").RawEquals(prior.GetAttr("commit")) {
		t.Fatal("an in-sync checkout must keep its commit")
	}
}

const sum64 = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
