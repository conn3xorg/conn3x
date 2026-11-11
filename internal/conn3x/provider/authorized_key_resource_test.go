// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"crypto/ed25519"
	"strings"
	"testing"

	"github.com/zclconf/go-cty/cty"
	gossh "golang.org/x/crypto/ssh"

	"github.com/opentofu/opentofu/internal/providers"
)

func testPubKey(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	k, err := gossh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(gossh.MarshalAuthorizedKey(k)))
}

// An exclusive step lists several keys and can't be made to remove them
// all or nothing at all.
func TestValidateAuthorizedKeyExclusive(t *testing.T) {
	r := resourceTypes["conn3x_authorized_key"]
	two := cty.StringVal(testPubKey(t) + "\n" + testPubKey(t) + "\n")
	ok := objFor(r.schema(), map[string]cty.Value{"user": cty.StringVal("deploy"), "key": two, "exclusive": cty.True})
	if diags := r.validate(ok); diags.HasErrors() {
		t.Fatalf("two keys, exclusive: %v", diags.Err())
	}
	for want, attrs := range map[string]map[string]cty.Value{
		"single line":            {"key": two},
		"lists no keys":          {"key": cty.StringVal("\n\n"), "exclusive": cty.True},
		`state = "absent"`:       {"key": two, "exclusive": cty.True, "state": cty.StringVal("absent")},
		"leaves authorized_keys": {"key": two, "exclusive": cty.True, "on_remove": cty.StringVal("delete")},
	} {
		attrs["user"] = cty.StringVal("deploy")
		diags := r.validate(objFor(r.schema(), attrs))
		if !diags.HasErrors() || !strings.Contains(diags.Err().Error(), want) {
			t.Errorf("%s: %v", want, diags.Err())
		}
	}
}

// An exclusive step defaults to leaving the file when it's removed, plans
// the unlisted keys away, and takes a change to its keys as an update: a
// replacement would remove the old keys first, and with them the way in.
func TestPlanAuthorizedKeyExclusive(t *testing.T) {
	r := resourceTypes["conn3x_authorized_key"]
	a, b := testPubKey(t), testPubKey(t)
	cfg := objFor(r.schema(), map[string]cty.Value{"user": cty.StringVal("deploy"), "key": cty.StringVal(a), "exclusive": cty.True})
	created := r.plan(providers.PlanResourceChangeRequest{PriorState: cty.NullVal(cfg.Type()), ProposedNewState: cfg, Config: cfg}).PlannedState
	if got := created.GetAttr("on_remove"); !got.RawEquals(cty.StringVal(onRemoveForget)) {
		t.Errorf("on_remove defaults to %#v, want forget", got)
	}
	if got := created.GetAttr("unlisted"); !got.RawEquals(cty.ListValEmpty(cty.String)) {
		t.Errorf("unlisted planned as %#v", got)
	}

	prior := created.AsValueMap()
	prior["id"], prior["in_sync"] = cty.StringVal("203.0.113.10:authorized_key:deploy"), cty.True
	prior["unlisted"] = cty.ListVal([]cty.Value{cty.StringVal("ssh-ed25519 SHA256:x")})
	next := objFor(r.schema(), map[string]cty.Value{"user": cty.StringVal("deploy"), "key": cty.StringVal(a + "\n" + b), "exclusive": cty.True})
	resp := r.plan(providers.PlanResourceChangeRequest{PriorState: cty.ObjectVal(prior), ProposedNewState: next, Config: next})
	if len(resp.RequiresReplace) != 0 {
		t.Errorf("a changed list replaces the step: %v", resp.RequiresReplace)
	}
	if resp.PlannedState.GetAttr("in_sync").IsKnown() {
		t.Error("a changed list with unlisted keys plans no change")
	}

	// Without exclusive, a new key is a new step, as before.
	plain := objFor(r.schema(), map[string]cty.Value{"user": cty.StringVal("deploy"), "key": cty.StringVal(a)})
	pp := r.plan(providers.PlanResourceChangeRequest{PriorState: cty.NullVal(plain.Type()), ProposedNewState: plain, Config: plain}).PlannedState.AsValueMap()
	pp["id"], pp["in_sync"] = cty.StringVal("x"), cty.True
	moved := objFor(r.schema(), map[string]cty.Value{"user": cty.StringVal("deploy"), "key": cty.StringVal(b)})
	if resp := r.plan(providers.PlanResourceChangeRequest{PriorState: cty.ObjectVal(pp), ProposedNewState: moved, Config: moved}); len(resp.RequiresReplace) != 1 {
		t.Errorf("a plain key change doesn't replace: %v", resp.RequiresReplace)
	}
}
