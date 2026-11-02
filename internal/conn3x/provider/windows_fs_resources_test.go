// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"strings"
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/providers"
)

func TestWinFileValidate(t *testing.T) {
	r := resourceTypes["conn3x_windows_file"]
	good := map[string]cty.Value{"path": cty.StringVal(`C:\app\x`), "content": cty.StringVal("x")}
	if d := r.validate(objFor(r.schema(), good)); d.HasErrors() {
		t.Fatal(d.Err())
	}
	for name, attrs := range map[string]map[string]cty.Value{
		"no content": {"path": cty.StringVal(`C:\app\x`)},
		"both":       {"path": cty.StringVal(`C:\app\x`), "content": cty.StringVal("x"), "content_wo": cty.StringVal("y")},
		"share":      {"path": cty.StringVal(`\\srv\share\x`), "content": cty.StringVal("x")},
		"stream":     {"path": cty.StringVal(`C:\x:evil`), "content": cty.StringVal("x")},
		"traversal":  {"path": cty.StringVal(`C:\a\..\b`), "content": cty.StringVal("x")},
		"too much":   {"path": cty.StringVal(`C:\x`), "content": cty.StringVal(strings.Repeat("x", 2<<20+1))},
		"on_remove":  {"path": cty.StringVal(`C:\x`), "content": cty.StringVal("x"), "on_remove": cty.StringVal("burn")},
	} {
		if d := r.validate(objFor(r.schema(), attrs)); !d.HasErrors() {
			t.Errorf("%s: accepted", name)
		}
	}
}

// content_wo stays out of the plan, and only the hash of what's wanted matters.
func TestWinFilePlanSecret(t *testing.T) {
	t.Setenv(hmacKeyEnv, strings.Repeat("k", 32))
	r := resourceTypes["conn3x_windows_file"]
	const secret = "s3ntinel"
	cfg := objFor(r.schema(), map[string]cty.Value{"path": cty.StringVal(`C:\s`), "content_wo": cty.StringVal(secret)})
	resp := r.plan(providers.PlanResourceChangeRequest{PriorState: cty.NullVal(cfg.Type()), ProposedNewState: cfg, Config: cfg})
	if resp.Diagnostics.HasErrors() {
		t.Fatal(resp.Diagnostics.Err())
	}
	p := resp.PlannedState
	if !p.GetAttr("content_wo").IsNull() || !p.GetAttr("content").IsNull() || !p.GetAttr("sha256").IsNull() {
		t.Fatalf("planned %#v", p)
	}
	key, _ := hmacKey(false)
	mac := p.GetAttr("content_hmac").AsString()
	if mac != winWoHMAC(key, `C:\s`, digest(secret)) {
		t.Errorf("mac %s", mac)
	}
	if strings.Contains(mac, digest(secret)) {
		t.Error("state would hold the plain hash of a secret")
	}
	// The host holding what was asked for plans nothing.
	vals := p.AsValueMap()
	vals["revision"], vals["in_sync"] = cty.StringVal("r"), cty.True
	prior := cty.ObjectVal(vals)
	proposed := prior.AsValueMap()
	proposed["content_wo"] = cty.NullVal(cty.String)
	again := r.plan(providers.PlanResourceChangeRequest{PriorState: prior, ProposedNewState: cty.ObjectVal(proposed), Config: cfg}).PlannedState
	if again.GetAttr("in_sync").IsKnown() != true || !again.GetAttr("content_hmac").RawEquals(prior.GetAttr("content_hmac")) {
		t.Errorf("planned a change: %#v", again)
	}
	// Different content on the host does.
	vals["content_hmac"] = cty.StringVal(winWoHMAC(key, `C:\s`, digest("other")))
	drift := r.plan(providers.PlanResourceChangeRequest{PriorState: cty.ObjectVal(vals), ProposedNewState: cty.ObjectVal(vals), Config: cfg}).PlannedState
	if drift.GetAttr("content_hmac").RawEquals(cty.StringVal(vals["content_hmac"].AsString())) {
		t.Error("drift planned no change")
	}
}

func TestWinFilePlanDriftInRules(t *testing.T) {
	r := resourceTypes["conn3x_windows_file"]
	cfg := objFor(r.schema(), map[string]cty.Value{"path": cty.StringVal(`C:\s`), "content": cty.StringVal("x")})
	p := r.plan(providers.PlanResourceChangeRequest{PriorState: cty.NullVal(cfg.Type()), ProposedNewState: cfg, Config: cfg}).PlannedState
	if p.GetAttr("sha256").AsString() != digest("x") {
		t.Fatalf("sha256 %#v", p.GetAttr("sha256"))
	}
	vals := p.AsValueMap()
	vals["revision"], vals["in_sync"] = cty.StringVal("r"), cty.False
	prior := cty.ObjectVal(vals)
	if again := r.plan(providers.PlanResourceChangeRequest{PriorState: prior, ProposedNewState: prior, Config: cfg}).PlannedState; again.GetAttr("in_sync").IsKnown() {
		t.Error("rules out of sync planned no change")
	}
}

func TestWinACLValidate(t *testing.T) {
	r := resourceTypes["conn3x_windows_acl"]
	entry := func(p string, rights ...string) cty.Value {
		rs := []cty.Value{}
		for _, x := range rights {
			rs = append(rs, cty.StringVal(x))
		}
		ty := r.schema().Block.BlockTypes["entry"].ImpliedType()
		vals := map[string]cty.Value{}
		for k, a := range ty.AttributeTypes() {
			vals[k] = cty.NullVal(a)
		}
		vals["principal"], vals["rights"] = cty.StringVal(p), cty.ListVal(rs)
		return cty.ObjectVal(vals)
	}
	good := objFor(r.schema(), map[string]cty.Value{"path": cty.StringVal(`C:\x`), "entry": cty.ListVal([]cty.Value{entry("Users", "Read")})})
	if d := r.validate(good); d.HasErrors() {
		t.Fatal(d.Err())
	}
	if d := r.validate(objFor(r.schema(), map[string]cty.Value{"path": cty.StringVal(`C:\x`)})); !d.HasErrors() {
		t.Error("accepted nothing to do")
	}
	if d := r.validate(objFor(r.schema(), map[string]cty.Value{"path": cty.StringVal(`C:\x`), "entry": cty.ListVal([]cty.Value{entry("Users", "Everything")})})); !d.HasErrors() {
		t.Error("accepted an unknown right")
	}
}
