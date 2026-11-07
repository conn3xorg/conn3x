// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"strings"
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/providers"
)

func TestWinADObjectsValidate(t *testing.T) {
	for typ, cases := range map[string]struct {
		ok  map[string]cty.Value
		bad map[string]map[string]cty.Value
	}{
		"conn3x_windows_ad_ou": {
			ok: map[string]cty.Value{"name": cty.StringVal("Servers"), "path": cty.StringVal("OU=Lab,DC=lab,DC=test"), "protected": cty.False, "on_remove": cty.StringVal("delete")},
			bad: map[string]map[string]cty.Value{
				"comma":     {"name": cty.StringVal("a,b")},
				"path":      {"name": cty.StringVal("a"), "path": cty.StringVal("Lab")},
				"on_remove": {"name": cty.StringVal("a"), "on_remove": cty.StringVal("purge")},
			},
		},
		"conn3x_windows_ad_group": {
			ok: map[string]cty.Value{"name": cty.StringVal("AppAdmins"), "scope": cty.StringVal("universal"), "members": cty.SetVal([]cty.Value{cty.StringVal("alice"), cty.StringVal("web1$")}), "authoritative": cty.True},
			bad: map[string]map[string]cty.Value{
				"scope":     {"name": cty.StringVal("g"), "scope": cty.StringVal("local")},
				"domain":    {"name": cty.StringVal("g"), "members": cty.SetVal([]cty.Value{cty.StringVal(`LAB\alice`)})},
				"auth only": {"name": cty.StringVal("g"), "authoritative": cty.True},
			},
		},
		"conn3x_windows_ad_user": {
			ok: map[string]cty.Value{"name": cty.StringVal("alice"), "upn": cty.StringVal("alice@lab.test"), "password_wo": cty.StringVal("x"), "enabled": cty.True},
			bad: map[string]map[string]cty.Value{
				"long":              {"name": cty.StringVal(strings.Repeat("a", 21))},
				"upn":               {"name": cty.StringVal("a"), "upn": cty.StringVal("a")},
				"empty password":    {"name": cty.StringVal("a"), "password_wo": cty.StringVal("")},
				"disables login":    {"name": cty.StringVal("ROOT"), "enabled": cty.False},
				"deletes the login": {"name": cty.StringVal("root"), "on_remove": cty.StringVal("delete")},
			},
		},
	} {
		r := resourceTypes[typ]
		if d := r.validate(objFor(r.schema(), cases.ok)); d.HasErrors() {
			t.Errorf("%s: %v", typ, d.Err())
		}
		for name, a := range cases.bad {
			if d := r.validate(objFor(r.schema(), a)); !d.HasErrors() {
				t.Errorf("%s: %s: accepted", typ, name)
			}
		}
	}
}

// The password is never in plan or state: only an HMAC, which changes with it.
func TestWinADUserPlanPassword(t *testing.T) {
	t.Setenv(hmacKeyEnv, strings.Repeat("k", 32))
	r := resourceTypes["conn3x_windows_ad_user"]
	cfg := func(pw string) cty.Value {
		return objFor(r.schema(), map[string]cty.Value{"name": cty.StringVal("alice"), "password_wo": cty.StringVal(pw)})
	}
	c := cfg("s3ntinel-ad-pw")
	p := r.plan(providers.PlanResourceChangeRequest{PriorState: cty.NullVal(c.Type()), ProposedNewState: c, Config: c}).PlannedState
	if !p.GetAttr("password_wo").IsNull() || p.GetAttr("password_hmac").IsNull() || strings.Contains(p.GoString(), "s3ntinel") {
		t.Fatalf("planned %#v", p)
	}
	user := resourceTypes["conn3x_windows_user"]
	local := objFor(user.schema(), map[string]cty.Value{"name": cty.StringVal("alice"), "password_wo": cty.StringVal("s3ntinel-ad-pw")})
	if lp := user.plan(providers.PlanResourceChangeRequest{PriorState: cty.NullVal(local.Type()), ProposedNewState: local, Config: local}).PlannedState; lp.GetAttr("password_hmac").RawEquals(p.GetAttr("password_hmac")) {
		t.Error("a local and a domain user with one password have one HMAC")
	}
	vals := p.AsValueMap()
	vals["revision"], vals["in_sync"] = cty.StringVal("r"), cty.True
	prior := cty.ObjectVal(vals)
	if again := r.plan(providers.PlanResourceChangeRequest{PriorState: prior, ProposedNewState: prior, Config: c}).PlannedState; !again.GetAttr("in_sync").IsKnown() {
		t.Error("the same password planned a change")
	}
	if changed := r.plan(providers.PlanResourceChangeRequest{PriorState: prior, ProposedNewState: prior, Config: cfg("other")}).PlannedState; changed.GetAttr("in_sync").IsKnown() {
		t.Error("a new password planned no change")
	}
	t.Setenv(hmacKeyEnv, strings.Repeat("o", 32))
	resp := r.apply(context.Background(), providers.ApplyResourceChangeRequest{PriorState: prior, PlannedState: prior, Config: c})
	if !resp.Diagnostics.HasErrors() || !strings.Contains(resp.Diagnostics.Err().Error(), "hashed with key") {
		t.Errorf("got %v", resp.Diagnostics.Err())
	}
}

// Removing a step forgets what it made unless on_remove says delete, and
// nothing connects to forget.
func TestWinADObjectsForgetOnRemove(t *testing.T) {
	for _, typ := range []string{"conn3x_windows_ad_ou", "conn3x_windows_ad_group", "conn3x_windows_ad_user"} {
		r := resourceTypes[typ]
		prior := objFor(r.schema(), map[string]cty.Value{"name": cty.StringVal("x"), "on_remove": cty.StringVal("forget")})
		resp := r.apply(context.Background(), providers.ApplyResourceChangeRequest{PriorState: prior, PlannedState: cty.NullVal(prior.Type()), Config: cty.NullVal(prior.Type())})
		if resp.Diagnostics.HasErrors() || !resp.NewState.IsNull() {
			t.Errorf("%s: %v", typ, resp.Diagnostics.Err())
		}
	}
}
