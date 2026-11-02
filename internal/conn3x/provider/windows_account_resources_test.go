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

func TestWinUserValidate(t *testing.T) {
	r := resourceTypes["conn3x_windows_user"]
	cfg := func(attrs map[string]cty.Value) cty.Value { return objFor(r.schema(), attrs) }
	if d := r.validate(cfg(map[string]cty.Value{"name": cty.StringVal("appsvc"), "password_wo": cty.StringVal("x")})); d.HasErrors() {
		t.Fatal(d.Err())
	}
	for name, a := range map[string]map[string]cty.Value{
		"wildcard":          {"name": cty.StringVal("app*")},
		"too long":          {"name": cty.StringVal(strings.Repeat("a", 21))},
		"empty password":    {"name": cty.StringVal("a"), "password_wo": cty.StringVal("")},
		"long description":  {"name": cty.StringVal("a"), "description": cty.StringVal(strings.Repeat("d", 49))},
		"bad on_remove":     {"name": cty.StringVal("a"), "on_remove": cty.StringVal("purge")},
		"disables login":    {"name": cty.StringVal("ROOT"), "disabled": cty.True},
		"deletes the login": {"name": cty.StringVal("root"), "on_remove": cty.StringVal("delete")},
	} {
		if d := r.validate(cfg(a)); !d.HasErrors() {
			t.Errorf("%s: accepted", name)
		}
	}
	// The login, written with its domain, is still the login.
	c := cfg(map[string]cty.Value{"name": cty.StringVal("azadmin"), "disabled": cty.True}).AsValueMap()
	ssh := c["ssh"].AsValueMap()
	ssh["user"] = cty.StringVal(`LAB\azadmin`)
	c["ssh"] = cty.ObjectVal(ssh)
	if d := r.validate(cty.ObjectVal(c)); !d.HasErrors() {
		t.Error("disabling LAB\\azadmin's local name was accepted")
	}
}

func TestWinUserPlanPassword(t *testing.T) {
	t.Setenv(hmacKeyEnv, strings.Repeat("k", 32))
	r := resourceTypes["conn3x_windows_user"]
	cfg := func(pw string) cty.Value {
		return objFor(r.schema(), map[string]cty.Value{"name": cty.StringVal("appsvc"), "password_wo": cty.StringVal(pw)})
	}
	c := cfg("s3ntinel-pw")
	p := r.plan(providers.PlanResourceChangeRequest{PriorState: cty.NullVal(c.Type()), ProposedNewState: c, Config: c}).PlannedState
	if !p.GetAttr("password_wo").IsNull() || p.GetAttr("password_hmac").IsNull() || strings.Contains(p.GoString(), "s3ntinel") {
		t.Fatalf("planned %#v", p)
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
	// A password under another key stops before anything connects.
	t.Setenv(hmacKeyEnv, strings.Repeat("o", 32))
	resp := r.apply(context.Background(), providers.ApplyResourceChangeRequest{PriorState: prior, PlannedState: prior, Config: c})
	if !resp.Diagnostics.HasErrors() || !strings.Contains(resp.Diagnostics.Err().Error(), "hashed with key") {
		t.Errorf("got %v", resp.Diagnostics.Err())
	}
}

func TestWinGroupValidate(t *testing.T) {
	r := resourceTypes["conn3x_windows_group"]
	members := cty.SetVal([]cty.Value{cty.StringVal(`LAB\alice`), cty.StringVal("S-1-5-32-545")})
	if d := r.validate(objFor(r.schema(), map[string]cty.Value{"name": cty.StringVal("Remote Desktop Users"), "members": members, "authoritative": cty.True})); d.HasErrors() {
		t.Fatal(d.Err())
	}
	for name, a := range map[string]map[string]cty.Value{
		"wildcard":                 {"name": cty.StringVal("Admin*")},
		"authoritative, no list":   {"name": cty.StringVal("g"), "authoritative": cty.True},
		"control character member": {"name": cty.StringVal("g"), "members": cty.SetVal([]cty.Value{cty.StringVal("a\tb")})},
	} {
		if d := r.validate(objFor(r.schema(), a)); !d.HasErrors() {
			t.Errorf("%s: accepted", name)
		}
	}
}

// A name that changes only in case is the same account: no replacement, so
// its SID, and its on_remove, don't come into it.
func TestWinAccountCaseIsNotReplace(t *testing.T) {
	for _, kind := range []string{"conn3x_windows_user", "conn3x_windows_group"} {
		r := resourceTypes[kind]
		c := objFor(r.schema(), map[string]cty.Value{"name": cty.StringVal("AppSvc")})
		p := r.plan(providers.PlanResourceChangeRequest{PriorState: cty.NullVal(c.Type()), ProposedNewState: c, Config: c}).PlannedState
		vals := p.AsValueMap()
		vals["revision"], vals["in_sync"] = cty.StringVal("r"), cty.True
		prior := cty.ObjectVal(vals)
		lower := objFor(r.schema(), map[string]cty.Value{"name": cty.StringVal("appsvc")})
		resp := r.plan(providers.PlanResourceChangeRequest{PriorState: prior, ProposedNewState: lower, Config: lower})
		if len(resp.RequiresReplace) != 0 {
			t.Errorf("%s: case change replaces: %v", kind, resp.RequiresReplace)
		}
		other := objFor(r.schema(), map[string]cty.Value{"name": cty.StringVal("other")})
		if resp := r.plan(providers.PlanResourceChangeRequest{PriorState: prior, ProposedNewState: other, Config: other}); len(resp.RequiresReplace) == 0 {
			t.Errorf("%s: a new name didn't replace", kind)
		}
	}
}

// One password on two hosts doesn't give one HMAC.
func TestWinUserHMACBindsTheHost(t *testing.T) {
	t.Setenv(hmacKeyEnv, strings.Repeat("k", 32))
	r := resourceTypes["conn3x_windows_user"]
	hmacOn := func(host string) string {
		c := objFor(r.schema(), map[string]cty.Value{"name": cty.StringVal("appsvc"), "password_wo": cty.StringVal("same")}).AsValueMap()
		ssh := c["ssh"].AsValueMap()
		ssh["host"] = cty.StringVal(host)
		c["ssh"] = cty.ObjectVal(ssh)
		cfg := cty.ObjectVal(c)
		return r.plan(providers.PlanResourceChangeRequest{PriorState: cty.NullVal(cfg.Type()), ProposedNewState: cfg, Config: cfg}).PlannedState.GetAttr("password_hmac").AsString()
	}
	if hmacOn("192.0.2.1") == hmacOn("192.0.2.2") {
		t.Error("the same HMAC on two hosts")
	}
}
