// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"strings"
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/providers"
)

func TestPgValidate(t *testing.T) {
	db := resourceTypes["conn3x_postgresql_database"]
	if d := db.validate(objFor(db.schema(), map[string]cty.Value{"name": cty.StringVal("app"), "owner": cty.StringVal("app"), "encoding": cty.StringVal("UTF8")})); d.HasErrors() {
		t.Fatal(d.Err())
	}
	for name, a := range map[string]map[string]cty.Value{
		"empty":         {"name": cty.StringVal("")},
		"too long":      {"name": cty.StringVal(strings.Repeat("a", 64))},
		"bad encoding":  {"name": cty.StringVal("app"), "encoding": cty.StringVal("UTF8' x")},
		"bad on_remove": {"name": cty.StringVal("app"), "on_remove": cty.StringVal("purge")},
	} {
		if d := db.validate(objFor(db.schema(), a)); !d.HasErrors() {
			t.Errorf("database %s: accepted", name)
		}
	}
	role := resourceTypes["conn3x_postgresql_role"]
	if d := role.validate(objFor(role.schema(), map[string]cty.Value{"name": cty.StringVal("app"), "password_wo": cty.StringVal("s3cret!"), "attributes": cty.SetVal([]cty.Value{cty.StringVal("CREATEDB")})})); d.HasErrors() {
		t.Fatal(d.Err())
	}
	for name, a := range map[string]map[string]cty.Value{
		"bad attribute":     {"name": cty.StringVal("app"), "attributes": cty.SetVal([]cty.Value{cty.StringVal("LOGIN")})},
		"non-ASCII":         {"name": cty.StringVal("app"), "password_wo": cty.StringVal("pässword")},
		"empty password":    {"name": cty.StringVal("app"), "password_wo": cty.StringVal("")},
		"drops postgres":    {"name": cty.StringVal("postgres"), "on_remove": cty.StringVal("delete")},
		"postgres no login": {"name": cty.StringVal("postgres"), "login": cty.False},
		"postgres no super": {"name": cty.StringVal("postgres"), "attributes": cty.SetValEmpty(cty.String)},
	} {
		if d := role.validate(objFor(role.schema(), a)); !d.HasErrors() {
			t.Errorf("role %s: accepted", name)
		}
	}
}

// pgPrior is the state after an apply of cfg.
func pgPrior(r resourceType, cfg cty.Value) cty.Value {
	vals := r.plan(providers.PlanResourceChangeRequest{PriorState: cty.NullVal(cfg.Type()), ProposedNewState: cfg, Config: cfg}).PlannedState.AsValueMap()
	vals["revision"], vals["in_sync"], vals["id"] = cty.StringVal("r"), cty.True, cty.StringVal("id")
	return cty.ObjectVal(vals)
}

// A new name is a new object; every other setting changes in place.
func TestPgPlan(t *testing.T) {
	t.Setenv(hmacKeyEnv, strings.Repeat("k", 32))
	for kind, base := range map[string]map[string]cty.Value{
		"conn3x_postgresql_database": {"name": cty.StringVal("app"), "owner": cty.StringVal("app"), "encoding": cty.StringVal("UTF8")},
		"conn3x_postgresql_role":     {"name": cty.StringVal("app"), "login": cty.True, "attributes": cty.SetValEmpty(cty.String), "password_wo": cty.StringVal("one")},
	} {
		r := resourceTypes[kind]
		cfg := func(k string, v cty.Value) cty.Value {
			a := map[string]cty.Value{}
			for kk, vv := range base {
				a[kk] = vv
			}
			if k != "" {
				a[k] = v
			}
			return objFor(r.schema(), a)
		}
		prior := pgPrior(r, cfg("", cty.NilVal))
		plan := func(c cty.Value) providers.PlanResourceChangeResponse {
			return r.plan(providers.PlanResourceChangeRequest{PriorState: prior, ProposedNewState: c, Config: c})
		}
		if resp := plan(cfg("", cty.NilVal)); !resp.PlannedState.GetAttr("in_sync").IsKnown() || len(resp.RequiresReplace) > 0 {
			t.Errorf("%s: the same config planned a change", kind)
		}
		if resp := plan(cfg("name", cty.StringVal("App"))); len(resp.RequiresReplace) == 0 {
			t.Errorf("%s: a new name, even in case only, didn't replace", kind)
		}
		changes := map[string]cty.Value{"owner": cty.StringVal("other"), "encoding": cty.StringVal("LATIN1")}
		if kind == "conn3x_postgresql_role" {
			changes = map[string]cty.Value{"login": cty.False, "attributes": cty.SetVal([]cty.Value{cty.StringVal("CREATEDB")}), "password_wo": cty.StringVal("two")}
		}
		for k, v := range changes {
			resp := plan(cfg(k, v))
			if resp.PlannedState.GetAttr("in_sync").IsKnown() || len(resp.RequiresReplace) > 0 {
				t.Errorf("%s: %s didn't plan an update in place", kind, k)
			}
			if k == "password_wo" && (resp.PlannedState.GetAttr("password_hmac").RawEquals(prior.GetAttr("password_hmac")) || strings.Contains(resp.PlannedState.GoString(), "two")) {
				t.Errorf("%s: a new password left password_hmac or reached the plan", kind)
			}
		}
	}
}
