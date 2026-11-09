// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"strings"
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/providers"
)

func grantsVal(db string, privs ...string) cty.Value {
	var ps []cty.Value
	for _, p := range privs {
		ps = append(ps, cty.StringVal(p))
	}
	return cty.MapVal(map[string]cty.Value{db: cty.SetVal(ps)})
}

func TestMysqlValidate(t *testing.T) {
	db := resourceTypes["conn3x_mysql_database"]
	if d := db.validate(objFor(db.schema(), map[string]cty.Value{"name": cty.StringVal("app"), "charset": cty.StringVal("utf8mb4"), "collation": cty.StringVal("utf8mb4_unicode_ci")})); d.HasErrors() {
		t.Fatal(d.Err())
	}
	for name, a := range map[string]map[string]cty.Value{
		"empty":         {"name": cty.StringVal("")},
		"too long":      {"name": cty.StringVal(strings.Repeat("a", 65))},
		"bad charset":   {"name": cty.StringVal("app"), "charset": cty.StringVal("utf8' x")},
		"bad on_remove": {"name": cty.StringVal("app"), "on_remove": cty.StringVal("purge")},
	} {
		if d := db.validate(objFor(db.schema(), a)); !d.HasErrors() {
			t.Errorf("database %s: accepted", name)
		}
	}
	user := resourceTypes["conn3x_mysql_user"]
	if d := user.validate(objFor(user.schema(), map[string]cty.Value{"name": cty.StringVal("app"), "host": cty.StringVal("10.0.0.%"), "password_wo": cty.StringVal(`s3cret 'x' \`), "grants": grantsVal("app", "SELECT", "INSERT")})); d.HasErrors() {
		t.Fatal(d.Err())
	}
	for name, a := range map[string]map[string]cty.Value{
		"root":           {"name": cty.StringVal("root")},
		"bad privilege":  {"name": cty.StringVal("app"), "grants": grantsVal("app", "FILE")},
		"empty password": {"name": cty.StringVal("app"), "password_wo": cty.StringVal("")},
		"line break":     {"name": cty.StringVal("app"), "password_wo": cty.StringVal("a\nb")},
		"bad host":       {"name": cty.StringVal("app"), "host": cty.StringVal("a host")},
	} {
		if d := user.validate(objFor(user.schema(), a)); !d.HasErrors() {
			t.Errorf("user %s: accepted", name)
		}
	}
}

// A new name, or for a user a new host, is a new object; every other
// setting changes in place. An unset host is localhost.
func TestMysqlPlan(t *testing.T) {
	t.Setenv(hmacKeyEnv, strings.Repeat("k", 32))
	for kind, base := range map[string]map[string]cty.Value{
		"conn3x_mysql_database": {"name": cty.StringVal("app"), "charset": cty.StringVal("utf8mb4")},
		"conn3x_mysql_user":     {"name": cty.StringVal("app"), "grants": grantsVal("app", "SELECT"), "password_wo": cty.StringVal("one")},
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
		keys := map[string]cty.Value{"name": cty.StringVal("App")}
		changes := map[string]cty.Value{"collation": cty.StringVal("utf8mb4_bin")}
		if kind == "conn3x_mysql_user" {
			if h := prior.GetAttr("host"); h.AsString() != "localhost" {
				t.Errorf("host defaulted to %s", h.AsString())
			}
			keys["host"] = cty.StringVal("%")
			changes = map[string]cty.Value{"grants": grantsVal("app", "ALL"), "password_wo": cty.StringVal("two")}
		}
		for k, v := range keys {
			if resp := plan(cfg(k, v)); len(resp.RequiresReplace) == 0 {
				t.Errorf("%s: a new %s didn't replace", kind, k)
			}
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
