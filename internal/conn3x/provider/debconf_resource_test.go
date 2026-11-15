// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"strings"
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/providers"
)

func TestDebconfValidate(t *testing.T) {
	r := resourceTypes["conn3x_debconf"]
	base := map[string]cty.Value{"name": cty.StringVal("postfix"), "question": cty.StringVal("postfix/main_mailer_type"), "vtype": cty.StringVal("select")}
	with := func(extra map[string]cty.Value) cty.Value {
		m := map[string]cty.Value{}
		for k, v := range base {
			m[k] = v
		}
		for k, v := range extra {
			m[k] = v
		}
		return objFor(r.schema(), m)
	}
	if diags := r.validate(with(map[string]cty.Value{"value": cty.StringVal("Internet Site")})); diags.HasErrors() {
		t.Fatal(diags.Err())
	}
	for name, cfg := range map[string]cty.Value{
		"no value":     with(nil),
		"both values":  with(map[string]cty.Value{"value": cty.StringVal("a"), "value_wo": cty.StringVal("b")}),
		"bad vtype":    with(map[string]cty.Value{"vtype": cty.StringVal("seen"), "value": cty.StringVal("a")}),
		"bad boolean":  with(map[string]cty.Value{"vtype": cty.StringVal("boolean"), "value_wo": cty.StringVal("yes")}),
		"bad question": with(map[string]cty.Value{"question": cty.StringVal("main mailer"), "value": cty.StringVal("a")}),
	} {
		if diags := r.validate(cfg); !diags.HasErrors() {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Another question is another answer, so it replaces; another value or type
// updates in place. value_wo never reaches the plan, only its HMAC does.
func TestDebconfPlan(t *testing.T) {
	t.Setenv(hmacKeyEnv, strings.Repeat("k", 32))
	r := resourceTypes["conn3x_debconf"]
	cfg := objFor(r.schema(), map[string]cty.Value{"name": cty.StringVal("postfix"), "question": cty.StringVal("postfix/main_mailer_type"), "vtype": cty.StringVal("select"), "value": cty.StringVal("Internet Site")})
	created := r.plan(providers.PlanResourceChangeRequest{PriorState: cty.NullVal(cfg.Type()), ProposedNewState: cfg, Config: cfg}).PlannedState
	if got := created.GetAttr("id"); !got.RawEquals(cty.StringVal("203.0.113.10:debconf:postfix:postfix/main_mailer_type")) {
		t.Errorf("id = %#v", got)
	}
	prior := withSync(created, true)

	next := objFor(r.schema(), map[string]cty.Value{"name": cty.StringVal("postfix"), "question": cty.StringVal("postfix/main_mailer_type"), "vtype": cty.StringVal("select"), "value": cty.StringVal("Satellite system")})
	resp := r.plan(providers.PlanResourceChangeRequest{PriorState: prior, ProposedNewState: next, Config: next})
	if len(resp.RequiresReplace) != 0 || resp.PlannedState.GetAttr("in_sync").IsKnown() {
		t.Errorf("value change: replace %v, planned %#v", resp.RequiresReplace, resp.PlannedState)
	}
	next = objFor(r.schema(), map[string]cty.Value{"name": cty.StringVal("postfix"), "question": cty.StringVal("postfix/mailname"), "vtype": cty.StringVal("string"), "value": cty.StringVal("mail.example.com")})
	if resp := r.plan(providers.PlanResourceChangeRequest{PriorState: prior, ProposedNewState: next, Config: next}); len(resp.RequiresReplace) != 1 {
		t.Errorf("question change: replace %v", resp.RequiresReplace)
	}

	wo := objFor(r.schema(), map[string]cty.Value{"name": cty.StringVal("app"), "question": cty.StringVal("app/db_password"), "vtype": cty.StringVal("password"), "value_wo": cty.StringVal("s3cret")})
	planned := r.plan(providers.PlanResourceChangeRequest{PriorState: cty.NullVal(cfg.Type()), ProposedNewState: wo, Config: wo}).PlannedState
	if !planned.GetAttr("value_wo").IsNull() || !strings.HasPrefix(planned.GetAttr("value_hmac").AsString(), "hmac-sha256:") {
		t.Fatalf("planned %#v", planned)
	}
	prior = withSync(planned, true)
	if resp := r.plan(providers.PlanResourceChangeRequest{PriorState: prior, ProposedNewState: wo, Config: wo}); !resp.PlannedState.GetAttr("in_sync").RawEquals(cty.True) {
		t.Errorf("same password planned a change: %#v", resp.PlannedState)
	}
	wo = objFor(r.schema(), map[string]cty.Value{"name": cty.StringVal("app"), "question": cty.StringVal("app/db_password"), "vtype": cty.StringVal("password"), "value_wo": cty.StringVal("other")})
	if resp := r.plan(providers.PlanResourceChangeRequest{PriorState: prior, ProposedNewState: wo, Config: wo}); resp.PlannedState.GetAttr("in_sync").IsKnown() || len(resp.RequiresReplace) != 0 {
		t.Errorf("new password: %#v", resp.PlannedState)
	}
}
