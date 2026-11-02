// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"strings"
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/providers"
)

func TestWinRegistryValidate(t *testing.T) {
	r := resourceTypes["conn3x_windows_registry_value"]
	base := func(extra map[string]cty.Value) cty.Value {
		attrs := map[string]cty.Value{"key": cty.StringVal(`HKLM\SOFTWARE\App`), "name": cty.StringVal("x"), "type": cty.StringVal("dword")}
		for k, v := range extra {
			attrs[k] = v
		}
		return objFor(r.schema(), attrs)
	}
	if d := r.validate(base(map[string]cty.Value{"data": cty.StringVal("1")})); d.HasErrors() {
		t.Fatal(d.Err())
	}
	for name, cfg := range map[string]cty.Value{
		"no data":     base(nil),
		"both":        base(map[string]cty.Value{"data": cty.StringVal("1"), "data_wo": cty.StringVal("2")}),
		"not decimal": base(map[string]cty.Value{"data": cty.StringVal("0xff")}),
		"too big":     base(map[string]cty.Value{"data": cty.StringVal("4294967296")}),
		"other hive":  base(map[string]cty.Value{"data": cty.StringVal("1"), "key": cty.StringVal(`HKCU\x`)}),
		"traversal":   base(map[string]cty.Value{"data": cty.StringVal("1"), "key": cty.StringVal(`HKLM\a\..\b`)}),
		"bad type":    base(map[string]cty.Value{"data": cty.StringVal("1"), "type": cty.StringVal("none")}),
	} {
		if d := r.validate(cfg); !d.HasErrors() {
			t.Errorf("%s: accepted", name)
		}
	}
	// A bad secret's error doesn't quote it.
	d := r.validate(base(map[string]cty.Value{"data_wo": cty.StringVal("hunter2")}))
	if !d.HasErrors() || strings.Contains(d.Err().Error(), "hunter2") {
		t.Errorf("diagnostics: %v", d.Err())
	}
}

func TestWinRegistryPlanSecret(t *testing.T) {
	t.Setenv(hmacKeyEnv, strings.Repeat("k", 32))
	r := resourceTypes["conn3x_windows_registry_value"]
	cfg := func(s string) cty.Value {
		return objFor(r.schema(), map[string]cty.Value{"key": cty.StringVal(`HKLM\SOFTWARE\App`), "name": cty.StringVal("t"), "type": cty.StringVal("string"), "data_wo": cty.StringVal(s)})
	}
	c := cfg("s3ntinel")
	p := r.plan(providers.PlanResourceChangeRequest{PriorState: cty.NullVal(c.Type()), ProposedNewState: c, Config: c}).PlannedState
	if !p.GetAttr("data_wo").IsNull() || !p.GetAttr("data").IsNull() || p.GetAttr("data_hmac").IsNull() {
		t.Fatalf("planned %#v", p)
	}
	vals := p.AsValueMap()
	vals["revision"], vals["in_sync"] = cty.StringVal("r"), cty.True
	prior := cty.ObjectVal(vals)
	if again := r.plan(providers.PlanResourceChangeRequest{PriorState: prior, ProposedNewState: prior, Config: c}).PlannedState; !again.GetAttr("in_sync").IsKnown() {
		t.Error("the same secret planned a change")
	}
	if changed := r.plan(providers.PlanResourceChangeRequest{PriorState: prior, ProposedNewState: prior, Config: cfg("other")}).PlannedState; changed.GetAttr("in_sync").IsKnown() {
		t.Error("a new secret planned no change")
	}
}

func TestWinServiceAndFeatureValidate(t *testing.T) {
	s := resourceTypes["conn3x_windows_service"]
	if d := s.validate(objFor(s.schema(), map[string]cty.Value{"name": cty.StringVal("W3SVC"), "state": cty.StringVal("running")})); d.HasErrors() {
		t.Fatal(d.Err())
	}
	for name, a := range map[string]map[string]cty.Value{
		"wildcard":      {"name": cty.StringVal("W3*"), "state": cty.StringVal("running")},
		"quote":         {"name": cty.StringVal("a'b"), "state": cty.StringVal("running")},
		"nothing":       {"name": cty.StringVal("W3SVC")},
		"bad mode":      {"name": cty.StringVal("W3SVC"), "start_mode": cty.StringVal("boot")},
		"bad state":     {"name": cty.StringVal("W3SVC"), "state": cty.StringVal("paused")},
		"contradiction": {"name": cty.StringVal("W3SVC"), "start_mode": cty.StringVal("disabled"), "state": cty.StringVal("running")},
	} {
		if d := s.validate(objFor(s.schema(), a)); !d.HasErrors() {
			t.Errorf("service %s: accepted", name)
		}
	}
	f := resourceTypes["conn3x_windows_feature"]
	if d := f.validate(objFor(f.schema(), map[string]cty.Value{"name": cty.StringVal("Web-Server")})); d.HasErrors() {
		t.Fatal(d.Err())
	}
	for _, bad := range []string{"Web-*", "a b", "$(x)", "-x"} {
		if d := f.validate(objFor(f.schema(), map[string]cty.Value{"name": cty.StringVal(bad)})); !d.HasErrors() {
			t.Errorf("feature %q: accepted", bad)
		}
	}
	if d := f.validate(objFor(f.schema(), map[string]cty.Value{"name": cty.StringVal("x"), "state": cty.StringVal("gone")})); !d.HasErrors() {
		t.Error("accepted a bad state")
	}
}

func TestWinFeaturePlanKeepsRebootFlag(t *testing.T) {
	f := resourceTypes["conn3x_windows_feature"]
	c := objFor(f.schema(), map[string]cty.Value{"name": cty.StringVal("Web-Server")})
	p := f.plan(providers.PlanResourceChangeRequest{PriorState: cty.NullVal(c.Type()), ProposedNewState: c, Config: c}).PlannedState
	if p.GetAttr("reboot_required").IsKnown() {
		t.Fatal("a new feature planned a known reboot_required")
	}
	vals := p.AsValueMap()
	vals["revision"], vals["in_sync"], vals["reboot_required"] = cty.StringVal("r"), cty.True, cty.True
	prior := cty.ObjectVal(vals)
	again := f.plan(providers.PlanResourceChangeRequest{PriorState: prior, ProposedNewState: prior, Config: c}).PlannedState
	if !again.GetAttr("reboot_required").RawEquals(cty.True) {
		t.Errorf("reboot_required = %#v", again.GetAttr("reboot_required"))
	}
}
