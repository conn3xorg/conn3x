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

func taskCfg(r resourceType, extra map[string]cty.Value) cty.Value {
	attrs := map[string]cty.Value{"name": cty.StringVal("Nightly"), "execute": cty.StringVal(`C:\Windows\System32\cmd.exe`), "user": cty.StringVal(`LAB\svc`), "allow_interpreter": cty.True}
	for k, v := range extra {
		attrs[k] = v
	}
	return objFor(r.schema(), attrs)
}

func TestWinTaskValidate(t *testing.T) {
	r := resourceTypes["conn3x_windows_scheduled_task"]
	if d := r.validate(taskCfg(r, map[string]cty.Value{"allow_interpreter": cty.True})); d.HasErrors() {
		t.Fatal(d.Err())
	}
	if d := r.validate(taskCfg(r, map[string]cty.Value{"allow_interpreter": cty.NullVal(cty.Bool)})); !d.HasErrors() {
		t.Error("cmd.exe without allow_interpreter was accepted")
	}
	if d := r.validate(taskCfg(r, map[string]cty.Value{"allow_interpreter": cty.True, "arguments": cty.StringVal(`/c %PUBLIC%\job`)})); !d.HasErrors() {
		t.Error("a % in arguments was accepted")
	}
	for name, a := range map[string]map[string]cty.Value{
		"relative program":   {"execute": cty.StringVal("cmd.exe")},
		"run level":          {"run_level": cty.StringVal("admin")},
		"empty password":     {"password_wo": cty.StringVal("")},
		"password on SYSTEM": {"user": cty.StringVal("SYSTEM"), "password_wo": cty.StringVal("x")},
		"bad on_remove":      {"on_remove": cty.StringVal("purge")},
	} {
		if d := r.validate(taskCfg(r, a)); !d.HasErrors() {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestWinTaskPlanPassword(t *testing.T) {
	t.Setenv(hmacKeyEnv, strings.Repeat("k", 32))
	r := resourceTypes["conn3x_windows_scheduled_task"]
	c := taskCfg(r, map[string]cty.Value{"password_wo": cty.StringVal("s3ntinel-pw")})
	resp := r.plan(providers.PlanResourceChangeRequest{PriorState: cty.NullVal(c.Type()), ProposedNewState: c, Config: c})
	p := resp.PlannedState
	if !p.GetAttr("password_wo").IsNull() || p.GetAttr("password_hmac").IsNull() || strings.Contains(p.GoString(), "s3ntinel") || p.GetAttr("on_remove").AsString() != "delete" {
		t.Fatalf("planned %#v", p)
	}
	vals := p.AsValueMap()
	vals["revision"], vals["in_sync"] = cty.StringVal("r"), cty.True
	prior := cty.ObjectVal(vals)
	if again := r.plan(providers.PlanResourceChangeRequest{PriorState: prior, ProposedNewState: prior, Config: c}).PlannedState; !again.GetAttr("in_sync").IsKnown() {
		t.Error("the same password planned a change")
	}
	other := taskCfg(r, map[string]cty.Value{"password_wo": cty.StringVal("other")})
	if changed := r.plan(providers.PlanResourceChangeRequest{PriorState: prior, ProposedNewState: prior, Config: other}).PlannedState; changed.GetAttr("in_sync").IsKnown() {
		t.Error("a new password planned no change")
	}
	t.Setenv(hmacKeyEnv, strings.Repeat("o", 32))
	ap := r.apply(context.Background(), providers.ApplyResourceChangeRequest{PriorState: prior, PlannedState: prior, Config: c})
	if !ap.Diagnostics.HasErrors() || !strings.Contains(ap.Diagnostics.Err().Error(), "hashed with key") {
		t.Errorf("got %v", ap.Diagnostics.Err())
	}
}

// A password's HMAC is stretched: the same password and key give the same
// value, and nothing a fast hash of the password would.
func TestPasswordHMACIsStretched(t *testing.T) {
	key := []byte(strings.Repeat("k", 32))
	a, b := passwordHMAC(key, "id", "hunter2"), passwordHMAC(key, "id", "hunter2")
	if a != b || !strings.HasPrefix(a, "argon2id-hmac-sha256:") || checkHMACKey(a, key) != nil {
		t.Fatalf("%q, %q", a, b)
	}
	if a == winWoHMAC(key, "id", digest("hunter2")) || a == passwordHMAC(key, "other", "hunter2") {
		t.Error("not stretched, or not bound to its id")
	}
}
