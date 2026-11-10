// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/providers"
)

type commandTest struct {
	*fileTest
}

func (c commandTest) obj(attrs map[string]cty.Value) cty.Value {
	ty := commandSchema().Block.ImpliedType()
	vals := map[string]cty.Value{}
	for name, at := range ty.AttributeTypes() {
		vals[name] = cty.NullVal(at)
	}
	vals["ssh"] = c.conn
	for k, v := range attrs {
		vals[k] = v
	}
	return cty.ObjectVal(vals)
}

func (c commandTest) cycle(prior, cfg cty.Value) (cty.Value, providers.ApplyResourceChangeResponse) {
	c.t.Helper()
	proposed := cfg
	if !prior.IsNull() {
		vals := cfg.AsValueMap()
		for _, n := range []string{"id", "satisfied", "stdout", "stderr", "stdin_hmac"} {
			vals[n] = prior.GetAttr(n)
		}
		proposed = cty.ObjectVal(vals)
	}
	plan := planCommand(providers.PlanResourceChangeRequest{PriorState: prior, ProposedNewState: proposed, Config: cfg})
	resp := applyCommand(ctx, providers.ApplyResourceChangeRequest{PriorState: prior, PlannedState: plan.PlannedState, Config: cfg})
	return plan.PlannedState, resp
}

func TestCommandRunsOnceWithCreatesGuard(t *testing.T) {
	c := commandTest{newFileTest(t)}
	marker := filepath.Join(c.server.Dir, "built")
	cfg := c.obj(map[string]cty.Value{
		"command": cty.StringVal("echo run >> runs.log; touch " + marker),
		"creates": cty.StringVal(marker),
	})
	_, resp := c.cycle(cty.NullVal(cfg.Type()), cfg)
	if resp.Diagnostics.HasErrors() {
		t.Fatal(resp.Diagnostics.Err())
	}
	state := resp.NewState

	// Re-applying with nothing changed doesn't run it.
	planned, resp := c.cycle(state, cfg)
	if !planned.GetAttr("satisfied").IsKnown() {
		t.Fatal("an unchanged, satisfied command was planned to run")
	}
	runs, _ := os.ReadFile(filepath.Join(c.server.Dir, "runs.log"))
	if strings.Count(string(runs), "run") != 1 {
		t.Fatalf("ran %d times, want 1", strings.Count(string(runs), "run"))
	}

	// Deleting what it creates is drift: refresh notices and it runs again.
	_ = os.Remove(marker)
	read := c.p.ReadResource(ctx, providers.ReadResourceRequest{TypeName: "conn3x_command", PriorState: resp.NewState})
	if read.NewState.GetAttr("satisfied").True() {
		t.Fatal("refresh did not notice the missing creates path")
	}
	planned, resp = c.cycle(read.NewState, cfg)
	if planned.GetAttr("satisfied").IsKnown() || resp.Diagnostics.HasErrors() {
		t.Fatalf("drift not re-run: %v", resp.Diagnostics.Err())
	}
	if runs, _ := os.ReadFile(filepath.Join(c.server.Dir, "runs.log")); strings.Count(string(runs), "run") != 2 {
		t.Fatal("command did not run again after drift")
	}
}

func TestCommandFailureIsAnError(t *testing.T) {
	c := commandTest{newFileTest(t)}
	cfg := c.obj(map[string]cty.Value{"command": cty.StringVal("echo nope >&2; exit 3")})
	_, resp := c.cycle(cty.NullVal(cfg.Type()), cfg)
	if !resp.Diagnostics.HasErrors() || !strings.Contains(resp.Diagnostics.Err().Error(), "nope") {
		t.Fatalf("diagnostics = %v", resp.Diagnostics.Err())
	}
}

func TestCommandWhoseGuardNeverHoldsIsAnError(t *testing.T) {
	c := commandTest{newFileTest(t)}
	cfg := c.obj(map[string]cty.Value{
		"command": cty.StringVal("true"),
		"creates": cty.StringVal(filepath.Join(c.server.Dir, "never")),
	})
	_, resp := c.cycle(cty.NullVal(cfg.Type()), cfg)
	if !resp.Diagnostics.HasErrors() || !strings.Contains(resp.Diagnostics.Err().Error(), "guards still don't hold") {
		t.Fatalf("diagnostics = %v", resp.Diagnostics.Err())
	}
}

func TestCommandChangeReruns(t *testing.T) {
	c := commandTest{newFileTest(t)}
	cfg := c.obj(map[string]cty.Value{"command": cty.StringVal("true")})
	_, resp := c.cycle(cty.NullVal(cfg.Type()), cfg)
	changed := c.obj(map[string]cty.Value{"command": cty.StringVal("true # v2")})
	proposed := changed.AsValueMap()
	for _, n := range []string{"id", "satisfied", "stdout", "stderr"} {
		proposed[n] = resp.NewState.GetAttr(n)
	}
	plan := planCommand(providers.PlanResourceChangeRequest{PriorState: resp.NewState, ProposedNewState: cty.ObjectVal(proposed), Config: changed})
	if len(plan.RequiresReplace) == 0 {
		t.Fatal("changing the command did not plan a re-run")
	}
}

// stdin_wo reaches the command on standard input and nowhere else: not the
// command line, not state, not the output kept. Changing it runs the
// command again; leaving it alone doesn't.
func TestCommandSecretInput(t *testing.T) {
	t.Setenv(hmacKeyEnv, strings.Repeat("k", 32))
	c := commandTest{newFileTest(t)}
	got := filepath.Join(c.server.Dir, "got")
	cfg := func(secret string) cty.Value {
		return c.obj(map[string]cty.Value{
			"command":  cty.StringVal("cat > " + got + "; cat " + got),
			"stdin_wo": cty.StringVal(secret),
		})
	}
	planned, resp := c.cycle(cty.NullVal(cfg("x").Type()), cfg("hunter2-token"))
	if resp.Diagnostics.HasErrors() {
		t.Fatal(resp.Diagnostics.Err())
	}
	if b, _ := os.ReadFile(got); string(b) != "hunter2-token" {
		t.Fatalf("the command read %q", b)
	}
	state := resp.NewState
	if !planned.GetAttr("stdin_wo").IsNull() || !state.GetAttr("stdin_wo").IsNull() || !strings.HasPrefix(state.GetAttr("stdin_hmac").AsString(), "hmac-sha256:") {
		t.Fatalf("planned %#v, state stdin_wo %#v, stdin_hmac %#v", planned.GetAttr("stdin_wo"), state.GetAttr("stdin_wo"), state.GetAttr("stdin_hmac"))
	}
	if out := state.GetAttr("stdout").AsString(); strings.Contains(out, "hunter2") {
		t.Fatalf("stdout kept the secret: %q", out)
	}

	if planned, _ := c.cycle(state, cfg("hunter2-token")); !planned.GetAttr("satisfied").IsKnown() {
		t.Error("the same secret planned a rerun")
	}
	planned, resp = c.cycle(state, cfg("rotated-token"))
	if planned.GetAttr("satisfied").IsKnown() || resp.Diagnostics.HasErrors() {
		t.Fatalf("a new secret did not rerun: %v", resp.Diagnostics.Err())
	}
	if b, _ := os.ReadFile(got); string(b) != "rotated-token" {
		t.Fatalf("after the change the command read %q", b)
	}

	// A failing command's error shows its output, minus the secret.
	fail := c.obj(map[string]cty.Value{"command": cty.StringVal("cat >&2; exit 1"), "stdin_wo": cty.StringVal("hunter2-token")})
	_, resp = c.cycle(cty.NullVal(fail.Type()), fail)
	if err := resp.Diagnostics.Err(); err == nil || strings.Contains(err.Error(), "hunter2") {
		t.Fatalf("diagnostics = %v", err)
	}

	if diags := validateCommand(c.obj(map[string]cty.Value{"command": cty.StringVal("true"), "stdin_wo": cty.StringVal("")})); !diags.HasErrors() {
		t.Error("an empty stdin_wo was accepted")
	}
}
