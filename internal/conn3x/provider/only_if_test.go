// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/plans/objchange"
	"github.com/opentofu/opentofu/internal/providers"
)

var gatedFile = withOnlyIf(fileSchema()).Block

// cfgWith is base, a type's own config, as OpenTofu sends it: with
// only_if cond and skipped null.
func cfgWith(base, cond cty.Value) cty.Value {
	vals := base.AsValueMap()
	vals["only_if"], vals["skipped"] = cond, cty.NullVal(cty.Bool)
	out, err := gatedFile.CoerceValue(cty.ObjectVal(vals)) // fills in the ssh settings left out
	if err != nil {
		panic(err)
	}
	return out
}

// gatedPlan plans as OpenTofu does: config proposed over prior.
func (f *fileTest) gatedPlan(prior, cfg cty.Value) providers.PlanResourceChangeResponse {
	f.t.Helper()
	resp := f.p.PlanResourceChange(ctx, providers.PlanResourceChangeRequest{
		TypeName: "conn3x_file", PriorState: prior, Config: cfg,
		ProposedNewState: objchange.ProposedNew(gatedFile, prior, cfg),
	})
	if resp.Diagnostics.HasErrors() {
		f.t.Fatalf("plan: %s", resp.Diagnostics.Err())
	}
	if !resp.PlannedState.GetAttr("only_if").IsNull() {
		f.t.Fatal("planned state holds only_if, which is write-only")
	}
	return resp
}

// gatedApply plans again with what the apply knows, checks that against
// the earlier plan as OpenTofu does, and applies.
func (f *fileTest) gatedApply(prior, planned, cfg cty.Value) cty.Value {
	f.t.Helper()
	final := f.gatedPlan(prior, cfg).PlannedState
	for _, err := range objchange.AssertObjectCompatible(gatedFile, planned, final) {
		f.t.Fatalf("final plan doesn't match the plan: %s", err)
	}
	return f.apply(prior, final, cfg)
}

func TestOnlyIfSchema(t *testing.T) {
	schemas := resourceSchemas()
	for name := range resourceTypes {
		a := schemas[name].Block.Attributes["only_if"]
		if want := gatedType(name); (a != nil) != want {
			t.Errorf("%s: only_if = %v, want it: %v", name, a != nil, want)
		} else if a != nil && !a.WriteOnly {
			t.Errorf("%s: only_if isn't write-only", name)
		}
	}
	for _, name := range []string{"conn3x_file", "conn3x_command", "conn3x_package", "conn3x_service_action", "conn3x_windows_file", "conn3x_windows_service"} {
		if !gatedType(name) {
			t.Errorf("%s doesn't take only_if", name)
		}
	}
	for _, name := range []string{"conn3x_eos_vlan", "conn3x_junos_config", "conn3x_vyos_interface", "conn3x_ios_hostname", "conn3x_eos_commit"} {
		if gatedType(name) {
			t.Errorf("network type %s takes only_if", name)
		}
	}
	if _, ok := fileSchema().Block.Attributes["only_if"]; ok {
		t.Error("withOnlyIf changed the type's own schema")
	}
}

func TestOnlyIfFalseSkipsAndTouchesNothing(t *testing.T) {
	f := newFileTest(t)
	cfg := cfgWith(f.config(map[string]cty.Value{"content": cty.StringVal("hi\n")}), cty.False)
	null := cty.NullVal(gatedFile.ImpliedType())
	planned := f.gatedPlan(null, cfg).PlannedState
	if !planned.GetAttr("skipped").RawEquals(cty.True) || planned.GetAttr("revision").IsKnown() {
		t.Fatalf("planned skipped = %#v, revision = %#v", planned.GetAttr("skipped"), planned.GetAttr("revision"))
	}
	state := f.gatedApply(null, planned, cfg)
	if _, err := os.Stat(f.path); !os.IsNotExist(err) {
		t.Fatalf("a skipped step wrote the file: %v", err)
	}
	if !state.GetAttr("id").IsNull() || !state.GetAttr("sha256").IsNull() {
		t.Fatalf("a skipped step records what it read: %#v", state)
	}
	if read := f.read(state); !read.RawEquals(state) {
		t.Fatalf("refresh changed a skipped step:\n%#v", read)
	}
	if again := f.gatedPlan(state, cfg); !again.PlannedState.RawEquals(state) || len(again.RequiresReplace) > 0 {
		t.Fatalf("second plan isn't clean:\n%#v\nwas\n%#v", again.PlannedState, state)
	}
	if err := os.WriteFile(f.path, []byte("theirs\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if gone := f.apply(state, null, null); !gone.IsNull() {
		t.Fatalf("destroy = %#v", gone)
	}
	if b, _ := os.ReadFile(f.path); string(b) != "theirs\n" {
		t.Fatal("removing a skipped step touched the host")
	}
}

func TestOnlyIfTrueRunsAsUsual(t *testing.T) {
	f := newFileTest(t)
	cfg := cfgWith(f.config(map[string]cty.Value{"content": cty.StringVal("hi\n")}), cty.True)
	null := cty.NullVal(gatedFile.ImpliedType())
	planned := f.gatedPlan(null, cfg).PlannedState
	state := f.gatedApply(null, planned, cfg)
	if b, _ := os.ReadFile(f.path); string(b) != "hi\n" {
		t.Fatalf("file = %q", b)
	}
	if !state.GetAttr("skipped").IsNull() || state.GetAttr("revision").AsString() == "" {
		t.Fatalf("skipped = %#v, revision = %#v", state.GetAttr("skipped"), state.GetAttr("revision"))
	}
	if again := f.gatedPlan(f.read(state), cfg); !again.PlannedState.RawEquals(state) {
		t.Fatalf("second plan isn't clean:\n%#v", again.PlannedState)
	}
}

func TestOnlyIfUnknown(t *testing.T) {
	f := newFileTest(t)
	unknown := cfgWith(f.config(map[string]cty.Value{"content": cty.StringVal("hi\n")}), cty.UnknownVal(cty.Bool))
	null := cty.NullVal(gatedFile.ImpliedType())
	planned := f.gatedPlan(null, unknown).PlannedState
	for _, name := range []string{"skipped", "id", "sha256", "revision"} {
		if planned.GetAttr(name).IsKnown() {
			t.Errorf("%s planned as %#v, but the step may not run", name, planned.GetAttr(name))
		}
	}
	if !planned.GetAttr("content").RawEquals(cty.StringVal("hi\n")) {
		t.Errorf("content = %#v", planned.GetAttr("content"))
	}

	// The apply learns the answer either way, and both match the plan.
	skipped := f.gatedApply(null, planned, cfgWith(unknown, cty.False))
	if !wasSkipped(skipped) {
		t.Fatalf("false at apply: %#v", skipped)
	}
	if _, err := os.Stat(f.path); !os.IsNotExist(err) {
		t.Fatal("skipped at apply, but the file was written")
	}
	// From skipped, while unknown, it may run: a change, not a clean plan.
	again := f.gatedPlan(skipped, unknown).PlannedState
	if again.GetAttr("skipped").IsKnown() || len(f.gatedPlan(skipped, unknown).RequiresReplace) > 0 {
		t.Fatalf("a skipped step whose only_if isn't known plans %#v", again)
	}
	ran := f.gatedApply(skipped, again, cfgWith(unknown, cty.True))
	if b, _ := os.ReadFile(f.path); string(b) != "hi\n" || wasSkipped(ran) {
		t.Fatalf("true at apply: file %q, state %#v", b, ran)
	}

	// A step in line does nothing whatever the answer, so it plans nothing.
	if inLine := f.gatedPlan(f.read(ran), unknown); !inLine.PlannedState.RawEquals(ran) {
		t.Fatalf("a step in line with an unknown only_if plans a change:\n%#v", inLine.PlannedState)
	}
}

func TestOnlyIfFalseLeavesAStepThatRan(t *testing.T) {
	f := newFileTest(t)
	null := cty.NullVal(gatedFile.ImpliedType())
	on := cfgWith(f.config(map[string]cty.Value{"content": cty.StringVal("v1\n")}), cty.True)
	ran := f.gatedApply(null, f.gatedPlan(null, on).PlannedState, on)
	rev := ran.GetAttr("revision")

	// The probe now says it needn't run: in line, it stays as it is.
	off := cfgWith(on, cty.False)
	if p := f.gatedPlan(f.read(ran), off); !p.PlannedState.RawEquals(ran) {
		t.Fatalf("only_if false on a step in line plans a change:\n%#v", p.PlannedState)
	}

	// Its arguments change while only_if is false: recorded as skipped,
	// the host left alone and the revision kept, so no handler fires.
	changed := cfgWith(f.config(map[string]cty.Value{"content": cty.StringVal("v2\n")}), cty.False)
	p := f.gatedPlan(ran, changed)
	if len(p.RequiresReplace) > 0 || !wasSkipped(p.PlannedState) {
		t.Fatalf("plan = %#v, replace %v", p.PlannedState, p.RequiresReplace)
	}
	state := f.gatedApply(ran, p.PlannedState, changed)
	if b, _ := os.ReadFile(f.path); string(b) != "v1\n" {
		t.Fatalf("a skipped step changed the file to %q", b)
	}
	if !state.GetAttr("revision").RawEquals(rev) {
		t.Fatalf("revision %#v, was %#v", state.GetAttr("revision"), rev)
	}

	// only_if turns true: a first run.
	back := cfgWith(changed, cty.True)
	final := f.gatedApply(state, f.gatedPlan(state, back).PlannedState, back)
	if b, _ := os.ReadFile(f.path); string(b) != "v2\n" || final.GetAttr("revision").RawEquals(rev) {
		t.Fatalf("file %q, revision %#v", b, final.GetAttr("revision"))
	}
}

func TestOnlyIfStepWithoutItIsUnchanged(t *testing.T) {
	f := newFileTest(t)
	cfg := cfgWith(f.config(map[string]cty.Value{"content": cty.StringVal("hi\n")}), cty.NullVal(cty.Bool))
	null := cty.NullVal(gatedFile.ImpliedType())
	state := f.gatedApply(null, f.gatedPlan(null, cfg).PlannedState, cfg)
	if !state.GetAttr("skipped").IsNull() {
		t.Fatalf("skipped = %#v without only_if", state.GetAttr("skipped"))
	}
	own := stripGate(cfg)
	base := f.plan(cty.NullVal(own.Type()), own).PlannedState
	if !stripGate(f.gatedPlan(null, cfg).PlannedState).RawEquals(base) {
		t.Fatal("a step without only_if plans differently through the gate")
	}
}

func TestOnlyIfValidateStillChecksTheStep(t *testing.T) {
	f := newFileTest(t)
	bad := cfgWith(f.config(map[string]cty.Value{"content": cty.StringVal("x"), "mode": cty.StringVal("rwx")}), cty.UnknownVal(cty.Bool))
	if err := f.p.ValidateResourceConfig(ctx, providers.ValidateResourceConfigRequest{TypeName: "conn3x_file", Config: bad}).Diagnostics.Err(); err == nil || !strings.Contains(err.Error(), "mode") {
		t.Fatalf("an unknown only_if hid a bad mode: %v", err)
	}
	vals := cfgWith(f.config(map[string]cty.Value{"content": cty.StringVal("x")}), cty.True).AsValueMap()
	vals["skipped"] = cty.True
	if err := f.p.ValidateResourceConfig(ctx, providers.ValidateResourceConfigRequest{TypeName: "conn3x_file", Config: cty.ObjectVal(vals)}).Diagnostics.Err(); err == nil || !strings.Contains(err.Error(), "skipped") {
		t.Fatalf("skipped set in config: %v", err)
	}
}

func TestOnlyIfUpgradeKeepsSkipped(t *testing.T) {
	p, _ := New()
	for raw, want := range map[string]cty.Value{
		`{"path":"/etc/x","content":"x","skipped":true}`: cty.True,
		`{"path":"/etc/x","content":"x"}`:                cty.NullVal(cty.Bool),
	} {
		resp := p.UpgradeResourceState(ctx, providers.UpgradeResourceStateRequest{TypeName: "conn3x_file", RawStateJSON: []byte(raw)})
		if err := resp.Diagnostics.Err(); err != nil {
			t.Fatalf("%s: %v", raw, err)
		}
		if got := resp.UpgradedState.GetAttr("skipped"); !got.RawEquals(want) {
			t.Errorf("%s: skipped = %#v", raw, got)
		}
		if !resp.UpgradedState.Type().Equals(gatedFile.ImpliedType()) {
			t.Errorf("%s: upgraded to the type's own shape", raw)
		}
	}
}

// A handler watches its steps' revisions and is replaced, so it acts,
// when one changes or isn't known at plan. A gated step's isn't known
// while its only_if isn't; when the apply then skips it, the handler is
// still replaced, as planned, but mustn't act.
func TestHandlerDoesNotActForASkippedStep(t *testing.T) {
	f := newFileTest(t)
	p := f.p.(*Provider)
	null := cty.NullVal(gatedFile.ImpliedType())
	unknown := cfgWith(f.config(map[string]cty.Value{"content": cty.StringVal("hi\n")}), cty.UnknownVal(cty.Bool))
	skipped := f.gatedApply(null, f.gatedPlan(null, unknown).PlannedState, cfgWith(unknown, cty.False))

	action := func(triggers cty.Value) []string {
		t.Helper()
		before := len(f.server.Commands())
		cfg := dressGate(actionObj(map[string]cty.Value{"name": cty.StringVal("dummy"), "triggers": triggers}), cty.NullVal(cty.Bool), withOnlyIf(serviceActionSchema()).Block.ImpliedType())
		vals := cfg.AsValueMap()
		vals["ssh"] = f.connFor(vals["ssh"])
		cfg, err := withOnlyIf(serviceActionSchema()).Block.CoerceValue(cty.ObjectVal(vals))
		if err != nil {
			t.Fatal(err)
		}
		prior := cty.NullVal(cfg.Type())
		plan := p.PlanResourceChange(ctx, providers.PlanResourceChangeRequest{TypeName: "conn3x_service_action", PriorState: prior, Config: cfg, ProposedNewState: objchange.ProposedNew(withOnlyIf(serviceActionSchema()).Block, prior, cfg)})
		if err := plan.Diagnostics.Err(); err != nil {
			t.Fatal(err)
		}
		p.ApplyResourceChange(ctx, providers.ApplyResourceChangeRequest{TypeName: "conn3x_service_action", PriorState: prior, PlannedState: plan.PlannedState, Config: cfg})
		return slices.Clone(f.commands()[before:])
	}
	ran := func(cmds []string) bool {
		return slices.ContainsFunc(cmds, func(c string) bool { return strings.Contains(c, "systemctl") })
	}

	if cmds := action(cty.TupleVal([]cty.Value{skipped.GetAttr("revision")})); ran(cmds) {
		t.Fatalf("the handler of a skipped step acted: %q", cmds)
	}
	// Another step it watches changed in this apply: it acts.
	on := cfgWith(unknown, cty.True)
	ranState := f.gatedApply(skipped, f.gatedPlan(skipped, on).PlannedState, on)
	if cmds := action(cty.TupleVal([]cty.Value{skipped.GetAttr("revision"), ranState.GetAttr("revision")})); !ran(cmds) {
		t.Fatalf("the handler of a step that ran didn't act: %q", cmds)
	}
	// Watching nothing that was skipped, a create acts as it always has.
	if cmds := action(cty.TupleVal([]cty.Value{cty.StringVal("from-an-earlier-apply")})); !ran(cmds) {
		t.Fatalf("a new handler didn't act: %q", cmds)
	}
}

// connFor is the test server's ssh block in the shape of v.
func (f *fileTest) connFor(v cty.Value) cty.Value {
	vals := v.AsValueMap()
	for k, c := range f.conn.AsValueMap() {
		vals[k] = c
	}
	return cty.ObjectVal(vals)
}

// A step skipped before it ever ran keeps a revision of its own, so a
// handler whose triggers hold "" (as try(x.revision, "") gives) isn't
// held back by an unrelated skip in the same apply.
func TestOnlyIfNeverRanSkipHasOwnRevision(t *testing.T) {
	planned := cty.ObjectVal(map[string]cty.Value{"revision": cty.UnknownVal(cty.String)})
	a, b := skipMark(planned).GetAttr("revision"), skipMark(planned).GetAttr("revision")
	if !strings.HasPrefix(a.AsString(), "skip:") || a.RawEquals(b) {
		t.Fatalf("never-ran skip revisions %q and %q", a.AsString(), b.AsString())
	}
	p := &Provider{}
	p.ran.skip(a)
	handler := cty.ObjectVal(map[string]cty.Value{"triggers": cty.MapVal(map[string]cty.Value{"cert": cty.StringVal("")})})
	if p.onlySkipped(providers.ApplyResourceChangeRequest{PriorState: cty.NullVal(handler.Type()), PlannedState: handler}) {
		t.Fatal("a handler whose triggers hold \"\" was held back by an unrelated skip")
	}
	watching := cty.ObjectVal(map[string]cty.Value{"triggers": cty.MapVal(map[string]cty.Value{"step": a})})
	if !p.onlySkipped(providers.ApplyResourceChangeRequest{PriorState: cty.NullVal(watching.Type()), PlannedState: watching}) {
		t.Fatal("a handler watching only the skipped step acted")
	}
}
