// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"encoding/json"
	"maps"
	"strings"
	"sync"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/plans/objchange"
	"github.com/opentofu/opentofu/internal/providers"
)

// only_if is a step's condition that may not be known until the apply,
// such as the exit code of a probe that reads the host after earlier steps
// changed it. when can't take one: it decides which instances exist, and
// that has to be known at plan.
//
// Every Linux and Windows step type takes it. The resource types don't see
// it: this layer strips only_if and skipped before calling them and puts
// skipped back on what they return.
//
// At apply, a step whose only_if is true runs as usual. One whose only_if
// is false does nothing on the host. If it never ran, or would change
// something were it to run, it's recorded as skipped: its arguments and
// skipped = true, with nothing read from the host and its revision kept, so
// what watches the revision doesn't fire. A skipped step owns nothing, so
// refresh doesn't read it and removing it touches nothing; when only_if
// turns true it runs as a first run. A step that ran and is still in line
// stays as it is while only_if is false, so a probe that now says "no need"
// doesn't make the next plan change it.
//
// While only_if isn't known, a step in line plans no change (it would do
// nothing either way), and any other plans as it would run, with skipped
// and everything it reads from the host left unknown: the plan says the
// step may change.
//
// only_if is write-only, so state doesn't keep the answer: stored, the
// probe flipping from "missing" to "there" after an install would show as
// a change on the next plan.

// gatedType reports whether a resource type takes only_if: every step type
// but the network devices', whose lines one commit per device applies.
func gatedType(name string) bool {
	if _, ok := resourceTypes[name]; !ok || name == "conn3x_test_container" {
		return false
	}
	for _, prefix := range []string{eosTypePrefix, junosTypePrefix, vyosTypePrefix, iosTypePrefix} {
		if strings.HasPrefix(name, prefix) {
			return false
		}
	}
	return true
}

// withOnlyIf adds only_if and skipped to a resource type's schema, on a
// copy, since a schema function may hand out a shared block.
func withOnlyIf(s providers.Schema) providers.Schema {
	b := *s.Block
	b.Attributes = maps.Clone(s.Block.Attributes)
	b.Attributes["only_if"] = &configschema.Attribute{
		Type: cty.Bool, Optional: true, WriteOnly: true,
		Description: "Run the step only when this is true. Unlike when, it may depend on what only the apply knows, such as a probe that reads the host after earlier steps. While it is false the step does nothing on the host. Not kept in state.",
	}
	b.Attributes["skipped"] = &configschema.Attribute{
		Type: cty.Bool, Computed: true,
		Description: "true while only_if kept the step from running, so it manages nothing on the host; null otherwise.",
	}
	s.Block = &b
	return s
}

// hasGate reports whether v has the type with only_if and skipped, as
// everything OpenTofu sends does. A test that calls the provider with a
// type's own shape gets the type's own behaviour.
func hasGate(v cty.Value) bool {
	ty := v.Type()
	return ty.IsObjectType() && ty.HasAttribute("skipped") && ty.HasAttribute("only_if")
}

// stripGate removes only_if and skipped from a known object.
func stripGate(v cty.Value) cty.Value {
	if !hasGate(v) {
		return v
	}
	attrs := maps.Clone(v.Type().AttributeTypes())
	delete(attrs, "only_if")
	delete(attrs, "skipped")
	if v.IsNull() || !v.IsKnown() {
		if v.IsNull() {
			return cty.NullVal(cty.Object(attrs))
		}
		return cty.UnknownVal(cty.Object(attrs))
	}
	vals := v.AsValueMap()
	delete(vals, "only_if")
	delete(vals, "skipped")
	return cty.ObjectVal(vals)
}

// dressGate puts only_if (always null: it's write-only) and skipped on what
// a resource type returned, as type full.
func dressGate(v, skipped cty.Value, full cty.Type) cty.Value {
	if v.IsNull() {
		return cty.NullVal(full)
	}
	if !v.IsKnown() {
		return cty.UnknownVal(full)
	}
	vals := v.AsValueMap()
	vals["only_if"] = cty.NullVal(cty.Bool)
	vals["skipped"] = skipped
	return cty.ObjectVal(vals)
}

// wasSkipped reports whether state holds a skipped step, which owns nothing.
func wasSkipped(state cty.Value) bool {
	if !hasGate(state) || state.IsNull() || !state.IsKnown() {
		return false
	}
	s := state.GetAttr("skipped")
	return s.IsKnown() && !s.IsNull() && s.True()
}

// gatedSkipped is skipped for a step that runs: null, or what it was.
func gatedSkipped(prior cty.Value) cty.Value {
	if hasGate(prior) && !prior.IsNull() && prior.IsKnown() && !wasSkipped(prior) {
		return prior.GetAttr("skipped")
	}
	return cty.NullVal(cty.Bool)
}

// onlyIf is the step's only_if; null without one, or with no config.
func onlyIf(cfg cty.Value) cty.Value {
	if !hasGate(cfg) || cfg.IsNull() || !cfg.IsKnown() {
		return cty.NullVal(cty.Bool)
	}
	return cfg.GetAttr("only_if")
}

// skippedState is what a skipped step records: planned with everything
// only the host can say (the computed-only attributes) null, and rev as
// its revision. What's still unknown is null too: nothing ran to learn it.
func skippedState(block *configschema.Block, planned, rev cty.Value) cty.Value {
	vals := planned.AsValueMap()
	for name, attr := range block.Attributes {
		if attr.Computed && !attr.Optional {
			vals[name] = cty.NullVal(attr.Type)
		}
	}
	if _, ok := block.Attributes["revision"]; ok {
		vals["revision"] = rev
	}
	return cty.UnknownAsNull(cty.ObjectVal(vals))
}

// skipRevision is the revision a skipped step keeps: the one it had, or ""
// for a step that never ran, which tells it apart from steps recorded
// before revisions existed.
func skipRevision(prior cty.Value) cty.Value {
	if prior.IsNull() || !prior.Type().HasAttribute("revision") {
		return cty.StringVal("")
	}
	if r := prior.GetAttr("revision"); r.IsKnown() && !r.IsNull() {
		return r
	}
	return cty.StringVal("")
}

// mayRun is planned for a step whose only_if isn't known: what it reads
// from the host may come back, or may stay null if it's skipped. Its
// revision stays as planned: unknown if running it would change the host,
// and otherwise the one a skip would keep too.
func mayRun(block *configschema.Block, planned cty.Value) cty.Value {
	vals := planned.AsValueMap()
	for name, attr := range block.Attributes {
		if attr.Computed && !attr.Optional && name != "revision" {
			vals[name] = cty.UnknownVal(attr.Type)
		}
	}
	return cty.ObjectVal(vals)
}

func (p *Provider) planGated(ctx context.Context, rt resourceType, req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	full := withOnlyIf(rt.schema()).Block.ImpliedType()
	block := rt.schema().Block
	cond, prior := onlyIf(req.Config), req.PriorState
	skippedBefore := wasSkipped(prior)
	if req.ProposedNewState.IsNull() && skippedBefore {
		return providers.PlanResourceChangeResponse{PlannedState: req.ProposedNewState} // removing it touches nothing
	}
	base := req
	base.Config, base.PriorState, base.ProposedNewState = stripGate(req.Config), stripGate(prior), stripGate(req.ProposedNewState)
	if skippedBefore {
		// A skipped step owns nothing, so running it is a first run.
		base.PriorState = cty.NullVal(block.ImpliedType())
		base.ProposedNewState = objchange.ProposedNew(block, base.PriorState, base.Config)
		base.PriorPrivate = nil
	}
	resp := p.planStep(ctx, rt, base)
	if resp.Diagnostics.HasErrors() {
		return resp
	}
	planned := resp.PlannedState
	if planned.IsNull() {
		resp.PlannedState = cty.NullVal(full)
		return resp
	}
	inLine := !base.PriorState.IsNull() && len(resp.RequiresReplace) == 0 && planned.RawEquals(base.PriorState)
	switch {
	case cond.IsKnown() && (cond.IsNull() || cond.True()), inLine:
		resp.PlannedState = dressGate(planned, gatedSkipped(prior), full)
	case !cond.IsKnown():
		resp.PlannedState = dressGate(mayRun(block, planned), cty.UnknownVal(cty.Bool), full)
	default: // false, and running it would change something: leave the host alone
		resp.RequiresReplace = nil
		resp.PlannedState = dressGate(skippedState(block, planned, skipRevision(prior)), cty.True, full)
		// Recorded here too: a step still skipped plans no change at apply,
		// and OpenTofu then doesn't call apply for it.
		p.ran.skip(resp.PlannedState.GetAttr("revision"))
	}
	if skippedBefore {
		resp.RequiresReplace = nil
	}
	return resp
}

func (p *Provider) applyGated(ctx context.Context, rt resourceType, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	full := withOnlyIf(rt.schema()).Block.ImpliedType()
	if req.PlannedState.IsNull() && wasSkipped(req.PriorState) {
		return providers.ApplyResourceChangeResponse{NewState: req.PlannedState} // removing a skipped step touches nothing
	}
	if wasSkipped(req.PlannedState) {
		// OpenTofu plans again at apply, with only_if known, so a planned
		// skip is the final word.
		p.ran.skip(req.PlannedState.GetAttr("revision"))
		return providers.ApplyResourceChangeResponse{NewState: req.PlannedState}
	}
	base := req
	base.Config, base.PriorState, base.PlannedState = stripGate(req.Config), stripGate(req.PriorState), stripGate(req.PlannedState)
	if wasSkipped(req.PriorState) {
		base.PriorState = cty.NullVal(rt.schema().Block.ImpliedType())
	}
	resp := p.applyStep(ctx, rt, base)
	resp.NewState = dressGate(resp.NewState, gatedSkipped(req.PriorState), full)
	return resp
}

func (p *Provider) readGated(ctx context.Context, rt resourceType, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	if wasSkipped(req.PriorState) {
		// A skipped step owns nothing on the host, so there is nothing to read.
		return providers.ReadResourceResponse{NewState: req.PriorState, Private: req.Private}
	}
	full := withOnlyIf(rt.schema()).Block.ImpliedType()
	base := req
	base.PriorState = stripGate(req.PriorState)
	resp := p.readStep(ctx, rt, base)
	if resp.NewState == cty.NilVal {
		resp.NewState = req.PriorState
		return resp
	}
	resp.NewState = dressGate(resp.NewState, gatedSkipped(req.PriorState), full)
	return resp
}

// upgradeGated upgrades state the type's own way, without skipped, which
// it doesn't know, and puts skipped back.
func upgradeGated(rt resourceType, req providers.UpgradeResourceStateRequest) providers.UpgradeResourceStateResponse {
	var raw map[string]json.RawMessage
	if len(req.RawStateJSON) == 0 || json.Unmarshal(req.RawStateJSON, &raw) != nil {
		return rt.upgrade(req)
	}
	skipped := cty.NullVal(cty.Bool)
	if s, ok := raw["skipped"]; ok {
		var b *bool
		if err := json.Unmarshal(s, &b); err == nil && b != nil {
			skipped = cty.BoolVal(*b)
		}
	}
	delete(raw, "skipped")
	delete(raw, "only_if")
	stripped, err := json.Marshal(raw)
	if err != nil {
		return rt.upgrade(req)
	}
	req.RawStateJSON = stripped
	resp := rt.upgrade(req)
	if !resp.Diagnostics.HasErrors() && resp.UpgradedState != cty.NilVal {
		resp.UpgradedState = dressGate(resp.UpgradedState, skipped, withOnlyIf(rt.schema()).Block.ImpliedType())
	}
	return resp
}

// applyLog is what one apply did: the revisions it gave steps that changed
// their host, and the revisions of steps it skipped. A Provider lives for
// one walk of the graph, so this is one apply's.
type applyLog struct {
	mu      sync.Mutex
	changed map[string]bool
	skipped map[string]bool
}

func (l *applyLog) skip(rev cty.Value) {
	if !rev.IsKnown() || rev.IsNull() || rev.Type() != cty.String {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.skipped == nil {
		l.skipped = map[string]bool{}
	}
	l.skipped[rev.AsString()] = true
}

// minted records the revision an apply gave a step that changed its host.
func (p *Provider) minted(planned, state cty.Value) {
	if planned.IsNull() || state.IsNull() || !state.IsKnown() || !planned.Type().HasAttribute("revision") || planned.GetAttr("revision").IsKnown() {
		return
	}
	rev := state.GetAttr("revision")
	if !rev.IsKnown() || rev.IsNull() {
		return
	}
	p.ran.mu.Lock()
	defer p.ran.mu.Unlock()
	if p.ran.changed == nil {
		p.ran.changed = map[string]bool{}
	}
	p.ran.changed[rev.AsString()] = true
}

// onlySkipped reports whether a handler being created, or replaced, in
// this apply watches nothing that changed its host in it, and at least one
// step that only_if skipped in it. The plan replaced the handler because
// that step's revision wasn't known yet; it turned out the step didn't run,
// so the handler mustn't act. Any other create acts, as it always has:
// this only holds back an action a skip alone caused.
func (p *Provider) onlySkipped(req providers.ApplyResourceChangeRequest) bool {
	if !req.PriorState.IsNull() || req.PlannedState.IsNull() || !req.PlannedState.Type().HasAttribute("triggers") {
		return false
	}
	triggers := req.PlannedState.GetAttr("triggers")
	if !triggers.IsWhollyKnown() {
		return false
	}
	p.ran.mu.Lock()
	defer p.ran.mu.Unlock()
	if len(p.ran.skipped) == 0 {
		return false
	}
	skipped := false
	changed := false
	_ = cty.Walk(triggers, func(_ cty.Path, v cty.Value) (bool, error) {
		if v.IsNull() || v.Type() != cty.String {
			return true, nil
		}
		changed = changed || p.ran.changed[v.AsString()]
		skipped = skipped || p.ran.skipped[v.AsString()]
		return true, nil
	})
	return skipped && !changed
}
