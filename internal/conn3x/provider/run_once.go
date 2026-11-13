// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/plans/objchange"
	"github.com/opentofu/opentofu/internal/providers"
)

// RunResult is what one module did on one host for conn3x run.
type RunResult struct {
	Changed        bool
	Stdout, Stderr string // for a command
}

// RunOnce brings one host in line with a module's arguments, as a step
// would, with no state: it validates, reads whether the host is already
// in line where the module can say, plans as for a new step and applies.
// With check, it stops before applying. args and ssh hold the module's
// arguments and the ssh block's; anything left out is null.
func RunOnce(ctx context.Context, typeName string, args, ssh map[string]cty.Value, check bool) (RunResult, error) {
	rt, ok := resourceTypes[typeName]
	if !ok {
		return RunResult{}, fmt.Errorf("there's no %s", typeName)
	}
	block := rt.schema().Block
	vals := block.EmptyValue().AsValueMap()
	for k, v := range args {
		vals[k] = v
	}
	sshVals := block.BlockTypes["ssh"].Block.EmptyValue().AsValueMap()
	for k, v := range ssh {
		sshVals[k] = v
	}
	vals["ssh"] = cty.ObjectVal(sshVals)
	cfg, err := block.CoerceValue(cty.ObjectVal(vals))
	if err != nil {
		return RunResult{}, err
	}
	diags := rt.validate(cfg).Append(validateSSH(cfg))
	if err := diags.Err(); err != nil {
		return RunResult{}, err
	}
	null := cty.NullVal(block.ImpliedType())
	plan := rt.plan(providers.PlanResourceChangeRequest{TypeName: typeName, PriorState: null, ProposedNewState: objchange.ProposedNew(block, null, cfg), Config: cfg})
	if err := plan.Diagnostics.Err(); err != nil {
		return RunResult{}, err
	}
	// Whether the host is in line already is what a refresh and a second
	// plan would say: read the host as if the step were in state, and plan
	// again from that. A plan that changes nothing means it's in line. A
	// command with no guard has nothing to be in line with, so it just
	// runs, as Ansible's ad-hoc commands do.
	if !unguarded(typeName, args) {
		read := rt.read(ctx, providers.ReadResourceRequest{TypeName: typeName, PriorState: cty.UnknownAsNull(plan.PlannedState)})
		if read.Diagnostics.Err() == nil && !read.NewState.IsNull() {
			again := rt.plan(providers.PlanResourceChangeRequest{TypeName: typeName, PriorState: read.NewState, ProposedNewState: objchange.ProposedNew(block, read.NewState, cfg), Config: cfg})
			if again.Diagnostics.Err() == nil && len(again.RequiresReplace) == 0 && again.PlannedState.IsWhollyKnown() && again.PlannedState.RawEquals(read.NewState) {
				return RunResult{}, nil
			}
		}
	}
	if check {
		return RunResult{Changed: true}, nil
	}
	applied := rt.apply(ctx, providers.ApplyResourceChangeRequest{TypeName: typeName, PriorState: null, PlannedState: plan.PlannedState, Config: cfg})
	if err := applied.Diagnostics.Err(); err != nil {
		return RunResult{}, err
	}
	res := RunResult{Changed: true}
	state, _ := applied.NewState.UnmarkDeep()
	for name, out := range map[string]*string{"stdout": &res.Stdout, "stderr": &res.Stderr} {
		if state.Type().HasAttribute(name) {
			if v := state.GetAttr(name); known(v) {
				*out = v.AsString()
			}
		}
	}
	return res, nil
}

// unguarded is a command that sets none of the guards that would make it
// skip.
func unguarded(typeName string, args map[string]cty.Value) bool {
	if typeName != "conn3x_command" {
		return false
	}
	for _, g := range []string{"creates", "removes", "unless", "triggers"} {
		if v, ok := args[g]; ok && !v.IsNull() {
			return false
		}
	}
	return true
}
