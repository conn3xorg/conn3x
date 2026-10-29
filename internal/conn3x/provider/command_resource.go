// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/conn3x/modules/command"
	"github.com/opentofu/opentofu/internal/providers"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

// commandRerun lists the arguments whose change means "run it again".
var commandRerun = []string{"command", "creates", "removes", "unless", "triggers"}

func commandSchema() providers.Schema {
	return providers.Schema{
		Block: &configschema.Block{
			Description: "A shell command, for what no module covers yet. Guards say when it has already done its job.",
			Attributes: map[string]*configschema.Attribute{
				"id":        {Type: cty.String, Computed: true},
				"revision":  revisionAttr(),
				"command":   {Type: cty.String, Required: true, Description: "Shell command, run with /bin/sh."},
				"creates":   {Type: cty.String, Optional: true, Description: "Skip the command while this path exists."},
				"removes":   {Type: cty.String, Optional: true, Description: "Skip the command while this path is missing."},
				"unless":    {Type: cty.String, Optional: true, Description: "Skip the command while this check command succeeds."},
				"triggers":  {Type: cty.DynamicPseudoType, Optional: true, Description: "Any value; the command runs again whenever it changes."},
				"satisfied": {Type: cty.Bool, Computed: true, Description: "Whether the guards hold on the host."},
				"stdout":    {Type: cty.String, Computed: true, Sensitive: true, Description: "Output of the last run, truncated to 4 KiB."},
				"stderr":    {Type: cty.String, Computed: true, Sensitive: true, Description: "Error output of the last run, truncated to 4 KiB."},
			},
			BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
		},
	}
}

func commandGuards(v cty.Value) command.Guards {
	return command.Guards{
		Creates: stringOr(v.GetAttr("creates"), ""),
		Removes: stringOr(v.GetAttr("removes"), ""),
		Unless:  stringOr(v.GetAttr("unless"), ""),
	}
}

func validateCommand(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() {
		return diags
	}
	if c := cfg.GetAttr("command"); known(c) && c.AsString() == "" {
		diags = diags.Append(attrError("command", "command must not be empty"))
	}
	for _, a := range []string{"creates", "removes", "unless"} {
		if !cfg.GetAttr(a).IsKnown() {
			return diags
		}
	}
	if err := commandGuards(cfg).Validate(); err != nil {
		diags = diags.Append(attrError("creates", err.Error()))
	}
	return diags
}

func planCommand(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	var resp providers.PlanResourceChangeResponse
	if req.ProposedNewState.IsNull() {
		resp.PlannedState = req.ProposedNewState
		return resp
	}
	vals := req.ProposedNewState.AsValueMap()
	host := req.ProposedNewState.GetAttr("ssh").GetAttr("host")
	vals["id"] = planID(req, "command")
	rerun := req.PriorState.IsNull()
	if !rerun {
		for _, a := range commandRerun {
			now := vals[a]
			if !now.IsWhollyKnown() || !req.PriorState.GetAttr(a).RawEquals(now) {
				resp.RequiresReplace = append(resp.RequiresReplace, cty.GetAttrPath(a))
				rerun = true
			}
		}
		if s := req.PriorState.GetAttr("satisfied"); known(s) && s.False() {
			rerun = true // refresh found the guards no longer hold
		}
		if !req.PriorState.GetAttr("ssh").GetAttr("host").RawEquals(host) {
			resp.RequiresReplace = append(resp.RequiresReplace, cty.GetAttrPath("ssh").GetAttr("host"))
			rerun = true
		}
	}
	if rerun {
		vals["satisfied"] = cty.UnknownVal(cty.Bool)
		vals["stdout"] = cty.UnknownVal(cty.String)
		vals["stderr"] = cty.UnknownVal(cty.String)
	} else {
		for _, a := range []string{"satisfied", "stdout", "stderr"} {
			vals[a] = req.PriorState.GetAttr(a)
		}
	}
	resp.PlannedState = cty.ObjectVal(vals)
	return resp
}

func readCommand(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	resp := providers.ReadResourceResponse{NewState: req.PriorState}
	if req.PriorState.IsNull() || !commandGuards(req.PriorState).Any() {
		return resp
	}
	host, err := dialConnection(ctx, req.PriorState.GetAttr("ssh"))
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(attrError("ssh", err.Error()))
		return resp
	}
	ok, err := command.Satisfied(ctx, host, commandGuards(req.PriorState))
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(err)
		return resp
	}
	vals := req.PriorState.AsValueMap()
	vals["satisfied"] = cty.BoolVal(ok)
	resp.NewState = cty.ObjectVal(vals)
	return resp
}

func applyCommand(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	var resp providers.ApplyResourceChangeResponse
	// A known satisfied means the plan found nothing to rerun.
	if req.PlannedState.IsNull() || (!req.PriorState.IsNull() && req.PlannedState.GetAttr("satisfied").IsKnown()) {
		resp.NewState = req.PlannedState
		return resp
	}
	host, err := dialForApply(ctx, req.PlannedState.GetAttr("ssh"))
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(attrError("ssh", err.Error()))
		return resp
	}

	guards := commandGuards(req.PlannedState)
	vals := req.PlannedState.AsValueMap()
	done, err := command.Satisfied(ctx, host, guards)
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(err)
		return resp
	}
	stdout, stderr := cty.StringVal(""), cty.StringVal("")
	if !req.PriorState.IsNull() {
		stdout, stderr = req.PriorState.GetAttr("stdout"), req.PriorState.GetAttr("stderr")
	}
	if !done {
		out, err := command.Run(ctx, host, req.PlannedState.GetAttr("command").AsString())
		if err != nil {
			resp.Diagnostics = resp.Diagnostics.Append(err)
			return resp
		}
		stdout, stderr = cty.StringVal(out.Stdout), cty.StringVal(out.Stderr)
		if guards.Any() {
			if ok, err := command.Satisfied(ctx, host, guards); err != nil || !ok {
				resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("the command ran, but its guards still don't hold; check creates, removes and unless match what it does"))
				return resp
			}
		}
	}
	vals["satisfied"] = cty.True
	vals["stdout"], vals["stderr"] = stdout, stderr
	resp.NewState = cty.ObjectVal(vals)
	return resp
}
