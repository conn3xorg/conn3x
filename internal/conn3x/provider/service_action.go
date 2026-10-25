// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/conn3x/modules/service"
	"github.com/opentofu/opentofu/internal/providers"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

// conn3x_service_action restarts or reloads a unit whenever its triggers
// change. Circuit handlers lower to it, with the notifying steps as
// triggers, so the action runs only when one of them changed.

func serviceActionSchema() providers.Schema {
	return providers.Schema{
		Block: &configschema.Block{
			Description: "Restarts or reloads a systemd unit when its triggers change.",
			Attributes: map[string]*configschema.Attribute{
				"id":       {Type: cty.String, Computed: true},
				"name":     {Type: cty.String, Required: true, Description: "Unit name."},
				"action":   {Type: cty.String, Optional: true, Computed: true, Description: "\"restart\" (default) or \"reload\"."},
				"triggers": {Type: cty.DynamicPseudoType, Optional: true, Description: "Any value; the action runs again whenever it changes."},
			},
			BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
		},
	}
}

func validateServiceAction(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() {
		return diags
	}
	if a := cfg.GetAttr("action"); known(a) && a.AsString() != "restart" && a.AsString() != "reload" {
		diags = diags.Append(attrError("action", fmt.Sprintf("action must be \"restart\" or \"reload\", not %q", a.AsString())))
	}
	if n := cfg.GetAttr("name"); known(n) {
		if err := (service.Desired{Name: n.AsString()}).Validate(); err != nil {
			diags = diags.Append(attrError("name", err.Error()))
		}
	}
	return diags
}

func planServiceAction(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	var resp providers.PlanResourceChangeResponse
	if req.ProposedNewState.IsNull() {
		resp.PlannedState = req.ProposedNewState
		return resp
	}
	vals := req.ProposedNewState.AsValueMap()
	if vals["action"].IsNull() {
		vals["action"] = cty.StringVal("restart")
	}
	if name := vals["name"]; name.IsKnown() {
		vals["id"] = planID(req, "service-action", service.Unit(name.AsString()))
	} else {
		vals["id"] = cty.UnknownVal(cty.String)
	}
	resp.PlannedState = cty.ObjectVal(vals)
	if !req.PriorState.IsNull() {
		prior, now := req.PriorState.GetAttr("triggers"), vals["triggers"]
		if !now.IsWhollyKnown() || !prior.RawEquals(now) {
			resp.RequiresReplace = append(resp.RequiresReplace, cty.GetAttrPath("triggers"))
		}
	}
	return resp
}

// readServiceAction keeps state as it is: an action has nothing on the
// host to drift.
func readServiceAction(_ context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	return providers.ReadResourceResponse{NewState: req.PriorState}
}

func applyServiceAction(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	var resp providers.ApplyResourceChangeResponse
	resp.NewState = req.PlannedState
	if req.PlannedState.IsNull() {
		return resp
	}
	host, err := dialConnection(ctx, req.PlannedState.GetAttr("ssh"))
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(attrError("ssh", err.Error()))
		return resp
	}
	defer host.Close()
	name := req.PlannedState.GetAttr("name").AsString()
	if req.PlannedState.GetAttr("action").AsString() == "reload" {
		err = service.Reload(ctx, host, name)
	} else {
		err = service.Restart(ctx, host, name)
	}
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("service %s: %w", service.Unit(name), err))
	}
	return resp
}
