// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"

	"github.com/zclconf/go-cty/cty"
	ctyjson "github.com/zclconf/go-cty/cty/json"

	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/conn3x/modules/service"
	"github.com/opentofu/opentofu/internal/providers"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

func serviceSchema() providers.Schema {
	return providers.Schema{
		Block: &configschema.Block{
			Description: "A systemd unit: whether it runs, and whether it starts at boot.",
			Attributes: map[string]*configschema.Attribute{
				"id":         {Type: cty.String, Computed: true},
				"revision":   revisionAttr(),
				"name":       {Type: cty.String, Required: true, Description: "Unit name. \".service\" is added when there is no suffix."},
				"state":      {Type: cty.String, Optional: true, Description: "\"started\" or \"stopped\". Left as is when unset."},
				"enabled":    {Type: cty.Bool, Optional: true, Description: "Start at boot. Left as is when unset."},
				"on_remove":  {Type: cty.String, Optional: true, Computed: true, Description: "What happens on the host when this resource is removed: \"forget\" (default) leaves the unit, \"delete\" stops and disables it."},
				"running":    {Type: cty.Bool, Computed: true, Description: "Whether the unit is running."},
				"is_enabled": {Type: cty.Bool, Computed: true, Description: "Whether the unit starts at boot."},
			},
			BlockTypes: map[string]*configschema.NestedBlock{
				"ssh": connectionBlock(),
			},
		},
	}
}

func desiredService(v cty.Value) service.Desired {
	d := service.Desired{Name: v.GetAttr("name").AsString(), State: service.State(stringOr(v.GetAttr("state"), ""))}
	if e := v.GetAttr("enabled"); !e.IsNull() && e.IsKnown() {
		b := e.True()
		d.Enabled = &b
	}
	return d
}

func actualService(v cty.Value) service.Actual {
	running, enabled := v.GetAttr("running"), v.GetAttr("is_enabled")
	if running.IsNull() || !running.IsKnown() {
		return service.Actual{}
	}
	return service.Actual{Exists: true, Running: running.True(), Enabled: !enabled.IsNull() && enabled.True()}
}

func validateService(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() || !cfg.GetAttr("name").IsKnown() || !cfg.GetAttr("state").IsKnown() {
		return diags
	}
	diags = diags.Append(validateOnRemove(cfg))
	if err := desiredService(cfg).Validate(); err != nil {
		diags = diags.Append(attrError("name", err.Error()))
	}
	return diags
}

func planService(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	var resp providers.PlanResourceChangeResponse
	if req.ProposedNewState.IsNull() {
		resp.PlannedState = req.ProposedNewState
		return resp
	}
	vals := req.ProposedNewState.AsValueMap()
	if vals["on_remove"].IsNull() {
		vals["on_remove"] = cty.StringVal(defaultOnRemove)
	}
	host := req.ProposedNewState.GetAttr("ssh").GetAttr("host")
	if name := vals["name"]; name.IsKnown() {
		vals["id"] = planID(req, "service", service.Unit(name.AsString()))
	} else {
		vals["id"] = cty.UnknownVal(cty.String)
	}
	planned := cty.ObjectVal(vals)
	if req.PriorState.IsNull() || !planned.IsWhollyKnown() || service.NeedsChange(desiredService(planned), actualService(req.PriorState)) {
		vals["running"] = cty.UnknownVal(cty.Bool)
		vals["is_enabled"] = cty.UnknownVal(cty.Bool)
	} else {
		vals["running"] = req.PriorState.GetAttr("running")
		vals["is_enabled"] = req.PriorState.GetAttr("is_enabled")
	}
	resp.PlannedState = cty.ObjectVal(vals)
	if !req.PriorState.IsNull() {
		if !req.PriorState.GetAttr("name").RawEquals(vals["name"]) {
			resp.RequiresReplace = append(resp.RequiresReplace, cty.GetAttrPath("name"))
		}
		if !req.PriorState.GetAttr("ssh").GetAttr("host").RawEquals(host) {
			resp.RequiresReplace = append(resp.RequiresReplace, cty.GetAttrPath("ssh").GetAttr("host"))
		}
	}
	return resp
}

func readService(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	resp := providers.ReadResourceResponse{NewState: req.PriorState}
	if req.PriorState.IsNull() {
		return resp
	}
	host, err := dialConnection(ctx, req.PriorState.GetAttr("ssh"))
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(attrError("ssh", err.Error()))
		return resp
	}
	defer host.Close()
	actual, err := service.Read(ctx, host, req.PriorState.GetAttr("name").AsString())
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(err)
		return resp
	}
	resp.NewState = serviceState(req.PriorState, actual)
	return resp
}

func applyService(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	var resp providers.ApplyResourceChangeResponse
	target := req.PlannedState
	if target.IsNull() {
		resp.NewState = target
		if req.PriorState.IsNull() || req.PriorState.GetAttr("on_remove").AsString() != onRemoveDelete {
			return resp
		}
		target = req.PriorState
	}
	host, err := dialForApply(ctx, target.GetAttr("ssh"))
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(attrError("ssh", err.Error()))
		return resp
	}
	defer host.Close()

	d := desiredService(target)
	if req.PlannedState.IsNull() {
		off := false
		d = service.Desired{Name: d.Name, State: service.Stopped, Enabled: &off}
	}
	unlock := lockHost(host, "systemd") // until it's read back, so no daemon-reload lands in between
	defer unlock()
	if err := service.Apply(ctx, host, d); err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("service %s: %w", service.Unit(d.Name), err))
		return resp
	}
	if req.PlannedState.IsNull() {
		return resp
	}
	actual, err := service.Read(ctx, host, d.Name)
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(err)
		return resp
	}
	if service.NeedsChange(d, actual) {
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("service %s did not reach the wanted state; check `systemctl status %s` on the host", service.Unit(d.Name), service.Unit(d.Name)))
		return resp
	}
	resp.NewState = serviceState(req.PlannedState, actual)
	return resp
}

func serviceState(base cty.Value, actual service.Actual) cty.Value {
	vals := base.AsValueMap()
	if !actual.Exists {
		vals["running"] = cty.NullVal(cty.Bool)
		vals["is_enabled"] = cty.NullVal(cty.Bool)
	} else {
		vals["running"] = cty.BoolVal(actual.Running)
		vals["is_enabled"] = cty.BoolVal(actual.Enabled)
	}
	return cty.ObjectVal(vals)
}

func upgradeService(req providers.UpgradeResourceStateRequest) providers.UpgradeResourceStateResponse {
	var resp providers.UpgradeResourceStateResponse
	val, err := ctyjson.Unmarshal(req.RawStateJSON, serviceSchema().Block.ImpliedType())
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(err)
		return resp
	}
	resp.UpgradedState = val
	return resp
}
