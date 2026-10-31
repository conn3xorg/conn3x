// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/conn3x/modules/account"
	"github.com/opentofu/opentofu/internal/conn3x/modules/pip"
	"github.com/opentofu/opentofu/internal/providers"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

func pipSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "A Python package in a virtual environment, installed with the venv's own pip. A missing venv is built with python3 -m venv.",
		Attributes: map[string]*configschema.Attribute{
			"id":                {Type: cty.String, Computed: true},
			"revision":          revisionAttr(),
			"name":              {Type: cty.String, Required: true, Description: "Package name, with no version or extras."},
			"venv":              {Type: cty.String, Required: true, Description: "Absolute path of the virtual environment."},
			"version":           {Type: cty.String, Optional: true, Description: "Exact version to pin, with state \"present\". Without it, any installed version is accepted."},
			"state":             {Type: cty.String, Optional: true, Computed: true, Description: "\"present\" (default), \"latest\" or \"absent\"."},
			"user":              {Type: cty.String, Optional: true, Description: "Who owns the venv and runs pip. Without it, the connecting user. Required when someone else owns the venv or a directory above it, such as anything in a user's home."},
			"on_remove":         {Type: cty.String, Optional: true, Computed: true, Description: "What happens on the host when this step is removed: \"forget\" (default) leaves the package, \"delete\" uninstalls it. The venv stays either way."},
			"installed_version": {Type: cty.String, Computed: true, Description: "Version in the venv, or null when it isn't there."},
			"latest_version":    {Type: cty.String, Computed: true, Description: "What an upgrade would install, read when state is \"latest\"."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func desiredPip(v cty.Value) pip.Desired {
	return pip.Desired{
		Name:    v.GetAttr("name").AsString(),
		Venv:    v.GetAttr("venv").AsString(),
		User:    stringOr(v.GetAttr("user"), ""),
		State:   pip.State(stringOr(v.GetAttr("state"), string(pip.Present))),
		Version: stringOr(v.GetAttr("version"), ""),
	}
}

func validatePip(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() || !cfg.IsWhollyKnown() {
		return diags
	}
	diags = diags.Append(validateOnRemove(cfg))
	d := desiredPip(cfg)
	if err := d.Validate(); err != nil {
		diags = diags.Append(attrError("name", err.Error()))
	}
	if d.User != "" {
		if err := (account.UserSpec{Name: d.User}).Validate(); err != nil {
			diags = diags.Append(attrError("user", err.Error()))
		}
	}
	return diags
}

func planPip(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	var resp providers.PlanResourceChangeResponse
	if req.ProposedNewState.IsNull() {
		resp.PlannedState = req.ProposedNewState
		return resp
	}
	vals := req.ProposedNewState.AsValueMap()
	if vals["state"].IsNull() {
		vals["state"] = cty.StringVal(string(pip.Present))
	}
	if vals["on_remove"].IsNull() {
		vals["on_remove"] = cty.StringVal(defaultOnRemove)
	}
	if n, v := vals["name"], vals["venv"]; n.IsKnown() && v.IsKnown() {
		vals["id"] = planID(req, "pip", v.AsString(), n.AsString())
	} else {
		vals["id"] = cty.UnknownVal(cty.String)
	}
	planned := cty.ObjectVal(vals)
	unknown := func() {
		vals["installed_version"] = cty.UnknownVal(cty.String)
		vals["latest_version"] = cty.UnknownVal(cty.String)
	}
	switch {
	case !planned.IsWhollyKnown():
		unknown()
	case req.PriorState.IsNull():
		unknown()
	default:
		// Refresh already recorded what's in the venv; plan a change only
		// when it differs from what is wanted.
		prior := req.PriorState
		a := pip.Actual{
			Installed: !prior.GetAttr("installed_version").IsNull(),
			Version:   stringOr(prior.GetAttr("installed_version"), ""),
			Candidate: stringOr(prior.GetAttr("latest_version"), ""),
		}
		if pip.NeedsChange(desiredPip(planned), a) {
			unknown()
		} else {
			vals["installed_version"] = prior.GetAttr("installed_version")
			vals["latest_version"] = prior.GetAttr("latest_version")
		}
	}
	resp.PlannedState = cty.ObjectVal(vals)
	if !req.PriorState.IsNull() {
		for _, a := range []string{"name", "venv", "user"} {
			if !req.PriorState.GetAttr(a).RawEquals(vals[a]) {
				resp.RequiresReplace = append(resp.RequiresReplace, cty.GetAttrPath(a))
			}
		}
		if !req.PriorState.GetAttr("ssh").GetAttr("host").RawEquals(req.ProposedNewState.GetAttr("ssh").GetAttr("host")) {
			resp.RequiresReplace = append(resp.RequiresReplace, cty.GetAttrPath("ssh").GetAttr("host"))
		}
	}
	return resp
}

func pipState(base cty.Value, a pip.Actual) cty.Value {
	vals := base.AsValueMap()
	vals["installed_version"] = cty.NullVal(cty.String)
	if a.Installed {
		vals["installed_version"] = cty.StringVal(a.Version)
	}
	vals["latest_version"] = cty.NullVal(cty.String)
	if a.Candidate != "" {
		vals["latest_version"] = cty.StringVal(a.Candidate)
	}
	return cty.ObjectVal(vals)
}

func readPip(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	return readPathResource(ctx, req, func(ctx context.Context, h *hostConn, prior cty.Value) (cty.Value, error) {
		d := desiredPip(prior)
		a, err := pip.Read(ctx, h, d)
		if err != nil {
			return cty.NilVal, fmt.Errorf("reading pip package %s in %s: %w", d.Name, d.Venv, err)
		}
		return pipState(prior, a), nil
	})
}

func applyPip(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	var resp providers.ApplyResourceChangeResponse
	target := req.PlannedState
	if target.IsNull() {
		resp.NewState = target
		if req.PriorState.IsNull() || req.PriorState.GetAttr("on_remove").AsString() != onRemoveDelete {
			return resp
		}
		target = req.PriorState
	}
	h, err := dialForApply(ctx, target.GetAttr("ssh"))
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(attrError("ssh", err.Error()))
		return resp
	}
	d := desiredPip(target)
	if req.PlannedState.IsNull() {
		d.State, d.Version = pip.Absent, ""
	}
	// Steps on one venv take turns: pip isn't safe to run twice at once there,
	// and a for_each runs them together.
	defer lockHost(h, "pip\x00"+d.Venv)()
	if err := pip.Apply(ctx, h, d); err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("pip package %s in %s: %w", d.Name, d.Venv, err))
		return resp
	}
	if req.PlannedState.IsNull() {
		return resp
	}
	a, err := pip.Read(ctx, h, d)
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("reading back pip package %s: %w", d.Name, err))
		return resp
	}
	if pip.NeedsChange(d, a) {
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("pip package %s in %s is not %s after applying; pip reported success but the venv disagrees", d.Name, d.Venv, d.State))
		return resp
	}
	resp.NewState = pipState(req.PlannedState, a)
	return resp
}
