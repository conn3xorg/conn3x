// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/conn3x/modules/npm"
	"github.com/opentofu/opentofu/internal/providers"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

func npmSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "A Node.js package, installed with the host's npm: a global CLI, or one dependency of a project directory.",
		Attributes: map[string]*configschema.Attribute{
			"id":                {Type: cty.String, Computed: true},
			"revision":          revisionAttr(),
			"name":              {Type: cty.String, Required: true, Description: "Package name, such as pm2 or @angular/cli, with no version or tag."},
			"version":           {Type: cty.String, Optional: true, Description: "Exact version to pin, with state \"present\". Without it, any installed version is accepted."},
			"global":            {Type: cty.Bool, Optional: true, Description: "Install into npm's global prefix, for CLIs. Default false, which needs path."},
			"path":              {Type: cty.String, Optional: true, Description: "Absolute path of the project directory, which has to exist. npm runs there and writes its package.json."},
			"state":             {Type: cty.String, Optional: true, Computed: true, Description: "\"present\" (default), \"latest\" or \"absent\"."},
			"on_remove":         {Type: cty.String, Optional: true, Computed: true, Description: "What happens on the host when this step is removed: \"forget\" (default) leaves the package, \"delete\" uninstalls it."},
			"installed_version": {Type: cty.String, Computed: true, Description: "Version installed, or null when it isn't there."},
			"latest_version":    {Type: cty.String, Computed: true, Description: "The registry's newest version, read when state is \"latest\"."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func desiredNpm(v cty.Value) npm.Desired {
	return npm.Desired{
		Name:    v.GetAttr("name").AsString(),
		Global:  boolOr(v.GetAttr("global")),
		Path:    stringOr(v.GetAttr("path"), ""),
		State:   npm.State(stringOr(v.GetAttr("state"), string(npm.Present))),
		Version: stringOr(v.GetAttr("version"), ""),
	}
}

func validateNpm(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() || !cfg.IsWhollyKnown() {
		return diags
	}
	diags = diags.Append(validateOnRemove(cfg))
	if err := desiredNpm(cfg).Validate(); err != nil {
		diags = diags.Append(attrError("name", err.Error()))
	}
	return diags
}

func planNpm(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	var resp providers.PlanResourceChangeResponse
	if req.ProposedNewState.IsNull() {
		resp.PlannedState = req.ProposedNewState
		return resp
	}
	vals := req.ProposedNewState.AsValueMap()
	if vals["state"].IsNull() {
		vals["state"] = cty.StringVal(string(npm.Present))
	}
	if vals["on_remove"].IsNull() {
		vals["on_remove"] = cty.StringVal(defaultOnRemove)
	}
	if n, g, p := vals["name"], vals["global"], vals["path"]; n.IsKnown() && g.IsKnown() && p.IsKnown() {
		where := stringOr(p, "")
		if boolOr(g) {
			where = "global"
		}
		vals["id"] = planID(req, "npm", where, n.AsString())
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
		// Refresh already recorded what npm has; plan a change only when it
		// differs from what is wanted.
		prior := req.PriorState
		a := npm.Actual{
			Installed: !prior.GetAttr("installed_version").IsNull(),
			Version:   stringOr(prior.GetAttr("installed_version"), ""),
			Candidate: stringOr(prior.GetAttr("latest_version"), ""),
		}
		if npm.NeedsChange(desiredNpm(planned), a) {
			unknown()
		} else {
			vals["installed_version"] = prior.GetAttr("installed_version")
			vals["latest_version"] = prior.GetAttr("latest_version")
		}
	}
	resp.PlannedState = cty.ObjectVal(vals)
	if !req.PriorState.IsNull() {
		for _, a := range []string{"name", "global", "path"} {
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

func npmState(base cty.Value, a npm.Actual) cty.Value {
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

func readNpm(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	return readPathResource(ctx, req, func(ctx context.Context, h *hostConn, prior cty.Value) (cty.Value, error) {
		d := desiredNpm(prior)
		a, err := npm.Read(ctx, h, d)
		if err != nil {
			return cty.NilVal, fmt.Errorf("reading npm package %s: %w", d.Name, err)
		}
		return npmState(prior, a), nil
	})
}

func applyNpm(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
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
	d := desiredNpm(target)
	if req.PlannedState.IsNull() {
		d.State, d.Version = npm.Absent, ""
	}
	// Steps on one tree take turns: npm isn't safe to run twice at once
	// there, and a for_each runs them together.
	defer lockHost(h, "npm\x00"+d.Path)()
	if err := npm.Apply(ctx, h, d); err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("npm package %s: %w", d.Name, err))
		return resp
	}
	if req.PlannedState.IsNull() {
		return resp
	}
	a, err := npm.Read(ctx, h, d)
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("reading back npm package %s: %w", d.Name, err))
		return resp
	}
	if npm.NeedsChange(d, a) {
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("npm package %s is not %s after applying; npm reported success but npm ls disagrees", d.Name, d.State))
		return resp
	}
	resp.NewState = npmState(req.PlannedState, a)
	return resp
}
