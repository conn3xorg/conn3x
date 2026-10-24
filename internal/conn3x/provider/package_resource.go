// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"

	"github.com/zclconf/go-cty/cty"
	ctyjson "github.com/zclconf/go-cty/cty/json"

	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/conn3x/modules/pkg"
	"github.com/opentofu/opentofu/internal/providers"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

func packageSchema() providers.Schema {
	return providers.Schema{
		Block: &configschema.Block{
			Description: "An OS package, installed with dnf on the Red Hat family and apt on Debian and Ubuntu.",
			Attributes: map[string]*configschema.Attribute{
				"id":                {Type: cty.String, Computed: true},
				"name":              {Type: cty.String, Required: true, Description: "Package name."},
				"state":             {Type: cty.String, Optional: true, Computed: true, Description: "\"present\" (default), \"latest\" or \"absent\"."},
				"version":           {Type: cty.String, Optional: true, Description: "Version to install, with state \"present\"."},
				"on_remove":         {Type: cty.String, Optional: true, Computed: true, Description: "What happens on the host when this resource is removed: \"forget\" (default) leaves the package, \"delete\" uninstalls it."},
				"installed_version": {Type: cty.String, Computed: true, Description: "Version installed on the host, or null when it isn't installed."},
				"latest_version":    {Type: cty.String, Computed: true, Description: "Newest available version, read when state is \"latest\"."},
			},
			BlockTypes: map[string]*configschema.NestedBlock{
				"ssh": connectionBlock(),
			},
		},
	}
}

func desiredPackage(v cty.Value) pkg.Desired {
	return pkg.Desired{
		Name:    v.GetAttr("name").AsString(),
		State:   pkg.State(stringOr(v.GetAttr("state"), string(pkg.Present))),
		Version: stringOr(v.GetAttr("version"), ""),
	}
}

func actualPackage(v cty.Value) pkg.Actual {
	installed := v.GetAttr("installed_version")
	return pkg.Actual{
		Installed: !installed.IsNull() && installed.IsKnown(),
		Version:   stringOr(installed, ""),
		Candidate: stringOr(v.GetAttr("latest_version"), ""),
	}
}

func validatePackage(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() || !cfg.GetAttr("name").IsKnown() {
		return diags
	}
	diags = diags.Append(validateOnRemove(cfg))
	for _, attr := range []string{"state", "version"} {
		if !cfg.GetAttr(attr).IsKnown() {
			return diags
		}
	}
	d := desiredPackage(cfg)
	if err := d.Validate(); err != nil {
		diags = diags.Append(attrError("name", err.Error()))
	}
	return diags
}

func planPackage(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	var resp providers.PlanResourceChangeResponse
	if req.ProposedNewState.IsNull() {
		resp.PlannedState = req.ProposedNewState
		return resp
	}
	vals := req.ProposedNewState.AsValueMap()
	if vals["state"].IsNull() {
		vals["state"] = cty.StringVal(string(pkg.Present))
	}
	if vals["on_remove"].IsNull() {
		vals["on_remove"] = cty.StringVal(defaultOnRemove)
	}
	host, name := req.ProposedNewState.GetAttr("ssh").GetAttr("host"), vals["name"]
	if host.IsKnown() && name.IsKnown() {
		vals["id"] = cty.StringVal(host.AsString() + ":package:" + name.AsString())
	} else {
		vals["id"] = cty.UnknownVal(cty.String)
	}

	planned := cty.ObjectVal(vals)
	unknownInstall := func() {
		vals["installed_version"] = cty.UnknownVal(cty.String)
		vals["latest_version"] = cty.UnknownVal(cty.String)
	}
	switch {
	case !planned.IsWhollyKnown():
		unknownInstall()
	case req.PriorState.IsNull():
		if desiredPackage(planned).State == pkg.Absent {
			vals["installed_version"] = cty.NullVal(cty.String)
			vals["latest_version"] = cty.NullVal(cty.String)
		} else {
			unknownInstall()
		}
	default:
		// Refresh already recorded what is on the host; plan a change only
		// when it differs from what is wanted.
		if pkg.NeedsChange(desiredPackage(planned), actualPackage(req.PriorState)) {
			unknownInstall()
		} else {
			vals["installed_version"] = req.PriorState.GetAttr("installed_version")
			vals["latest_version"] = req.PriorState.GetAttr("latest_version")
		}
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

func readPackage(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
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
	actual, err := readPackageOnHost(ctx, host, desiredPackage(req.PriorState))
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(err)
		return resp
	}
	resp.NewState = packageState(req.PriorState, actual)
	return resp
}

func readPackageOnHost(ctx context.Context, host *hostConn, d pkg.Desired) (pkg.Actual, error) {
	family, err := pkg.DetectFamily(ctx, host)
	if err != nil {
		return pkg.Actual{}, err
	}
	actual, err := pkg.Read(ctx, host, family, d.Name, d.State == pkg.Latest)
	if err != nil {
		return actual, fmt.Errorf("reading package %s: %w", d.Name, err)
	}
	return actual, nil
}

func applyPackage(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	var resp providers.ApplyResourceChangeResponse
	target := req.PlannedState
	if target.IsNull() {
		resp.NewState = target
		if req.PriorState.IsNull() || req.PriorState.GetAttr("on_remove").AsString() != onRemoveDelete {
			return resp
		}
		target = req.PriorState
	}
	host, err := dialConnection(ctx, target.GetAttr("ssh"))
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(attrError("ssh", err.Error()))
		return resp
	}
	defer host.Close()

	d := desiredPackage(target)
	if req.PlannedState.IsNull() {
		d = pkg.Desired{Name: d.Name, State: pkg.Absent}
	}
	family, err := pkg.DetectFamily(ctx, host)
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(err)
		return resp
	}
	if err := pkg.Apply(ctx, host, family, d); err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("package %s: %w", d.Name, err))
		return resp
	}
	if req.PlannedState.IsNull() {
		return resp
	}
	actual, err := pkg.Read(ctx, host, family, d.Name, d.State == pkg.Latest)
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("reading back package %s: %w", d.Name, err))
		return resp
	}
	if pkg.NeedsChange(d, actual) {
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("package %s is not %s after applying; the package manager reported success but the host disagrees", d.Name, d.State))
		return resp
	}
	resp.NewState = packageState(req.PlannedState, actual)
	return resp
}

func packageState(base cty.Value, actual pkg.Actual) cty.Value {
	vals := base.AsValueMap()
	vals["installed_version"] = cty.NullVal(cty.String)
	if actual.Installed {
		vals["installed_version"] = cty.StringVal(actual.Version)
	}
	vals["latest_version"] = cty.NullVal(cty.String)
	if actual.Candidate != "" {
		vals["latest_version"] = cty.StringVal(actual.Candidate)
	}
	return cty.ObjectVal(vals)
}

func upgradePackage(req providers.UpgradeResourceStateRequest) providers.UpgradeResourceStateResponse {
	var resp providers.UpgradeResourceStateResponse
	val, err := ctyjson.Unmarshal(req.RawStateJSON, packageSchema().Block.ImpliedType())
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(err)
		return resp
	}
	resp.UpgradedState = val
	return resp
}
