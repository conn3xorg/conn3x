// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/conn3x/modules/windows"
	"github.com/opentofu/opentofu/internal/providers"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

func winChocoSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "A Chocolatey package on a Windows host that already has Chocolatey. A package's install script runs as an administrator, and its version comes from the feed: use a feed you control. It never reboots: reboot_required says whether the package wants one.",
		Attributes: map[string]*configschema.Attribute{
			"id":              {Type: cty.String, Computed: true},
			"revision":        revisionAttr(),
			"name":            {Type: cty.String, Required: true, Description: "The package ID, such as git."},
			"version":         {Type: cty.String, Optional: true, Description: "The exact version, such as 2.44.0. Unset, any installed version will do, and a missing package gets the feed's newest."},
			"state":           {Type: cty.String, Optional: true, Description: "\"present\" (default) or \"absent\"."},
			"source":          {Type: cty.String, Optional: true, Description: "The feed: an https URL with no login in it, or an absolute folder. Unset, Chocolatey's configured sources, the community feed by default."},
			"pinned":          {Type: cty.Bool, Optional: true, Description: "Whether choco upgrade all leaves the package alone. Unset leaves the pin as it is."},
			"timeout":         {Type: cty.String, Optional: true, Description: "How long to allow. Defaults to \"30m\"."},
			"reboot_required": {Type: cty.Bool, Computed: true, Description: "Whether choco asked for a reboot (3010 or 1641) at the last change."},
			"in_sync":         {Type: cty.Bool, Computed: true, Description: "Whether the package matched at the last refresh."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func winChocoFrom(v cty.Value) windows.ChocoPackage {
	p := windows.ChocoPackage{
		Name: stringOr(v.GetAttr("name"), ""), Version: stringOr(v.GetAttr("version"), ""),
		Absent: isAbsent(v), Source: stringOr(v.GetAttr("source"), ""),
	}
	if pin := v.GetAttr("pinned"); known(pin) {
		b := pin.True()
		p.Pinned = &b
	}
	return p
}

func validateWinChoco(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() {
		return diags
	}
	diags = diags.Append(validateState(cfg, "version", "source", "pinned"))
	if t := cfg.GetAttr("timeout"); t.IsKnown() {
		if _, err := durationOr(t, defaultPackageTimeout); err != nil {
			diags = diags.Append(attrError("timeout", err.Error()))
		}
	}
	for _, a := range []string{"name", "version", "state", "source", "pinned"} {
		if !cfg.GetAttr(a).IsWhollyKnown() {
			return diags
		}
	}
	if err := winChocoFrom(cfg).Validate(); err != nil {
		diags = diags.Append(attrError("name", err.Error()))
	}
	return diags
}

func planWinChoco(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	resp := planSyncedFold(req, "windows_choco_package", []string{"name"}, []string{"state", "version", "source", "pinned"})
	if resp.PlannedState.IsNull() {
		return resp
	}
	vals := resp.PlannedState.AsValueMap()
	if vals["in_sync"].IsKnown() {
		vals["reboot_required"] = req.PriorState.GetAttr("reboot_required")
	} else {
		vals["reboot_required"] = cty.UnknownVal(cty.Bool)
	}
	resp.PlannedState = cty.ObjectVal(vals)
	return resp
}

func readWinChoco(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	resp := providers.ReadResourceResponse{NewState: req.PriorState}
	if req.PriorState.IsNull() {
		return resp
	}
	h, err := winHost(ctx, req.PriorState.GetAttr("ssh"))
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(attrError("ssh", err.Error()))
		return resp
	}
	p := winChocoFrom(req.PriorState)
	a, err := windows.ReadChoco(ctx, h.raw(), p.Name)
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(err)
		return resp
	}
	resp.NewState = withSync(req.PriorState, p.Matches(a))
	return resp
}

func applyWinChoco(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	var resp providers.ApplyResourceChangeResponse
	if req.PlannedState.IsNull() {
		resp.NewState = req.PlannedState
		return resp
	}
	fail := func(err error) providers.ApplyResourceChangeResponse {
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("windows_choco_package: %w", err))
		return resp
	}
	p := winChocoFrom(req.PlannedState)
	if err := p.Validate(); err != nil {
		return fail(err)
	}
	timeout, err := durationOr(req.PlannedState.GetAttr("timeout"), defaultPackageTimeout)
	if err != nil {
		return fail(err)
	}
	h, err := winHost(ctx, req.PlannedState.GetAttr("ssh"))
	if err != nil {
		return fail(err)
	}
	// choco runs one operation at a time, and its packages may run msiexec.
	defer lockHost(h, "windows_package")()
	a, err := windows.ReadChoco(ctx, h.raw(), p.Name)
	if err != nil {
		return fail(err)
	}
	restart := false
	if !p.Matches(a) {
		if restart, err = windows.ApplyChoco(ctx, h.raw(), p, a, timeout); err != nil {
			return fail(fmt.Errorf("%s: %w", p.Name, err))
		}
		if a, err = windows.ReadChoco(ctx, h.raw(), p.Name); err != nil {
			return fail(err)
		}
		if !p.Matches(a) {
			return fail(fmt.Errorf("%s doesn't match after choco ran: installed %v, version %q, pinned %v", p.Name, a.Installed, a.Version, a.Pinned))
		}
	}
	vals := withSync(req.PlannedState, true).AsValueMap()
	vals["reboot_required"] = cty.BoolVal(restart)
	resp.NewState = cty.ObjectVal(vals)
	return resp
}
