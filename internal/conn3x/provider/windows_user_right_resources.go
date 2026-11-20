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

func winUserRightSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "Who holds a user right on a Windows host, such as SeServiceLogonRight. A Group Policy that sets the right puts it back at its next refresh.",
		Attributes: map[string]*configschema.Attribute{
			"id":            {Type: cty.String, Computed: true},
			"revision":      revisionAttr(),
			"name":          {Type: cty.String, Required: true, Description: "The right's constant name, such as SeServiceLogonRight or SeDebugPrivilege."},
			"principals":    {Type: cty.Set(cty.String), Optional: true, Description: "Users and groups that must hold it, by name, such as .\\svc_app or LAB\\alice, or by SID. Others keep it unless authoritative is set."},
			"authoritative": {Type: cty.Bool, Optional: true, Description: "true makes principals the complete list: anyone else loses the right, and no principals clears it. Never leaves the login Conn3x uses without a logon right it has."},
			"on_remove":     {Type: cty.String, Optional: true, Computed: true, Description: "What happens on the host when this resource is removed: \"forget\" (default) leaves the right as it is, \"delete\" takes it from principals."},
			"in_sync":       {Type: cty.Bool, Computed: true, Description: "Whether the right was held as configured at the last refresh."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func winUserRightFrom(v cty.Value) windows.UserRight {
	u := windows.UserRight{Name: stringOr(v.GetAttr("name"), "")}
	if a := v.GetAttr("authoritative"); known(a) {
		u.Authoritative = a.True()
	}
	if p := v.GetAttr("principals"); known(p) {
		for it := p.ElementIterator(); it.Next(); {
			_, e := it.Element()
			u.Principals = append(u.Principals, e.AsString())
		}
	}
	return u
}

func validateWinUserRight(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() {
		return diags
	}
	diags = diags.Append(validateOnRemove(cfg))
	for _, a := range []string{"name", "principals", "authoritative"} {
		if !cfg.GetAttr(a).IsWhollyKnown() {
			return diags
		}
	}
	if err := winUserRightFrom(cfg).Validate(); err != nil {
		diags = diags.Append(attrError("name", err.Error()))
	}
	return diags
}

func planWinUserRight(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	return planSyncedFold(req, "windows_user_right", []string{"name"}, []string{"principals", "authoritative"})
}

func readWinUserRight(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	resp := providers.ReadResourceResponse{NewState: req.PriorState}
	if req.PriorState.IsNull() {
		return resp
	}
	h, err := winHost(ctx, req.PriorState.GetAttr("ssh"))
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(attrError("ssh", err.Error()))
		return resp
	}
	u := winUserRightFrom(req.PriorState)
	a, err := windows.ReadUserRight(ctx, h.raw(), u)
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(err)
		return resp
	}
	resp.NewState = withSync(req.PriorState, u.Matches(a))
	return resp
}

func applyWinUserRight(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	var resp providers.ApplyResourceChangeResponse
	fail := func(err error) providers.ApplyResourceChangeResponse {
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("windows_user_right: %w", err))
		return resp
	}
	if req.PlannedState.IsNull() {
		resp.NewState = req.PlannedState
		if req.PriorState.IsNull() || req.PriorState.GetAttr("on_remove").AsString() != onRemoveDelete {
			return resp
		}
		h, err := winHost(ctx, req.PriorState.GetAttr("ssh"))
		if err != nil {
			return fail(err)
		}
		u := winUserRightFrom(req.PriorState)
		if err := windows.ApplyUserRightRemove(ctx, h.raw(), u.Name, u.Principals); err != nil {
			return fail(err)
		}
		return resp
	}
	u := winUserRightFrom(req.PlannedState)
	if err := u.Validate(); err != nil {
		return fail(err)
	}
	h, err := winHost(ctx, req.PlannedState.GetAttr("ssh"))
	if err != nil {
		return fail(err)
	}
	a, err := windows.ReadUserRight(ctx, h.raw(), u)
	if err != nil {
		return fail(err)
	}
	if !u.Matches(a) {
		if err := windows.ApplyUserRight(ctx, h.raw(), u, a); err != nil {
			return fail(err)
		}
		if a, err = windows.ReadUserRight(ctx, h.raw(), u); err != nil {
			return fail(err)
		}
		if !u.Matches(a) {
			return fail(fmt.Errorf("%s isn't held as set; something else changed it", u.Name))
		}
	}
	resp.NewState = withSync(req.PlannedState, true)
	return resp
}
