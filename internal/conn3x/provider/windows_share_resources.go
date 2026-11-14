// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/conn3x/modules/windows"
	"github.com/opentofu/opentofu/internal/providers"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

func winShareSchema() providers.Schema {
	list := func(right string) *configschema.Attribute {
		return &configschema.Attribute{Type: cty.List(cty.String), Optional: true, Description: "Accounts with " + right + " access, such as BUILTIN\\Administrators or CONTOSO\\Finance. When any of full_access, change_access and read_access is set, the three together are the share's whole set of Allow entries: others are revoked. Unset, all three, leaves access alone."}
	}
	return providers.Schema{Block: &configschema.Block{
		Description: winExperimental + "An SMB share on a Windows host, and who may use it. Access changes in place, never by recreating the share. Deny entries are left alone.",
		Attributes: map[string]*configschema.Attribute{
			"id":            {Type: cty.String, Computed: true},
			"revision":      revisionAttr(),
			"name":          {Type: cty.String, Required: true, Description: "The share name, such as Finance, or Backup$ for one hidden from browsing. Not C$, ADMIN$ or IPC$."},
			"path":          {Type: cty.String, Required: true, Description: "The folder it shares, such as D:\\Shares\\Finance. It must exist; make it with a windows_directory step. A share's folder can't change in place."},
			"description":   {Type: cty.String, Optional: true, Description: "Its description. Unset leaves it alone."},
			"full_access":   list("Full"),
			"change_access": list("Change"),
			"read_access":   list("Read"),
			"on_remove":     {Type: cty.String, Optional: true, Computed: true, Description: "\"delete\" (default) removes the share when the step goes, and leaves the folder and its files; \"forget\" leaves the share."},
			"in_sync":       {Type: cty.Bool, Computed: true, Description: "Whether the share, its description and its Allow entries matched at the last refresh."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func winShareFrom(v cty.Value) windows.Share {
	s := windows.Share{Name: stringOr(v.GetAttr("name"), ""), Path: stringOr(v.GetAttr("path"), ""), Description: optString(v.GetAttr("description"))}
	for attr, dst := range map[string]*[]string{"full_access": &s.Full, "change_access": &s.Change, "read_access": &s.Read} {
		if l := v.GetAttr(attr); known(l) {
			*dst = append([]string{}, stringList(l)...)
		}
	}
	return s
}

func validateWinShare(cfg cty.Value) tfdiags.Diagnostics {
	if cfg.IsNull() || !cfg.IsWhollyKnown() {
		return nil
	}
	diags := validateOnRemove(cfg)
	if err := winShareFrom(cfg).Validate(); err != nil {
		diags = diags.Append(attrError("name", err.Error()))
	}
	return diags
}

func planWinShare(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	return planSyncedFold(deleteByDefault(req), "windows_share", []string{"name", "path"}, []string{"description", "full_access", "change_access", "read_access"})
}

func readWinShare(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	resp := providers.ReadResourceResponse{NewState: req.PriorState}
	if req.PriorState.IsNull() {
		return resp
	}
	h, err := winHost(ctx, req.PriorState.GetAttr("ssh"))
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(attrError("ssh", err.Error()))
		return resp
	}
	s := winShareFrom(req.PriorState)
	a, err := windows.ReadShare(ctx, h.client, s)
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(err)
		return resp
	}
	ok, err := s.Matches(a)
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(tfdiags.SimpleWarning("windows_share " + s.Name + ": " + err.Error()))
	}
	resp.NewState = withSync(req.PriorState, ok)
	return resp
}

func applyWinShare(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	return applyWinStep(ctx, req, "windows_share", func(ctx context.Context, h *hostConn, v cty.Value, remove bool) error {
		if remove {
			return windows.ApplyShareRemove(ctx, h.client, winShareFrom(v).Name)
		}
		return windows.ApplyShare(ctx, h.client, winShareFrom(v))
	})
}
