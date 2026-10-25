// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/conn3x/modules/account"
	"github.com/opentofu/opentofu/internal/conn3x/modules/sshkey"
	"github.com/opentofu/opentofu/internal/providers"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

func authorizedKeySchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "One public key in a user's ~/.ssh/authorized_keys.",
		Attributes: map[string]*configschema.Attribute{
			"id":        {Type: cty.String, Computed: true},
			"revision":  revisionAttr(),
			"user":      {Type: cty.String, Required: true, Description: "The account the key logs in as."},
			"key":       {Type: cty.String, Required: true, Description: "Public key, in authorized_keys format."},
			"state":     {Type: cty.String, Optional: true, Description: "\"present\" (default) or \"absent\"."},
			"on_remove": {Type: cty.String, Optional: true, Computed: true, Description: "\"delete\" (default) removes the key, so a rotated key stops working; \"forget\" leaves it."},
			"in_sync":   {Type: cty.Bool, Computed: true, Description: "Whether authorized_keys already matches."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func keyPresent(v cty.Value) bool { return stringOr(v.GetAttr("state"), "present") != "absent" }

func validateAuthorizedKey(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() || !cfg.IsWhollyKnown() {
		return diags
	}
	diags = diags.Append(validateOnRemove(cfg))
	if s := stringOr(cfg.GetAttr("state"), "present"); s != "present" && s != "absent" {
		diags = diags.Append(attrError("state", fmt.Sprintf("state must be \"present\" or \"absent\", not %q", s)))
	}
	if err := (account.UserSpec{Name: cfg.GetAttr("user").AsString()}).Validate(); err != nil {
		diags = diags.Append(attrError("user", err.Error()))
	}
	if _, err := sshkey.Edit("", cfg.GetAttr("key").AsString(), true); err != nil {
		diags = diags.Append(attrError("key", err.Error()))
	}
	return diags
}

func planAuthorizedKey(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	var resp providers.PlanResourceChangeResponse
	if req.ProposedNewState.IsNull() {
		resp.PlannedState = req.ProposedNewState
		return resp
	}
	vals := deleteByDefault(req).ProposedNewState.AsValueMap()
	host := req.ProposedNewState.GetAttr("ssh").GetAttr("host")
	if user := vals["user"]; user.IsKnown() {
		vals["id"] = planID(req, "authorized_key", user.AsString())
	} else {
		vals["id"] = cty.UnknownVal(cty.String)
	}
	stale := req.PriorState.IsNull()
	if !stale {
		for _, a := range []string{"user", "key"} {
			if !req.PriorState.GetAttr(a).RawEquals(vals[a]) {
				resp.RequiresReplace = append(resp.RequiresReplace, cty.GetAttrPath(a))
				stale = true
			}
		}
		if !req.PriorState.GetAttr("ssh").GetAttr("host").RawEquals(host) {
			resp.RequiresReplace = append(resp.RequiresReplace, cty.GetAttrPath("ssh").GetAttr("host"))
		}
		if s := req.PriorState.GetAttr("in_sync"); !known(s) || s.False() || !req.PriorState.GetAttr("state").RawEquals(vals["state"]) {
			stale = true
		}
	}
	vals["in_sync"] = cty.True
	if stale {
		vals["in_sync"] = cty.UnknownVal(cty.Bool)
	}
	resp.PlannedState = cty.ObjectVal(vals)
	return resp
}

func readAuthorizedKey(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	return readPathResource(ctx, req, func(ctx context.Context, h *hostConn, prior cty.Value) (cty.Value, error) {
		vals := prior.AsValueMap()
		loc, err := sshkey.Locate(ctx, h, prior.GetAttr("user").AsString())
		if err != nil {
			vals["in_sync"] = cty.False
			return cty.ObjectVal(vals), nil
		}
		content, err := sshkey.Read(ctx, h, loc)
		if err != nil {
			return cty.NilVal, err
		}
		edited, err := sshkey.Edit(content, prior.GetAttr("key").AsString(), keyPresent(prior))
		if err != nil {
			return cty.NilVal, err
		}
		vals["in_sync"] = cty.BoolVal(edited == content)
		return cty.ObjectVal(vals), nil
	})
}

func applyAuthorizedKey(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	run := func(ctx context.Context, h *hostConn, v cty.Value, present bool) error {
		loc, err := sshkey.Locate(ctx, h, v.GetAttr("user").AsString())
		if err != nil {
			return err
		}
		return sshkey.Apply(ctx, h, loc, v.GetAttr("key").AsString(), present)
	}
	return applyPathResource(ctx, req,
		func(ctx context.Context, h *hostConn, planned cty.Value) (cty.Value, error) {
			if err := run(ctx, h, planned, keyPresent(planned)); err != nil {
				return cty.NilVal, fmt.Errorf("authorized key for %s: %w", planned.GetAttr("user").AsString(), err)
			}
			vals := planned.AsValueMap()
			vals["in_sync"] = cty.True
			return cty.ObjectVal(vals), nil
		},
		func(ctx context.Context, h *hostConn, prior cty.Value) error { return run(ctx, h, prior, false) })
}
