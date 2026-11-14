// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"errors"
	"fmt"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/conn3x/modules/windows"
	"github.com/opentofu/opentofu/internal/providers"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

func winCertSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: winExperimental + "A certificate file on a Windows host, imported into a certificate store: a CA's .cer into Root, or a server's .pfx, with its private key, into My for IIS.",
		Attributes: map[string]*configschema.Attribute{
			"id":             {Type: cty.String, Computed: true},
			"revision":       revisionAttr(),
			"path":           {Type: cty.String, Required: true, Description: "The file on the host, ending in .cer, .crt, .der, .pfx or .p12, such as C:\\certs\\web.pfx. A .pfx or .p12 is imported with its private key."},
			"store_location": {Type: cty.String, Optional: true, Description: "\"LocalMachine\" (default) or \"CurrentUser\", the account Conn3x logs in as."},
			"store_name":     {Type: cty.String, Required: true, Description: "The store, such as My (personal, where IIS looks), Root, CA, TrustedPeople or WebHosting."},
			"password_wo":    {Type: cty.String, Optional: true, Sensitive: true, WriteOnly: true, Description: "Write-only: a .pfx's password, never kept in state or plan files."},
			"state":          {Type: cty.String, Optional: true, Description: "\"present\" (default), or \"absent\" to take the certificate out of the store."},
			"thumbprint":     {Type: cty.String, Computed: true, Description: "The imported certificate's thumbprint, which a refresh looks for in the store. For a .pfx with its chain, the one with the private key."},
			"file_sha256":    {Type: cty.String, Computed: true, Description: "The file's SHA-256 at the import. A different file at path, such as a renewed certificate, plans a new import."},
			"on_remove":      {Type: cty.String, Optional: true, Computed: true, Description: "What happens on the host when this resource is removed: \"forget\" (default) leaves the certificate in the store, \"delete\" takes it out. The file stays either way."},
			"in_sync":        {Type: cty.Bool, Computed: true, Description: "Whether the store had the certificate, and the file was still the one imported, at the last refresh."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func winCertFrom(v cty.Value) windows.Certificate {
	return windows.Certificate{Path: stringOr(v.GetAttr("path"), ""), Location: stringOr(v.GetAttr("store_location"), "LocalMachine"), Store: stringOr(v.GetAttr("store_name"), ""), Absent: stringOr(v.GetAttr("state"), "present") == "absent"}
}

func validateWinCert(cfg cty.Value) tfdiags.Diagnostics {
	if cfg.IsNull() {
		return nil
	}
	diags := validateOnRemove(cfg)
	if s := cfg.GetAttr("state"); known(s) && s.AsString() != "present" && s.AsString() != "absent" {
		diags = diags.Append(attrError("state", fmt.Sprintf(`state must be "present" or "absent", not %q`, s.AsString())))
	}
	for _, a := range []string{"path", "store_location", "store_name"} {
		if !cfg.GetAttr(a).IsKnown() {
			return diags
		}
	}
	c := winCertFrom(cfg)
	if err := c.Validate(); err != nil {
		return diags.Append(attrError("path", err.Error()))
	}
	if c.PFX() && !c.Absent && cfg.GetAttr("password_wo").IsNull() {
		diags = diags.Append(attrError("password_wo", "a .pfx or .p12 needs password_wo to import it"))
	}
	return diags
}

func planWinCert(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	if !req.ProposedNewState.IsNull() {
		vals := req.ProposedNewState.AsValueMap()
		vals["password_wo"] = cty.NullVal(cty.String)
		req.ProposedNewState = cty.ObjectVal(vals)
	}
	return unknownWhenStale(planSyncedFold(req, "windows_certificate", []string{"path", "store_location", "store_name"}, []string{"state"}), "thumbprint", "file_sha256")
}

func readWinCert(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	resp := providers.ReadResourceResponse{NewState: req.PriorState}
	if req.PriorState.IsNull() {
		return resp
	}
	h, err := winHost(ctx, req.PriorState.GetAttr("ssh"))
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(attrError("ssh", err.Error()))
		return resp
	}
	c := winCertFrom(req.PriorState)
	a, err := windows.ReadCertificate(ctx, h.client, c, stringOr(req.PriorState.GetAttr("thumbprint"), ""))
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(err)
		return resp
	}
	resp.NewState = withSync(req.PriorState, c.Matches(a, stringOr(req.PriorState.GetAttr("file_sha256"), "")))
	return resp
}

func applyWinCert(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	var resp providers.ApplyResourceChangeResponse
	v, remove := req.PlannedState, req.PlannedState.IsNull()
	if remove {
		resp.NewState = req.PlannedState
		if req.PriorState.IsNull() || req.PriorState.GetAttr("on_remove").AsString() != onRemoveDelete {
			return resp
		}
		v = req.PriorState
	}
	h, err := winHost(ctx, v.GetAttr("ssh"))
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(attrError("ssh", err.Error()))
		return resp
	}
	c := winCertFrom(v)
	prior := ""
	if !req.PriorState.IsNull() {
		prior = stringOr(req.PriorState.GetAttr("thumbprint"), "")
	}
	if remove {
		c.Absent = true
	} else if c.PFX() && !c.Absent {
		if !req.Config.IsNull() {
			c.Password = stringOr(req.Config.GetAttr("password_wo"), "")
		}
		if c.Password == "" {
			resp.Diagnostics = resp.Diagnostics.Append(errors.New("windows_certificate: password_wo didn't reach the apply; it's write-only, so set it in the step's config"))
			return resp
		}
	}
	thumb, sum, err := windows.ApplyCertificate(ctx, h.client, c, prior)
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("windows_certificate: %w", err))
		return resp
	}
	if remove {
		return resp
	}
	vals := v.AsValueMap()
	vals["password_wo"] = cty.NullVal(cty.String)
	if c.Absent {
		vals["thumbprint"], vals["file_sha256"] = cty.NullVal(cty.String), cty.NullVal(cty.String)
	} else {
		vals["thumbprint"], vals["file_sha256"] = cty.StringVal(thumb), cty.StringVal(sum)
	}
	resp.NewState = withSync(cty.ObjectVal(vals), true)
	return resp
}
