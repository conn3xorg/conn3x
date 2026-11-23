// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/conn3x/modules/caps"
	"github.com/opentofu/opentofu/internal/providers"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

func capsSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "A file's capabilities, such as cap_net_bind_service so a service binds port 443 without root, kept with getcap and setcap. Owned whole: capabilities not listed are taken off.",
		Attributes: map[string]*configschema.Attribute{
			"id":           {Type: cty.String, Computed: true},
			"revision":     revisionAttr(),
			"path":         {Type: cty.String, Required: true, Description: "The file, absolute. It must exist."},
			"capabilities": {Type: cty.List(cty.String), Required: true, Description: "The capabilities, as setcap takes them, such as [\"cap_net_raw+ep\"] or [\"cap_net_bind_service,cap_net_raw=ep\"]. They're compared by meaning, so cap_net_raw+ep matches what newer getcap prints, cap_net_raw=ep."},
			"on_remove":    {Type: cty.String, Optional: true, Computed: true, Description: "What happens on the host when this resource is removed: \"forget\" (default) leaves the capabilities, \"delete\" takes them all off with setcap -r."},
			"in_sync":      {Type: cty.Bool, Computed: true, Description: "Whether the file had exactly these capabilities at the last refresh. A package upgrade that replaces the file drops them, which shows here."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func capsFrom(v cty.Value) (caps.File, error) {
	set, err := caps.Parse(strings.Join(stringList(v.GetAttr("capabilities")), " "))
	return caps.File{Path: stringOr(v.GetAttr("path"), ""), Caps: set}, err
}

func validateCaps(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() || !cfg.IsWhollyKnown() {
		return diags
	}
	diags = diags.Append(validateOnRemove(cfg))
	f, err := capsFrom(cfg)
	if err == nil {
		err = f.Validate()
	}
	if err != nil {
		diags = diags.Append(attrError("capabilities", err.Error()))
	}
	return diags
}

func planCaps(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	return planSynced(req, "file_capabilities", []string{"path"}, []string{"capabilities"})
}

func readCaps(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	return readPathResource(ctx, req, func(ctx context.Context, h *hostConn, prior cty.Value) (cty.Value, error) {
		f, err := capsFrom(prior)
		if err != nil {
			return cty.NilVal, err
		}
		have, err := caps.Read(ctx, h, f.Path)
		if err != nil {
			return cty.NilVal, err
		}
		return withSync(prior, have.Equal(f.Caps)), nil
	})
}

func applyCaps(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	return applyPathResource(ctx, req,
		func(ctx context.Context, h *hostConn, planned cty.Value) (cty.Value, error) {
			f, err := capsFrom(planned)
			if err != nil {
				return cty.NilVal, err
			}
			have, err := caps.Read(ctx, h, f.Path)
			if err == nil && !have.Equal(f.Caps) {
				err = caps.Apply(ctx, h, f)
			}
			if err != nil {
				return cty.NilVal, fmt.Errorf("file_capabilities: %w", err)
			}
			return withSync(planned, true), nil
		},
		func(ctx context.Context, h *hostConn, prior cty.Value) error {
			file := stringOr(prior.GetAttr("path"), "")
			// setcap -r fails on a file with nothing to take off.
			have, err := caps.Read(ctx, h, file)
			if err != nil || len(have) == 0 {
				return err
			}
			return caps.Remove(ctx, h, file)
		})
}
