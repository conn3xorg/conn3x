// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/conn3x/modules/patch"
	"github.com/opentofu/opentofu/internal/providers"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

func patchSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "A unified diff applied to a file or a tree with GNU patch, or taken out again. Dry runs both ways tell whether it's in; a patch that fits neither way is reported, never forced.",
		Attributes: map[string]*configschema.Attribute{
			"id":                {Type: cty.String, Computed: true},
			"revision":          revisionAttr(),
			"content":           {Type: cty.String, Optional: true, Description: "The patch itself, such as file(\"${path.module}/files/fix.patch\"). Set this or src."},
			"src":               {Type: cty.String, Optional: true, Description: "A patch file already on the host, absolute. Set this or content."},
			"dest":              {Type: cty.String, Optional: true, Description: "The one file to patch, absolute. Set this or basedir."},
			"basedir":           {Type: cty.String, Optional: true, Description: "The directory the patch's file names start from, absolute, for a patch that touches several files. Set this or dest."},
			"strip":             {Type: cty.Number, Optional: true, Description: "How many leading directories to take off the patch's file names, as patch -p. Default 0."},
			"ignore_whitespace": {Type: cty.Bool, Optional: true, Description: "Match the patch's context even where whitespace differs, as patch --ignore-whitespace."},
			"binary":            {Type: cty.Bool, Optional: true, Description: "Read and write files byte for byte, without turning CRLF into LF, as patch --binary."},
			"state":             {Type: cty.String, Optional: true, Description: "\"present\" (default) applies the patch, \"absent\" takes it out."},
			"on_remove":         {Type: cty.String, Optional: true, Computed: true, Description: "What happens on the host when this resource is removed: \"forget\" (default) leaves the files as they are, \"delete\" takes the patch out when it's in."},
			"status":            {Type: cty.String, Computed: true, Description: "What the dry runs found at the last refresh: \"applied\", \"not_applied\", or \"conflict\" when the patch fits neither way."},
			"in_sync":           {Type: cty.Bool, Computed: true, Description: "Whether the patch was in, or out, as state asks, at the last refresh."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func patchFrom(v cty.Value) patch.Patch {
	return patch.Patch{
		Content:          stringOr(v.GetAttr("content"), ""),
		Src:              stringOr(v.GetAttr("src"), ""),
		Dest:             stringOr(v.GetAttr("dest"), ""),
		Basedir:          stringOr(v.GetAttr("basedir"), ""),
		Strip:            intOr(v.GetAttr("strip"), 0),
		IgnoreWhitespace: boolOr(v.GetAttr("ignore_whitespace")),
		Binary:           boolOr(v.GetAttr("binary")),
		State:            patch.State(stringOr(v.GetAttr("state"), string(patch.Present))),
	}
}

func validatePatch(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() || !cfg.IsWhollyKnown() {
		return diags
	}
	diags = diags.Append(validateOnRemove(cfg))
	if s := cfg.GetAttr("strip"); !s.IsNull() && !s.AsBigFloat().IsInt() {
		diags = diags.Append(attrError("strip", "strip must be a whole number"))
	}
	if err := patchFrom(cfg).Validate(); err != nil {
		diags = diags.Append(attrError("dest", err.Error()))
	}
	return diags
}

func planPatch(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	resp := planSynced(req, "patch", []string{"dest", "basedir"}, []string{"content", "src", "strip", "ignore_whitespace", "binary", "state"})
	if p := resp.PlannedState; !p.IsNull() && !p.GetAttr("in_sync").IsKnown() {
		vals := p.AsValueMap()
		vals["status"] = cty.UnknownVal(cty.String)
		resp.PlannedState = cty.ObjectVal(vals)
	}
	return resp
}

// patchState is v with what Check found.
func patchState(v cty.Value, st patch.Status) cty.Value {
	vals := v.AsValueMap()
	vals["status"] = cty.StringVal(string(st))
	vals["in_sync"] = cty.BoolVal(patch.InSync(patchFrom(v).State, st))
	return cty.ObjectVal(vals)
}

func readPatch(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	return readPathResource(ctx, req, func(ctx context.Context, h *hostConn, prior cty.Value) (cty.Value, error) {
		st, _, err := patch.Check(ctx, h, patchFrom(prior))
		if err != nil {
			return cty.NilVal, err
		}
		return patchState(prior, st), nil
	})
}

func applyPatch(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	return applyPathResource(ctx, req,
		func(ctx context.Context, h *hostConn, planned cty.Value) (cty.Value, error) {
			p := patchFrom(planned)
			if err := patch.Apply(ctx, h, p); err != nil {
				return cty.NilVal, fmt.Errorf("patch %s: %w", p.Dest+p.Basedir, err)
			}
			st, _, err := patch.Check(ctx, h, p)
			if err != nil {
				return cty.NilVal, err
			}
			state := patchState(planned, st)
			if state.GetAttr("in_sync").False() {
				return cty.NilVal, fmt.Errorf("patch %s: patch ran, but a dry run then found the patch %s", p.Dest+p.Basedir, st)
			}
			return state, nil
		},
		func(ctx context.Context, h *hostConn, prior cty.Value) error {
			p := patchFrom(prior)
			p.State = patch.Absent
			if err := patch.Apply(ctx, h, p); err != nil {
				return fmt.Errorf("patch %s: %w", p.Dest+p.Basedir, err)
			}
			return nil
		})
}
