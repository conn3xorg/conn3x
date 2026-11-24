// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/conn3x/modules/pack"
	"github.com/opentofu/opentofu/internal/providers"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

func packSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "Files and directories on the host packed into a tar or zip archive. It's packed again when a packed file's size, time, mode or owner changes, or the archive is gone.",
		Attributes: map[string]*configschema.Attribute{
			"id":             {Type: cty.String, Computed: true},
			"revision":       revisionAttr(),
			"paths":          {Type: cty.List(cty.String), Required: true, Description: "Absolute paths of the files and directories to pack. * and ? in a path's last part match names in its directory, as /var/log/app/*.log does; names starting with a dot match only a pattern that starts with one. Names in the archive start from the deepest directory holding every path."},
			"dest":           {Type: cty.String, Required: true, Description: "Absolute path of the archive. Its directory must exist."},
			"format":         {Type: cty.String, Optional: true, Description: "\"gz\" (default), \"bz2\", \"xz\", \"zstd\", \"tar\" or \"zip\". Every format but zip needs GNU tar; each also needs its own program: gzip, bzip2, xz, zstd or zip."},
			"exclude":        {Type: cty.List(cty.String), Optional: true, Description: "Absolute paths or patterns to leave out, matched against every entry's path, where * and ? match any characters, / too. A matching directory is left out with everything in it."},
			"owner":          {Type: cty.String, Optional: true, Description: "Owner of the archive."},
			"group":          {Type: cty.String, Optional: true, Description: "Group of the archive."},
			"mode":           {Type: cty.String, Optional: true, Description: "Mode of the archive, four octal digits. Default \"0600\": an archive of /etc can hold secrets."},
			"on_remove":      {Type: cty.String, Optional: true, Computed: true, Description: "What happens on the host when this resource is removed: \"forget\" (default) leaves the archive, \"delete\" deletes it. The packed files are never touched."},
			"sources_sha256": {Type: cty.String, Computed: true, Description: "SHA-256 over the name, type, mode, owner, group, size and modification time of every entry packed at the last apply."},
			"in_sync":        {Type: cty.Bool, Computed: true, Description: "Whether the archive was there, and its files unchanged since it was packed, at the last refresh."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func packFrom(v cty.Value) pack.Pack {
	return pack.Pack{
		Paths:   stringList(v.GetAttr("paths")),
		Exclude: stringList(v.GetAttr("exclude")),
		Dest:    stringOr(v.GetAttr("dest"), ""),
		Format:  stringOr(v.GetAttr("format"), ""),
		Owner:   stringOr(v.GetAttr("owner"), ""),
		Group:   stringOr(v.GetAttr("group"), ""),
		Mode:    stringOr(v.GetAttr("mode"), ""),
	}
}

func validatePack(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() || !settled(cfg) {
		return diags
	}
	diags = diags.Append(validateOnRemove(cfg))
	for _, k := range []string{"paths", "exclude"} {
		if v := cfg.GetAttr(k); !v.IsNull() {
			for _, e := range v.AsValueSlice() {
				if e.IsNull() {
					return diags.Append(attrError(k, k+" can't hold null"))
				}
			}
		}
	}
	if err := packFrom(cfg).Validate(); err != nil {
		diags = diags.Append(attrError("paths", err.Error()))
	}
	return diags
}

func planPack(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	resp := planSynced(req, "pack", []string{"dest"}, []string{"paths", "format", "exclude", "owner", "group", "mode"})
	if p := resp.PlannedState; !p.IsNull() && !p.GetAttr("in_sync").IsKnown() {
		vals := p.AsValueMap()
		vals["sources_sha256"] = cty.UnknownVal(cty.String)
		resp.PlannedState = cty.ObjectVal(vals)
	}
	return resp
}

// packSynced is v after a refresh that found sum and whether the archive is
// there: in sync while it is and sum is what was packed.
func packSynced(v cty.Value, sum string, present bool) cty.Value {
	packed := v.GetAttr("sources_sha256")
	return withSync(v, present && known(packed) && packed.AsString() == sum)
}

func readPack(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	return readPathResource(ctx, req, func(ctx context.Context, h *hostConn, prior cty.Value) (cty.Value, error) {
		sum, present, err := pack.Read(ctx, h, packFrom(prior))
		if err != nil {
			return cty.NilVal, err
		}
		return packSynced(prior, sum, present), nil
	})
}

func applyPack(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	return applyPathResource(ctx, req,
		func(ctx context.Context, h *hostConn, planned cty.Value) (cty.Value, error) {
			p := packFrom(planned)
			sum, err := pack.Apply(ctx, h, p)
			if err != nil {
				return cty.NilVal, fmt.Errorf("pack %s: %w", p.Dest, err)
			}
			vals := planned.AsValueMap()
			vals["sources_sha256"] = cty.StringVal(sum)
			return withSync(cty.ObjectVal(vals), true), nil
		},
		func(ctx context.Context, h *hostConn, prior cty.Value) error {
			return pack.Delete(ctx, h, packFrom(prior).Dest)
		})
}
