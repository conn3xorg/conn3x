// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/conn3x/modules/pkg"
	"github.com/opentofu/opentofu/internal/conn3x/modules/repo"
	"github.com/opentofu/opentofu/internal/providers"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

func packageSourcesSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "Keeps a host to the distribution's package sources, those repository steps wrote, and keep: any other file in /etc/apt/sources.list.d or /etc/yum.repos.d is moved to " + repo.DisabledDir + ".",
		Attributes: map[string]*configschema.Attribute{
			"id":       {Type: cty.String, Computed: true},
			"revision": revisionAttr(),
			"keep":     {Type: cty.List(cty.String), Optional: true, Description: "File names to keep as well, such as \"ubuntu-esm-apps.sources\"."},
			"remove":   {Type: cty.List(cty.String), Optional: true, Description: "The distribution's files to move aside anyway, such as \"rocky-devel.repo\"."},
			"unlisted": {Type: cty.List(cty.String), Computed: true, Description: "Files the step doesn't keep, by name, as of the last refresh. Apply moves them aside."},
			"in_sync":  {Type: cty.Bool, Computed: true, Description: "Whether the host had no other package sources at the last refresh."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func packageSourcesFrom(v cty.Value) repo.Sources {
	list := func(l cty.Value) []string {
		var out []string
		if !known(l) {
			return out
		}
		for _, s := range l.AsValueSlice() {
			out = append(out, stringOr(s, ""))
		}
		return out
	}
	return repo.Sources{Keep: list(v.GetAttr("keep")), Remove: list(v.GetAttr("remove"))}
}

func validatePackageSources(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() || !cfg.IsWhollyKnown() {
		return diags
	}
	if err := packageSourcesFrom(cfg).Validate(); err != nil {
		diags = diags.Append(attrError("keep", err.Error()))
	}
	return diags
}

func planPackageSources(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	resp := planSynced(req, "package_sources", nil, []string{"keep", "remove"})
	if resp.PlannedState.IsNull() {
		return resp
	}
	vals := resp.PlannedState.AsValueMap()
	vals["unlisted"] = cty.ListValEmpty(cty.String)
	if !req.PriorState.IsNull() {
		if u := req.PriorState.GetAttr("unlisted"); !known(u) || u.LengthInt() > 0 {
			vals["in_sync"] = cty.UnknownVal(cty.Bool)
		}
	}
	resp.PlannedState = cty.ObjectVal(vals)
	return resp
}

// unlistedSources reads the host and returns the files s doesn't keep.
func unlistedSources(ctx context.Context, h *hostConn, s repo.Sources) (pkg.Family, []string, error) {
	family, err := pkg.DetectFamily(ctx, h)
	if err != nil {
		return "", nil, err
	}
	id, files, err := repo.ReadSources(ctx, h, family)
	if err != nil {
		return "", nil, err
	}
	gone, err := s.Unlisted(family, id, files)
	return family, gone, err
}

func readPackageSources(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	var gone []string
	resp := readPathResource(ctx, req, func(ctx context.Context, h *hostConn, prior cty.Value) (cty.Value, error) {
		var err error
		if _, gone, err = unlistedSources(ctx, h, packageSourcesFrom(prior)); err != nil {
			return cty.NilVal, err
		}
		vals := prior.AsValueMap()
		vals["in_sync"] = cty.BoolVal(len(gone) == 0)
		vals["unlisted"] = cty.ListValEmpty(cty.String)
		if len(gone) > 0 {
			names := make([]cty.Value, len(gone))
			for i, g := range gone {
				names[i] = cty.StringVal(g)
			}
			vals["unlisted"] = cty.ListVal(names)
		}
		return cty.ObjectVal(vals), nil
	})
	if len(gone) > 0 && !resp.Diagnostics.HasErrors() {
		resp.Diagnostics = resp.Diagnostics.Append(tfdiags.SimpleWarning(fmt.Sprintf(
			"%d package source(s) the package_sources step doesn't keep, which apply moves to %s: %s", len(gone), repo.DisabledDir, strings.Join(gone, ", "))))
	}
	return resp
}

func applyPackageSources(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	return applyPathResource(ctx, req,
		func(ctx context.Context, h *hostConn, planned cty.Value) (cty.Value, error) {
			s := packageSourcesFrom(planned)
			if err := s.Validate(); err != nil {
				return cty.NilVal, err
			}
			// Moving sources and refreshing apt takes turns with package
			// and repository steps.
			unlock := lockHost(h, "packages")
			defer unlock()
			family, gone, err := unlistedSources(ctx, h, s)
			if err != nil {
				return cty.NilVal, err
			}
			if err := repo.Disable(ctx, h, family, gone); err != nil {
				return cty.NilVal, err
			}
			vals := planned.AsValueMap()
			vals["in_sync"] = cty.True
			vals["unlisted"] = cty.ListValEmpty(cty.String)
			return cty.ObjectVal(vals), nil
		},
		// Removing the step leaves the files where they are; it has no
		// on_remove, since putting them back isn't safe to guess.
		func(context.Context, *hostConn, cty.Value) error { return nil })
}
