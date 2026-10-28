// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/conn3x/modules/pkg"
	"github.com/opentofu/opentofu/internal/conn3x/modules/repo"
	"github.com/opentofu/opentofu/internal/providers"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

func repositorySchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "A package repository and its signing key: a .repo file for dnf, or a .sources file for apt, which then refreshes its package lists.",
		Attributes: map[string]*configschema.Attribute{
			"id":         {Type: cty.String, Computed: true},
			"revision":   revisionAttr(),
			"name":       {Type: cty.String, Required: true, Description: "Repository name, used for its file names."},
			"url":        {Type: cty.String, Required: true, Description: "Base URL. dnf expands $releasever and $basearch in it."},
			"key":        {Type: cty.String, Required: true, Description: "ASCII-armored public key the repository is signed with."},
			"suites":     {Type: cty.List(cty.String), Optional: true, Description: "apt suites, such as [\"noble\"]. Required on Debian and Ubuntu."},
			"components": {Type: cty.List(cty.String), Optional: true, Description: "apt components. Defaults to [\"main\"]."},
			"on_remove":  {Type: cty.String, Optional: true, Computed: true, Description: "\"forget\" (default) leaves the repository, \"delete\" removes its files."},
			"in_sync":    {Type: cty.Bool, Computed: true, Description: "Whether the repository's files match."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func repoFrom(v cty.Value) repo.Repo {
	list := func(l cty.Value) []string {
		var out []string
		if l.IsNull() {
			return out
		}
		for _, s := range l.AsValueSlice() {
			out = append(out, s.AsString())
		}
		return out
	}
	return repo.Repo{Name: v.GetAttr("name").AsString(), URL: v.GetAttr("url").AsString(), Key: v.GetAttr("key").AsString(),
		Suites: list(v.GetAttr("suites")), Components: list(v.GetAttr("components"))}
}

func validateRepository(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() || !cfg.IsWhollyKnown() {
		return diags
	}
	diags = diags.Append(validateOnRemove(cfg))
	// The host's family is not known until apply; check what both share,
	// and the apt fields whenever they are set.
	r := repoFrom(cfg)
	err := r.Validate(pkg.RPM)
	if err == nil && len(r.Suites) > 0 {
		err = r.Validate(pkg.Deb)
	}
	if err != nil {
		diags = diags.Append(attrError("url", err.Error()))
	}
	return diags
}

func planRepository(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	return planSynced(req, "repository", []string{"name"}, []string{"url", "key", "suites", "components"})
}

func readRepository(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	return readPathResource(ctx, req, func(ctx context.Context, h *hostConn, prior cty.Value) (cty.Value, error) {
		family, err := pkg.DetectFamily(ctx, h)
		if err != nil {
			return cty.NilVal, err
		}
		ok, err := repo.InSync(ctx, h, family, repoFrom(prior))
		if err != nil {
			return cty.NilVal, err
		}
		return withSync(prior, ok), nil
	})
}

func applyRepository(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	withFamily := func(ctx context.Context, h *hostConn, v cty.Value, do func(context.Context, *hostConn, pkg.Family, repo.Repo) error) error {
		family, err := pkg.DetectFamily(ctx, h)
		if err != nil {
			return err
		}
		r := repoFrom(v)
		// A repository refreshes the package lists, so it takes turns with
		// package steps: apt-get update beside apt-get install can fail.
		unlock := lockHost(h, "packages")
		defer unlock()
		if err := do(ctx, h, family, r); err != nil {
			return fmt.Errorf("repository %s: %w", r.Name, err)
		}
		return nil
	}
	return applyPathResource(ctx, req,
		func(ctx context.Context, h *hostConn, planned cty.Value) (cty.Value, error) {
			if err := withFamily(ctx, h, planned, func(ctx context.Context, h *hostConn, f pkg.Family, r repo.Repo) error {
				return repo.Apply(ctx, h, f, r)
			}); err != nil {
				return cty.NilVal, err
			}
			return withSync(planned, true), nil
		},
		func(ctx context.Context, h *hostConn, prior cty.Value) error {
			return withFamily(ctx, h, prior, func(ctx context.Context, h *hostConn, f pkg.Family, r repo.Repo) error {
				return repo.Delete(ctx, h, f, r)
			})
		})
}
