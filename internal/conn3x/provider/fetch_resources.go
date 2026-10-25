// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/conn3x/modules/fetch"
	"github.com/opentofu/opentofu/internal/providers"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

func validateWith(attr string, check func(cty.Value) error) func(cty.Value) tfdiags.Diagnostics {
	return func(cfg cty.Value) tfdiags.Diagnostics {
		var diags tfdiags.Diagnostics
		if cfg.IsNull() || !cfg.IsWhollyKnown() {
			return diags
		}
		if cfg.Type().HasAttribute("on_remove") {
			diags = diags.Append(validateOnRemove(cfg))
		}
		if err := check(cfg); err != nil {
			diags = diags.Append(attrError(attr, err.Error()))
		}
		return diags
	}
}

func downloadSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "A file downloaded on the host and kept only if its SHA-256 matches.",
		Attributes: map[string]*configschema.Attribute{
			"id":        {Type: cty.String, Computed: true},
			"revision":  revisionAttr(),
			"url":       {Type: cty.String, Required: true, Description: "http or https URL."},
			"dest":      {Type: cty.String, Required: true, Description: "Absolute path to save it to."},
			"sha256":    {Type: cty.String, Required: true, Description: "Expected SHA-256, in lowercase hex."},
			"mode":      {Type: cty.String, Optional: true, Description: "Octal permissions. Defaults to \"0644\"."},
			"owner":     {Type: cty.String, Optional: true, Description: "Owner."},
			"group":     {Type: cty.String, Optional: true, Description: "Group."},
			"on_remove": {Type: cty.String, Optional: true, Computed: true, Description: "\"forget\" (default) leaves the file, \"delete\" removes it."},
			"in_sync":   {Type: cty.Bool, Computed: true, Description: "Whether the file is there with the right checksum."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func downloadFrom(v cty.Value) fetch.Download {
	return fetch.Download{URL: v.GetAttr("url").AsString(), Dest: v.GetAttr("dest").AsString(), SHA256: v.GetAttr("sha256").AsString(),
		Mode: stringOr(v.GetAttr("mode"), ""), Owner: stringOr(v.GetAttr("owner"), ""), Group: stringOr(v.GetAttr("group"), "")}
}

func planDownload(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	return planSynced(req, "download", []string{"dest"}, []string{"url", "sha256", "mode", "owner", "group"})
}

func readDownload(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	return readPathResource(ctx, req, func(ctx context.Context, h *hostConn, prior cty.Value) (cty.Value, error) {
		d := downloadFrom(prior)
		got, err := fetch.ReadDownload(ctx, h, d.Dest)
		if err != nil {
			return cty.NilVal, err
		}
		return withSync(prior, got == d.SHA256), nil
	})
}

func applyDownload(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	return applyPathResource(ctx, req,
		func(ctx context.Context, h *hostConn, planned cty.Value) (cty.Value, error) {
			d := downloadFrom(planned)
			if err := fetch.ApplyDownload(ctx, h, d); err != nil {
				return cty.NilVal, fmt.Errorf("download %s: %w", d.Dest, err)
			}
			return withSync(planned, true), nil
		},
		func(ctx context.Context, h *hostConn, prior cty.Value) error {
			return fetch.DeleteDownload(ctx, h, downloadFrom(prior).Dest)
		})
}

func archiveSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "A tar or zip file on the host, unpacked into a directory unless its creates path exists. Removing it leaves the files.",
		Attributes: map[string]*configschema.Attribute{
			"id":       {Type: cty.String, Computed: true},
			"revision": revisionAttr(),
			"src":      {Type: cty.String, Required: true, Description: "Absolute path of the archive on the host, such as a download's dest."},
			"dest":     {Type: cty.String, Required: true, Description: "Directory to unpack into."},
			"creates":  {Type: cty.String, Required: true, Description: "A path the archive creates. While it exists, nothing is unpacked."},
			"in_sync":  {Type: cty.Bool, Computed: true, Description: "Whether the creates path exists."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func archiveFrom(v cty.Value) fetch.Archive {
	return fetch.Archive{Src: v.GetAttr("src").AsString(), Dest: v.GetAttr("dest").AsString(), Creates: v.GetAttr("creates").AsString()}
}

func planArchive(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	return planSynced(req, "archive", []string{"dest"}, []string{"src", "creates"})
}

func readArchive(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	return readPathResource(ctx, req, func(ctx context.Context, h *hostConn, prior cty.Value) (cty.Value, error) {
		ok, err := fetch.ReadArchive(ctx, h, archiveFrom(prior))
		if err != nil {
			return cty.NilVal, err
		}
		return withSync(prior, ok), nil
	})
}

func applyArchive(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	return applyPathResource(ctx, req,
		func(ctx context.Context, h *hostConn, planned cty.Value) (cty.Value, error) {
			a := archiveFrom(planned)
			if err := fetch.ApplyArchive(ctx, h, a); err != nil {
				return cty.NilVal, fmt.Errorf("archive %s: %w", a.Src, err)
			}
			return withSync(planned, true), nil
		}, nil)
}

func gitSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "A git checkout at a branch, tag or commit. Refresh notices when a branch moves on the remote. Removing it leaves the checkout.",
		Attributes: map[string]*configschema.Attribute{
			"id":       {Type: cty.String, Computed: true},
			"revision": revisionAttr(),
			"repo":     {Type: cty.String, Required: true, Description: "Repository URL. The host needs access to it."},
			"dest":     {Type: cty.String, Required: true, Description: "Directory to check it out in."},
			"ref":      {Type: cty.String, Optional: true, Description: "Branch, tag or full commit. Defaults to the remote's default branch."},
			"commit":   {Type: cty.String, Computed: true, Description: "The commit checked out."},
			"in_sync":  {Type: cty.Bool, Computed: true, Description: "Whether the checkout is at the commit ref points to."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func gitFrom(v cty.Value) fetch.Git {
	return fetch.Git{Repo: v.GetAttr("repo").AsString(), Dest: v.GetAttr("dest").AsString(), Ref: stringOr(v.GetAttr("ref"), "")}
}

func planGit(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	resp := planSynced(req, "git", []string{"dest"}, []string{"repo", "ref"})
	if resp.PlannedState.IsNull() || resp.PlannedState.GetAttr("in_sync").IsKnown() {
		return resp
	}
	vals := resp.PlannedState.AsValueMap()
	vals["commit"] = cty.UnknownVal(cty.String)
	resp.PlannedState = cty.ObjectVal(vals)
	return resp
}

func readGit(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	return readPathResource(ctx, req, func(ctx context.Context, h *hostConn, prior cty.Value) (cty.Value, error) {
		g := gitFrom(prior)
		have, err := fetch.Checkout(ctx, h, g.Dest)
		if err != nil {
			return cty.NilVal, err
		}
		want, err := fetch.Remote(ctx, h, g)
		if err != nil {
			return cty.NilVal, err
		}
		vals := withSync(prior, have != "" && have == want).AsValueMap()
		vals["commit"] = cty.StringVal(have)
		return cty.ObjectVal(vals), nil
	})
}

func applyGit(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	return applyPathResource(ctx, req,
		func(ctx context.Context, h *hostConn, planned cty.Value) (cty.Value, error) {
			g := gitFrom(planned)
			commit, err := fetch.Remote(ctx, h, g)
			if err == nil {
				err = fetch.ApplyGit(ctx, h, g, commit)
			}
			if err != nil {
				return cty.NilVal, fmt.Errorf("git %s: %w", g.Dest, err)
			}
			vals := withSync(planned, true).AsValueMap()
			vals["commit"] = cty.StringVal(commit)
			return cty.ObjectVal(vals), nil
		}, nil)
}
