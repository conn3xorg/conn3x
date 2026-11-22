// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"math/big"

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
			"id":         {Type: cty.String, Computed: true},
			"revision":   revisionAttr(),
			"url":        {Type: cty.String, Required: true, Description: "http or https URL, without a user name or password."},
			"netrc_file": {Type: cty.String, Optional: true, Description: "Absolute path of a netrc file on the host with the login for the URL's server. Needs curl on the host."},
			"headers":    {Type: cty.Map(cty.String), Optional: true, Description: "Request headers, such as { Accept = \"application/octet-stream\" }. Sent only to the URL's origin: a redirect to another host goes on without them. Needs curl on the host."},
			"headers_wo": {Type: cty.Map(cty.String), Optional: true, WriteOnly: true, Sensitive: true, Description: "Headers kept out of plan and state, such as { Authorization = \"Bearer ...\" } or { PRIVATE-TOKEN = ... }. They reach curl on stdin, never its command line, and only the URL's origin gets them. A change to them alone downloads nothing: sha256 decides whether the file is right. Needs curl on the host."},
			"dest":       {Type: cty.String, Required: true, Description: "Absolute path to save it to."},
			"sha256":     {Type: cty.String, Required: true, Description: "Expected SHA-256, in lowercase hex."},
			"mode":       {Type: cty.String, Optional: true, Description: "Octal permissions. Defaults to \"0644\"."},
			"owner":      {Type: cty.String, Optional: true, Description: "Owner."},
			"group":      {Type: cty.String, Optional: true, Description: "Group."},
			"on_remove":  {Type: cty.String, Optional: true, Computed: true, Description: "\"forget\" (default) leaves the file, \"delete\" removes it."},
			"in_sync":    {Type: cty.Bool, Computed: true, Description: "Whether the file is there with the right checksum."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func downloadFrom(v cty.Value) fetch.Download {
	d := fetch.Download{URL: v.GetAttr("url").AsString(), Dest: v.GetAttr("dest").AsString(), SHA256: v.GetAttr("sha256").AsString(),
		Mode: stringOr(v.GetAttr("mode"), ""), Owner: stringOr(v.GetAttr("owner"), ""), Group: stringOr(v.GetAttr("group"), ""),
		NetrcFile: stringOr(v.GetAttr("netrc_file"), "")}
	for _, name := range []string{"headers", "headers_wo"} {
		if h := v.GetAttr(name); known(h) {
			if d.Headers == nil {
				d.Headers = map[string]string{}
			}
			for k, e := range h.AsValueMap() {
				d.Headers[k] = stringOr(e, "")
			}
		}
	}
	return d
}

func planDownload(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	resp := planSynced(req, "download", []string{"dest"}, []string{"url", "sha256", "mode", "owner", "group"})
	// Write-only values never reach plan or state; apply reads them from
	// the configuration.
	if !resp.PlannedState.IsNull() {
		vals := resp.PlannedState.AsValueMap()
		vals["headers_wo"] = cty.NullVal(cty.Map(cty.String))
		resp.PlannedState = cty.ObjectVal(vals)
	}
	return resp
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
			if !req.Config.IsNull() {
				for k, v := range downloadFrom(req.Config).Headers {
					if d.Headers == nil {
						d.Headers = map[string]string{}
					}
					d.Headers[k] = v
				}
			}
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
			"repo":     {Type: cty.String, Required: true, Description: "Repository URL, without a user name or password. The host needs access to it. Plain http needs a full commit as ref."},
			"dest":     {Type: cty.String, Required: true, Description: "Directory to check it out in."},
			"ref":      {Type: cty.String, Optional: true, Description: "Branch, tag or full commit. Defaults to the remote's default branch."},
			"key_file": {Type: cty.String, Optional: true, Description: "Private key on the host to log in to an ssh repo with, such as a deploy key, absolute. Only that key is offered, and ssh never asks for a password. The repo's server must already be in the host's known_hosts: add a known_hosts step before this one."},
			"depth":    {Type: cty.Number, Optional: true, Description: "Fetch only this many commits of history, 1 or more, for a shallow checkout. Tags aren't fetched then. A full commit as ref needs a server that lets clients fetch a commit by its hash. Changing it doesn't reclone, and removing it fetches the rest of the history. Defaults to the whole history."},
			"commit":   {Type: cty.String, Computed: true, Description: "The commit checked out."},
			"in_sync":  {Type: cty.Bool, Computed: true, Description: "Whether the checkout is at the commit ref points to."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func gitFrom(v cty.Value) fetch.Git {
	g := fetch.Git{Repo: v.GetAttr("repo").AsString(), Dest: v.GetAttr("dest").AsString(), Ref: stringOr(v.GetAttr("ref"), ""), KeyFile: stringOr(v.GetAttr("key_file"), "")}
	if d := v.GetAttr("depth"); !d.IsNull() && d.IsKnown() {
		n, acc := d.AsBigFloat().Int64()
		// A depth of 0 or less, or one that isn't a whole number, is refused
		// rather than read as the whole history.
		if n < 1 || acc != big.Exact {
			n = -1
		}
		g.Depth = int(n)
	}
	return g
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
