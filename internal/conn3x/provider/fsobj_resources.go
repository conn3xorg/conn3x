// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/conn3x/modules/file"
	"github.com/opentofu/opentofu/internal/conn3x/modules/fsobj"
	"github.com/opentofu/opentofu/internal/providers"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

func directorySchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "A directory, created with its parents.",
		Attributes: map[string]*configschema.Attribute{
			"id":        {Type: cty.String, Computed: true},
			"path":      {Type: cty.String, Required: true, Description: "Absolute path."},
			"mode":      {Type: cty.String, Optional: true, Computed: true, Description: "Octal permissions. Defaults to \"0755\"."},
			"owner":     {Type: cty.String, Optional: true, Description: "Owning user. Left as is when unset."},
			"group":     {Type: cty.String, Optional: true, Description: "Owning group. Left as is when unset."},
			"on_remove": {Type: cty.String, Optional: true, Computed: true, Description: "\"forget\" (default) leaves the directory, \"delete\" removes it when it is empty."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func directoryFrom(v cty.Value) fsobj.Directory {
	return fsobj.Directory{
		Path: v.GetAttr("path").AsString(), Mode: stringOr(v.GetAttr("mode"), "0755"),
		Owner: stringOr(v.GetAttr("owner"), ""), Group: stringOr(v.GetAttr("group"), ""),
	}
}

func validateDirectory(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() || !cfg.GetAttr("path").IsKnown() || !cfg.GetAttr("mode").IsKnown() {
		return diags
	}
	diags = diags.Append(validateOnRemove(cfg))
	if err := directoryFrom(cfg).Validate(); err != nil {
		diags = diags.Append(attrError("path", err.Error()))
	}
	return diags
}

func planDirectory(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	return planPathResource(req, "directory", func(vals map[string]cty.Value) {
		if vals["mode"].IsNull() {
			vals["mode"] = cty.StringVal("0755")
		}
		if m := vals["mode"]; m.IsKnown() {
			vals["mode"] = cty.StringVal(file.NormalizeMode(m.AsString()))
		}
	})
}

func readDirectory(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	return readPathResource(ctx, req, func(ctx context.Context, h *hostConn, prior cty.Value) (cty.Value, error) {
		s, err := fsobj.ReadDirectory(ctx, h, prior.GetAttr("path").AsString())
		if err != nil || !s.Exists {
			return cty.NullVal(prior.Type()), err
		}
		return directoryState(prior, s), nil
	})
}

func applyDirectory(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	return applyPathResource(ctx, req,
		func(ctx context.Context, h *hostConn, planned cty.Value) (cty.Value, error) {
			d := directoryFrom(planned)
			if err := fsobj.ApplyDirectory(ctx, h, d); err != nil {
				return cty.NilVal, fmt.Errorf("directory %s: %w", d.Path, err)
			}
			s, err := fsobj.ReadDirectory(ctx, h, d.Path)
			if err != nil {
				return cty.NilVal, err
			}
			if fsobj.DirectoryNeedsChange(d, s) {
				return cty.NilVal, fmt.Errorf("directory %s does not match the configuration after applying", d.Path)
			}
			return directoryState(planned, s), nil
		},
		func(ctx context.Context, h *hostConn, prior cty.Value) error {
			return fsobj.DeleteDirectory(ctx, h, prior.GetAttr("path").AsString())
		})
}

func directoryState(base cty.Value, s fsobj.DirectoryState) cty.Value {
	vals := base.AsValueMap()
	vals["mode"] = cty.StringVal(s.Mode)
	if !vals["owner"].IsNull() {
		vals["owner"] = cty.StringVal(s.Owner)
	}
	if !vals["group"].IsNull() {
		vals["group"] = cty.StringVal(s.Group)
	}
	return cty.ObjectVal(vals)
}

func linkSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "A symbolic link.",
		Attributes: map[string]*configschema.Attribute{
			"id":        {Type: cty.String, Computed: true},
			"path":      {Type: cty.String, Required: true, Description: "Absolute path of the link."},
			"target":    {Type: cty.String, Required: true, Description: "What the link points to, absolute or relative to the link."},
			"on_remove": {Type: cty.String, Optional: true, Computed: true, Description: "\"forget\" (default) leaves the link, \"delete\" removes it."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func linkFrom(v cty.Value) fsobj.Link {
	return fsobj.Link{Path: v.GetAttr("path").AsString(), Target: v.GetAttr("target").AsString()}
}

func validateLink(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() || !cfg.GetAttr("path").IsKnown() || !cfg.GetAttr("target").IsKnown() {
		return diags
	}
	diags = diags.Append(validateOnRemove(cfg))
	if err := linkFrom(cfg).Validate(); err != nil {
		diags = diags.Append(attrError("path", err.Error()))
	}
	return diags
}

func planLink(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	return planPathResource(req, "link", func(map[string]cty.Value) {})
}

func readLink(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	return readPathResource(ctx, req, func(ctx context.Context, h *hostConn, prior cty.Value) (cty.Value, error) {
		s, err := fsobj.ReadLink(ctx, h, prior.GetAttr("path").AsString())
		if err != nil || !s.Exists {
			return cty.NullVal(prior.Type()), err
		}
		vals := prior.AsValueMap()
		vals["target"] = cty.StringVal(s.Target)
		return cty.ObjectVal(vals), nil
	})
}

func applyLink(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	return applyPathResource(ctx, req,
		func(ctx context.Context, h *hostConn, planned cty.Value) (cty.Value, error) {
			l := linkFrom(planned)
			if err := fsobj.ApplyLink(ctx, h, l); err != nil {
				return cty.NilVal, fmt.Errorf("link %s: %w", l.Path, err)
			}
			return planned, nil
		},
		func(ctx context.Context, h *hostConn, prior cty.Value) error {
			return fsobj.DeleteLink(ctx, h, prior.GetAttr("path").AsString())
		})
}

// planPathResource is the plan logic shared by resources keyed by a path:
// defaults, id, and replacing when the path or host changes.
func planPathResource(req providers.PlanResourceChangeRequest, kind string, defaults func(map[string]cty.Value)) providers.PlanResourceChangeResponse {
	var resp providers.PlanResourceChangeResponse
	if req.ProposedNewState.IsNull() {
		resp.PlannedState = req.ProposedNewState
		return resp
	}
	vals := req.ProposedNewState.AsValueMap()
	if vals["on_remove"].IsNull() {
		vals["on_remove"] = cty.StringVal(defaultOnRemove)
	}
	defaults(vals)
	host := req.ProposedNewState.GetAttr("ssh").GetAttr("host")
	path := vals["path"]
	if path.IsKnown() {
		vals["id"] = planID(req, kind, path.AsString())
	} else {
		vals["id"] = cty.UnknownVal(cty.String)
	}
	resp.PlannedState = cty.ObjectVal(vals)
	if !req.PriorState.IsNull() {
		if !req.PriorState.GetAttr("path").RawEquals(path) {
			resp.RequiresReplace = append(resp.RequiresReplace, cty.GetAttrPath("path"))
		}
		if !req.PriorState.GetAttr("ssh").GetAttr("host").RawEquals(host) {
			resp.RequiresReplace = append(resp.RequiresReplace, cty.GetAttrPath("ssh").GetAttr("host"))
		}
	}
	return resp
}

func readPathResource(ctx context.Context, req providers.ReadResourceRequest, read func(context.Context, *hostConn, cty.Value) (cty.Value, error)) providers.ReadResourceResponse {
	resp := providers.ReadResourceResponse{NewState: req.PriorState}
	if req.PriorState.IsNull() {
		return resp
	}
	h, err := dialConnection(ctx, req.PriorState.GetAttr("ssh"))
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(attrError("ssh", err.Error()))
		return resp
	}
	defer h.Close()
	state, err := read(ctx, h, req.PriorState)
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(err)
		return resp
	}
	resp.NewState = state
	return resp
}

func applyPathResource(ctx context.Context, req providers.ApplyResourceChangeRequest,
	apply func(context.Context, *hostConn, cty.Value) (cty.Value, error),
	remove func(context.Context, *hostConn, cty.Value) error) providers.ApplyResourceChangeResponse {
	var resp providers.ApplyResourceChangeResponse
	target := req.PlannedState
	if target.IsNull() {
		resp.NewState = target
		if req.PriorState.IsNull() || !req.PriorState.Type().HasAttribute("on_remove") || req.PriorState.GetAttr("on_remove").AsString() != onRemoveDelete {
			return resp
		}
		target = req.PriorState
	}
	// An update that planned nothing stale only changed how Conn3x reaches
	// the host, so there is nothing to do there.
	if !req.PriorState.IsNull() && !req.PlannedState.IsNull() && req.PlannedState.Type().HasAttribute("in_sync") {
		if s := req.PlannedState.GetAttr("in_sync"); s.IsKnown() && !s.IsNull() && s.True() {
			resp.NewState = req.PlannedState
			return resp
		}
	}
	h, err := dialConnection(ctx, target.GetAttr("ssh"))
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(attrError("ssh", err.Error()))
		return resp
	}
	defer h.Close()
	if req.PlannedState.IsNull() {
		if err := remove(ctx, h, req.PriorState); err != nil {
			resp.Diagnostics = resp.Diagnostics.Append(err)
		}
		return resp
	}
	state, err := apply(ctx, h, req.PlannedState)
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(err)
		return resp
	}
	resp.NewState = state
	return resp
}
