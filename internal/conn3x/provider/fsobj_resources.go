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
			"id":            {Type: cty.String, Computed: true},
			"revision":      revisionAttr(),
			"path":          {Type: cty.String, Required: true, Description: "Absolute path."},
			"mode":          {Type: cty.String, Optional: true, Computed: true, Description: "Octal permissions. Defaults to \"0755\". With recurse, a symbolic mode such as \"u=rwX,g=rX,o=\", for the directory and everything under it."},
			"owner":         {Type: cty.String, Optional: true, Description: "Owning user. Left as is when unset."},
			"group":         {Type: cty.String, Optional: true, Description: "Owning group. Left as is when unset."},
			"recurse":       {Type: cty.Bool, Optional: true, Description: "Sets owner, group and a symbolic mode on everything under the directory too, without following links or crossing into another filesystem."},
			"changes_under": {Type: cty.Number, Computed: true, Description: "With recurse, how many paths under the directory had another owner, group or mode at the last refresh. Apply changes them."},
			"on_remove":     {Type: cty.String, Optional: true, Computed: true, Description: "\"forget\" (default) leaves the directory, \"delete\" removes it when it is empty."},
			"state":         {Type: cty.String, Optional: true, Description: "\"present\" (default) or \"absent\", which removes the directory when it is empty and keeps it gone."},
			"in_sync":       {Type: cty.Bool, Computed: true, Description: "With state \"absent\", whether the directory is already gone. Null otherwise."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func directoryFrom(v cty.Value) fsobj.Directory {
	return fsobj.Directory{
		Path: v.GetAttr("path").AsString(), Mode: stringOr(v.GetAttr("mode"), "0755"),
		Owner: stringOr(v.GetAttr("owner"), ""), Group: stringOr(v.GetAttr("group"), ""),
		Recurse: isTrue(v.GetAttr("recurse")),
	}
}

func isTrue(v cty.Value) bool { return v.IsKnown() && !v.IsNull() && v.True() }

func validateDirectory(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() || !cfg.GetAttr("path").IsKnown() || !cfg.GetAttr("mode").IsKnown() {
		return diags
	}
	diags = diags.Append(validateOnRemove(cfg))
	diags = diags.Append(validateState(cfg, "mode", "owner", "group", "recurse"))
	if m := cfg.GetAttr("mode"); isTrue(cfg.GetAttr("recurse")) && !m.IsNull() && !fsobj.IsSymbolic(m.AsString()) {
		// A numeric mode means one thing for files and another for
		// directories, so it can't be given to a whole tree.
		diags = diags.Append(attrError("mode", fmt.Sprintf("with recurse, mode must be symbolic, such as \"u=rwX,g=rX,o=\", not %q: X gives directories their execute bit without making every file executable", m.AsString())))
		return diags
	}
	if err := directoryFrom(cfg).Validate(); err != nil {
		diags = diags.Append(attrError("path", err.Error()))
	}
	return diags
}

func planDirectory(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	return planPathResource(req, "directory", func(vals map[string]cty.Value) {
		switch {
		case !vals["state"].IsKnown():
			// Whether the directory should exist isn't known yet, so
			// neither is anything read from it.
			if req.Config.GetAttr("mode").IsNull() {
				vals["mode"] = cty.UnknownVal(cty.String)
			}
			vals["in_sync"], vals["changes_under"] = cty.UnknownVal(cty.Bool), cty.UnknownVal(cty.Number)
			return
		case isAbsent(req.ProposedNewState):
			vals["mode"], vals["in_sync"], vals["changes_under"] = cty.NullVal(cty.String), absentInSync(req), cty.NullVal(cty.Number)
			return
		}
		vals["in_sync"] = cty.NullVal(cty.Bool)
		if req.Config.GetAttr("mode").IsNull() { // the proposal carries the refreshed mode
			vals["mode"] = cty.StringVal("0755")
		}
		if m := vals["mode"]; m.IsKnown() && !fsobj.IsSymbolic(m.AsString()) {
			vals["mode"] = cty.StringVal(file.NormalizeMode(m.AsString()))
		}
		vals["changes_under"] = cty.NullVal(cty.Number)
		if r := vals["recurse"]; !r.IsKnown() {
			vals["changes_under"] = cty.UnknownVal(cty.Number)
		} else if isTrue(r) {
			vals["changes_under"] = cty.Zero
		}
	})
}

func readDirectory(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	var tree fsobj.Tree
	resp := readPathResource(ctx, req, func(ctx context.Context, h *hostConn, prior cty.Value) (cty.Value, error) {
		s, err := fsobj.ReadDirectory(ctx, h, prior.GetAttr("path").AsString())
		if err == nil && isAbsent(prior) {
			vals := prior.AsValueMap()
			vals["in_sync"] = cty.BoolVal(!s.Exists)
			return cty.ObjectVal(vals), nil
		}
		if err != nil || !s.Exists {
			return cty.NullVal(prior.Type()), err
		}
		state := directoryState(prior, s)
		if d := directoryFrom(prior); d.Recurse {
			if tree, err = fsobj.ReadTree(ctx, h, d, treeOwner(d, s)); err != nil {
				return cty.NilVal, err
			}
			vals := state.AsValueMap()
			vals["changes_under"] = cty.NumberIntVal(int64(tree.Changes))
			state = cty.ObjectVal(vals)
		}
		return state, nil
	})
	if (tree.Changes > 0 || tree.Skipped > 0) && !resp.Diagnostics.HasErrors() {
		p := req.PriorState.GetAttr("path").AsString()
		msg := fmt.Sprintf("%d path(s) under %s have another owner, group or mode, which apply changes", tree.Changes, p)
		if tree.Skipped > 0 {
			msg += fmt.Sprintf("; %d file(s) with another hard link elsewhere are left as they are, since the other link could be anywhere", tree.Skipped)
		}
		resp.Diagnostics = resp.Diagnostics.Append(tfdiags.SimpleWarning(msg))
	}
	return resp
}

// treeOwner is who a recursive directory's tree ends up belonging to.
func treeOwner(d fsobj.Directory, s fsobj.DirectoryState) string {
	if d.Owner != "" {
		return d.Owner
	}
	return s.Owner
}

func applyDirectory(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	return applyPathResource(ctx, req,
		func(ctx context.Context, h *hostConn, planned cty.Value) (cty.Value, error) {
			if isAbsent(planned) {
				return removeDirectory(ctx, h, planned)
			}
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
			if !d.Recurse {
				return directoryState(planned, s), nil
			}
			if err := fsobj.ApplyTree(ctx, h, d); err != nil {
				return cty.NilVal, fmt.Errorf("directory %s: %w", d.Path, err)
			}
			tree, err := fsobj.ReadTree(ctx, h, d, treeOwner(d, s))
			if err != nil {
				return cty.NilVal, err
			}
			if tree.Changes > 0 {
				return cty.NilVal, fmt.Errorf("directory %s: %d path(s) under it still have another owner, group or mode after applying", d.Path, tree.Changes)
			}
			return directoryState(planned, s), nil
		},
		func(ctx context.Context, h *hostConn, prior cty.Value) error {
			return fsobj.DeleteDirectory(ctx, h, prior.GetAttr("path").AsString())
		})
}

// removeDirectory removes the directory for state = "absent". ReadDirectory
// refuses anything else at the path, and DeleteDirectory one with files in it.
func removeDirectory(ctx context.Context, h *hostConn, planned cty.Value) (cty.Value, error) {
	p := planned.GetAttr("path").AsString()
	s, err := fsobj.ReadDirectory(ctx, h, p)
	if err == nil && s.Exists {
		err = fsobj.DeleteDirectory(ctx, h, p)
	}
	if err != nil {
		return cty.NilVal, fmt.Errorf("removing %s: %w", p, err)
	}
	vals := planned.AsValueMap()
	vals["in_sync"] = cty.True
	return cty.ObjectVal(vals), nil
}

func directoryState(base cty.Value, s fsobj.DirectoryState) cty.Value {
	vals := base.AsValueMap()
	// A symbolic mode stays in state while the directory's mode is what it
	// makes, so it isn't planned as a change every time.
	if m := vals["mode"]; !m.IsKnown() || m.IsNull() || !fsobj.IsSymbolic(m.AsString()) || directoryFrom(base).WantMode(s.Mode, true) != s.Mode {
		vals["mode"] = cty.StringVal(s.Mode)
	}
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
			"revision":  revisionAttr(),
			"path":      {Type: cty.String, Required: true, Description: "Absolute path of the link."},
			"target":    {Type: cty.String, Optional: true, Description: "What the link points to, absolute or relative to the link. Required unless state is \"absent\"."},
			"on_remove": {Type: cty.String, Optional: true, Computed: true, Description: "\"forget\" (default) leaves the link, \"delete\" removes it."},
			"state":     {Type: cty.String, Optional: true, Description: "\"present\" (default) or \"absent\", which removes the link and keeps it gone."},
			"in_sync":   {Type: cty.Bool, Computed: true, Description: "With state \"absent\", whether the link is already gone. Null otherwise."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func linkFrom(v cty.Value) fsobj.Link {
	return fsobj.Link{Path: v.GetAttr("path").AsString(), Target: stringOr(v.GetAttr("target"), "")}
}

func validateLink(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() || !cfg.GetAttr("path").IsKnown() || !cfg.GetAttr("target").IsKnown() {
		return diags
	}
	diags = diags.Append(validateOnRemove(cfg))
	diags = diags.Append(validateState(cfg, "target"))
	l := linkFrom(cfg)
	switch {
	case !cfg.GetAttr("state").IsKnown() || isAbsent(cfg):
		// Without a target, only the path is left to check.
		if err := (file.Desired{Path: l.Path, Mode: defaultMode}).Validate(); err != nil {
			diags = diags.Append(attrError("path", err.Error()))
		}
	case cfg.GetAttr("target").IsNull():
		diags = diags.Append(attrError("target", fmt.Sprintf("target is required unless state is %q", stateAbsent)))
	default:
		if err := l.Validate(); err != nil {
			diags = diags.Append(attrError("path", err.Error()))
		}
	}
	return diags
}

func planLink(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	return planPathResource(req, "link", func(vals map[string]cty.Value) {
		switch {
		case !vals["state"].IsKnown():
			vals["in_sync"] = cty.UnknownVal(cty.Bool)
		case isAbsent(req.ProposedNewState):
			vals["in_sync"] = absentInSync(req)
		default:
			vals["in_sync"] = cty.NullVal(cty.Bool)
		}
	})
}

func readLink(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	return readPathResource(ctx, req, func(ctx context.Context, h *hostConn, prior cty.Value) (cty.Value, error) {
		s, err := fsobj.ReadLink(ctx, h, prior.GetAttr("path").AsString())
		if err == nil && isAbsent(prior) {
			vals := prior.AsValueMap()
			vals["in_sync"] = cty.BoolVal(!s.Exists)
			return cty.ObjectVal(vals), nil
		}
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
			if isAbsent(planned) {
				return removeLink(ctx, h, planned)
			}
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

// removeLink removes the link for state = "absent". DeleteLink refuses
// anything at the path that isn't a link, and removes only the link, never
// what it points to.
func removeLink(ctx context.Context, h *hostConn, planned cty.Value) (cty.Value, error) {
	p := planned.GetAttr("path").AsString()
	if err := fsobj.DeleteLink(ctx, h, p); err != nil {
		return cty.NilVal, fmt.Errorf("removing %s: %w", p, err)
	}
	vals := planned.AsValueMap()
	vals["in_sync"] = cty.True
	return cty.ObjectVal(vals), nil
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
	h, err := dialForApply(ctx, target.GetAttr("ssh"))
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(attrError("ssh", err.Error()))
		return resp
	}
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
