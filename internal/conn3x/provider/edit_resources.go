// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/conn3x/modules/edit"
	"github.com/opentofu/opentofu/internal/conn3x/modules/file"
	"github.com/opentofu/opentofu/internal/providers"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

// An edit resource changes part of a file. edits builds the edit from
// configuration; remove builds the edit that undoes it for on_remove.
type editKind struct {
	name   string
	attrs  map[string]*configschema.Attribute
	edit   func(cty.Value) func(string) (string, error)
	remove func(cty.Value) func(string) (string, error)
	check  func(cty.Value) error
}

var lineKind = editKind{
	name: "line",
	attrs: map[string]*configschema.Attribute{
		"line":          {Type: cty.String, Optional: true, Description: "The line. Required unless state is \"absent\" with a regexp."},
		"regexp":        {Type: cty.String, Optional: true, Description: "Replace the last line matching this; with state \"absent\", remove every match."},
		"insert_after":  {Type: cty.String, Optional: true, Description: "When adding, insert after the last line matching this regexp, or \"EOF\" (default)."},
		"insert_before": {Type: cty.String, Optional: true, Description: "When adding, insert before the first line matching this regexp, or \"BOF\"."},
		"state":         {Type: cty.String, Optional: true, Description: "\"present\" (default) or \"absent\"."},
	},
	edit: func(v cty.Value) func(string) (string, error) {
		l := lineFrom(v)
		return func(s string) (string, error) { return edit.ApplyLine(s, l) }
	},
	remove: func(v cty.Value) func(string) (string, error) {
		l := lineFrom(v)
		l.State, l.InsertAfter, l.InsertBefore = edit.Absent, "", ""
		if l.Regexp == "" || l.Line != "" {
			l.Regexp = ""
		}
		return func(s string) (string, error) { return edit.ApplyLine(s, l) }
	},
	check: func(v cty.Value) error { return lineFrom(v).Validate() },
}

func lineFrom(v cty.Value) edit.Line {
	return edit.Line{
		Line: stringOr(v.GetAttr("line"), ""), Regexp: stringOr(v.GetAttr("regexp"), ""),
		InsertAfter: stringOr(v.GetAttr("insert_after"), ""), InsertBefore: stringOr(v.GetAttr("insert_before"), ""),
		State: edit.State(stringOr(v.GetAttr("state"), "")),
	}
}

var blockKind = editKind{
	name: "block",
	attrs: map[string]*configschema.Attribute{
		"content":       {Type: cty.String, Optional: true, Description: "Lines of the block."},
		"marker":        {Type: cty.String, Optional: true, Description: "Marker line with {mark}, which becomes BEGIN and END. Defaults to \"# {mark} CONN3X MANAGED BLOCK\"."},
		"insert_after":  {Type: cty.String, Optional: true, Description: "Where a new block goes: after the last match of this regexp, or \"EOF\" (default)."},
		"insert_before": {Type: cty.String, Optional: true, Description: "Where a new block goes: before the first match of this regexp, or \"BOF\"."},
		"state":         {Type: cty.String, Optional: true, Description: "\"present\" (default) or \"absent\"."},
	},
	edit: func(v cty.Value) func(string) (string, error) {
		b := blockFrom(v)
		return func(s string) (string, error) { return edit.ApplyBlock(s, b) }
	},
	remove: func(v cty.Value) func(string) (string, error) {
		b := blockFrom(v)
		b.State = edit.Absent
		return func(s string) (string, error) { return edit.ApplyBlock(s, b) }
	},
	check: func(v cty.Value) error { return blockFrom(v).Validate() },
}

func blockFrom(v cty.Value) edit.Block {
	return edit.Block{
		Content: stringOr(v.GetAttr("content"), ""), Marker: stringOr(v.GetAttr("marker"), ""),
		InsertAfter: stringOr(v.GetAttr("insert_after"), ""), InsertBefore: stringOr(v.GetAttr("insert_before"), ""),
		State: edit.State(stringOr(v.GetAttr("state"), "")),
	}
}

func (k editKind) schema() providers.Schema {
	attrs := map[string]*configschema.Attribute{
		"id":        {Type: cty.String, Computed: true},
		"revision":  revisionAttr(),
		"path":      {Type: cty.String, Required: true, Description: "Absolute path of the file."},
		"create":    {Type: cty.Bool, Optional: true, Description: "Create the file when it is missing. Otherwise a missing file is an error."},
		"on_remove": {Type: cty.String, Optional: true, Computed: true, Description: "\"forget\" (default) leaves the file as it is, \"delete\" takes the edit back out."},
		"in_sync":   {Type: cty.Bool, Computed: true, Description: "Whether the file already matches."},
	}
	for name, a := range k.attrs {
		attrs[name] = a
	}
	return providers.Schema{Block: &configschema.Block{
		Description: "Part of a text file: a " + k.name + " that should, or should not, be there.",
		Attributes:  attrs,
		BlockTypes:  map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func (k editKind) validate(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() || !cfg.IsWhollyKnown() {
		return diags
	}
	diags = diags.Append(validateOnRemove(cfg))
	if err := (file.Desired{Path: cfg.GetAttr("path").AsString(), Mode: "0644"}).Validate(); err != nil {
		diags = diags.Append(attrError("path", err.Error()))
	}
	if err := k.check(cfg); err != nil {
		diags = diags.Append(attrError(k.name, err.Error()))
	}
	return diags
}

func (k editKind) plan(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	resp := planPathResource(req, k.name, func(map[string]cty.Value) {})
	if resp.PlannedState.IsNull() {
		return resp
	}
	vals := resp.PlannedState.AsValueMap()
	changed := req.PriorState.IsNull()
	if !changed {
		for name := range k.attrs {
			if !req.PriorState.GetAttr(name).RawEquals(vals[name]) {
				changed = true
			}
		}
		if s := req.PriorState.GetAttr("in_sync"); !known(s) || s.False() {
			changed = true
		}
	}
	if changed {
		vals["in_sync"] = cty.UnknownVal(cty.Bool)
	} else {
		vals["in_sync"] = cty.True
	}
	resp.PlannedState = cty.ObjectVal(vals)
	return resp
}

func (k editKind) read(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	return readPathResource(ctx, req, func(ctx context.Context, h *hostConn, prior cty.Value) (cty.Value, error) {
		vals := prior.AsValueMap()
		actual, err := file.Read(ctx, h, prior.GetAttr("path").AsString())
		if err != nil {
			return cty.NilVal, err
		}
		inSync := false
		if actual.Exists {
			edited, err := k.edit(prior)(actual.Content)
			if err != nil {
				return cty.NilVal, err
			}
			inSync = edited == actual.Content
		}
		vals["in_sync"] = cty.BoolVal(inSync)
		return cty.ObjectVal(vals), nil
	})
}

func (k editKind) apply(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	return applyPathResource(ctx, req,
		func(ctx context.Context, h *hostConn, planned cty.Value) (cty.Value, error) {
			create := planned.GetAttr("create")
			if err := editFile(ctx, h, planned.GetAttr("path").AsString(), known(create) && create.True(), k.edit(planned)); err != nil {
				return cty.NilVal, err
			}
			vals := planned.AsValueMap()
			vals["in_sync"] = cty.True
			return cty.ObjectVal(vals), nil
		},
		func(ctx context.Context, h *hostConn, prior cty.Value) error {
			return editFile(ctx, h, prior.GetAttr("path").AsString(), false, k.remove(prior))
		})
}

// editFile reads a file, applies fn and writes it back only if it changed,
// keeping its mode and ownership. Edits to one file on a host take turns,
// so one doesn't write over another it read the file before.
func editFile(ctx context.Context, h *hostConn, path string, create bool, fn func(string) (string, error)) error {
	defer lockHost(h, "edit\x00"+path)()
	actual, err := file.Read(ctx, h, path)
	if err != nil {
		return err
	}
	if !actual.Exists {
		if !create {
			return fmt.Errorf("%s does not exist; set create = true to create it", path)
		}
		actual = file.Actual{Mode: "0644"}
	}
	edited, err := fn(actual.Content)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if actual.Exists && edited == actual.Content {
		return nil
	}
	return file.Apply(ctx, h, file.Desired{Path: path, Content: edited, Mode: actual.Mode, Owner: actual.Owner, Group: actual.Group})
}
