// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"errors"
	"fmt"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/conn3x/modules/edit"
	"github.com/opentofu/opentofu/internal/conn3x/modules/windows"
	"github.com/opentofu/opentofu/internal/providers"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

// windows_line is the line step for a Windows host: the same arguments and
// the same edit, made in Conn3x on the file's text, written back in the
// file's own encoding and line endings through windows_file's write.

func winLineSchema() providers.Schema {
	attrs := map[string]*configschema.Attribute{
		"id":        {Type: cty.String, Computed: true},
		"revision":  revisionAttr(),
		"path":      {Type: cty.String, Required: true, Description: "Full path of the file, such as C:\\App\\app.ini."},
		"create":    {Type: cty.Bool, Optional: true, Description: "Create the file when it's missing, as UTF-8 with \\r\\n line endings. Otherwise a missing file is an error."},
		"on_remove": {Type: cty.String, Optional: true, Computed: true, Description: "\"forget\" (default) leaves the file as it is, \"delete\" takes the line back out."},
		"in_sync":   {Type: cty.Bool, Computed: true, Description: "Whether the file already matched at the last refresh."},
	}
	for name, a := range lineKind.attrs {
		attrs[name] = a
	}
	return providers.Schema{Block: &configschema.Block{
		Description: "A line in a text file on a Windows host that should, or should not, be there. The file keeps its encoding (UTF-8, with or without a byte order mark, or UTF-16 LE) and its line endings.",
		Attributes:  attrs,
		BlockTypes:  map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func validateWinLine(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() || !settled(cfg) {
		return diags
	}
	diags = diags.Append(validateOnRemove(cfg))
	diags = diags.Append(validateWinPathAttr(cfg))
	if err := lineKind.check(cfg); err != nil {
		diags = diags.Append(attrError("line", err.Error()))
	}
	return diags
}

func planWinLine(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	return planSynced(req, "windows_line", []string{"path"}, []string{"line", "regexp", "insert_after", "insert_before", "state", "backrefs", "create"})
}

func readWinLine(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	resp := providers.ReadResourceResponse{NewState: req.PriorState}
	if req.PriorState.IsNull() {
		return resp
	}
	fail := func(err error) providers.ReadResourceResponse {
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("windows_line: %w", err))
		return resp
	}
	h, err := winHost(ctx, req.PriorState.GetAttr("ssh"))
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(attrError("ssh", err.Error()))
		return resp
	}
	path, err := winPath(req.PriorState)
	if err != nil {
		return fail(err)
	}
	f, err := windows.ReadTextFile(ctx, h.raw(), path)
	if err != nil {
		return fail(err)
	}
	if !f.Exists {
		// A line that should be absent is, in a file that isn't there.
		resp.NewState = withSync(req.PriorState, lineFrom(req.PriorState).State == edit.Absent)
		return resp
	}
	edited, err := lineKind.edit(req.PriorState)(f.Text)
	if err != nil {
		return fail(err)
	}
	resp.NewState = withSync(req.PriorState, edited == f.Text)
	return resp
}

func applyWinLine(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	var resp providers.ApplyResourceChangeResponse
	fail := func(err error) providers.ApplyResourceChangeResponse {
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("windows_line: %w", err))
		return resp
	}
	v, fn := req.PlannedState, (func(string) (string, error))(nil)
	if req.PlannedState.IsNull() {
		resp.NewState = req.PlannedState
		if req.PriorState.IsNull() || req.PriorState.GetAttr("on_remove").AsString() != onRemoveDelete {
			return resp
		}
		v, fn = req.PriorState, lineKind.remove(req.PriorState)
	} else {
		if err := lineKind.check(v); err != nil {
			return fail(err)
		}
		fn = lineKind.edit(v)
	}
	h, err := winHost(ctx, v.GetAttr("ssh"))
	if err != nil {
		return fail(err)
	}
	path, err := winPath(v)
	if err != nil {
		return fail(err)
	}
	f, err := windows.ReadTextFile(ctx, h.raw(), path)
	if err != nil {
		return fail(err)
	}
	removing := req.PlannedState.IsNull()
	if !f.Exists {
		switch {
		case removing || lineFrom(v).State == edit.Absent:
			// Nothing to take out of a file that isn't there.
			if !removing {
				resp.NewState = withSync(v, true)
			}
			return resp
		case !known(v.GetAttr("create")) || v.GetAttr("create").False():
			return fail(fmt.Errorf("%s doesn't exist; set create = true to make it", path))
		}
		f = windows.NewTextFile()
	}
	edited, err := fn(f.Text)
	if err != nil {
		return fail(err)
	}
	if edited != f.Text || !f.Exists {
		f.Text = edited
		b := f.Encode()
		if len(b) > windows.MaxContent {
			return fail(errors.New("the edited file would be larger than 2 MiB"))
		}
		if err := windows.ApplyFile(ctx, h.raw(), path, b, nil, nil); err != nil {
			return fail(err)
		}
	}
	if !removing {
		resp.NewState = withSync(v, true)
	}
	return resp
}
