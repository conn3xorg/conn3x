// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/zclconf/go-cty/cty"
	ctyjson "github.com/zclconf/go-cty/cty/json"

	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/conn3x/modules/file"
	"github.com/opentofu/opentofu/internal/providers"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

const (
	defaultMode     = "0644"
	onRemoveForget  = "forget"
	onRemoveDelete  = "delete"
	defaultOnRemove = onRemoveForget
)

func fileSchema() providers.Schema {
	return providers.Schema{
		Block: &configschema.Block{
			Description: "A regular file on a host: its content, mode and ownership.",
			Attributes: map[string]*configschema.Attribute{
				"id":        {Type: cty.String, Computed: true},
				"path":      {Type: cty.String, Required: true, Description: "Absolute path of the file on the host."},
				"content":   {Type: cty.String, Required: true, Description: "Exact content of the file."},
				"mode":      {Type: cty.String, Optional: true, Computed: true, Description: "Octal permissions. Defaults to \"0644\"."},
				"owner":     {Type: cty.String, Optional: true, Description: "Owning user. Left as is when unset."},
				"group":     {Type: cty.String, Optional: true, Description: "Owning group. Left as is when unset."},
				"on_remove": {Type: cty.String, Optional: true, Computed: true, Description: "What happens on the host when this resource is removed: \"forget\" (default) leaves the file, \"delete\" removes it."},
				"sha256":    {Type: cty.String, Computed: true, Description: "SHA-256 of the content, hex encoded."},
			},
			BlockTypes: map[string]*configschema.NestedBlock{
				"ssh": connectionBlock(),
			},
		},
	}
}

func validateFile(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() {
		return diags
	}
	if v := cfg.GetAttr("on_remove"); v.IsKnown() && !v.IsNull() {
		if s := v.AsString(); s != onRemoveForget && s != onRemoveDelete {
			diags = diags.Append(attrError("on_remove", fmt.Sprintf("on_remove must be %q or %q, not %q", onRemoveForget, onRemoveDelete, s)))
		}
	}
	path, mode := cfg.GetAttr("path"), cfg.GetAttr("mode")
	if path.IsKnown() && !path.IsNull() {
		d := file.Desired{Path: path.AsString(), Mode: defaultMode}
		if err := d.Validate(); err != nil {
			diags = diags.Append(attrError("path", err.Error()))
		}
	}
	if mode.IsKnown() && !mode.IsNull() {
		d := file.Desired{Path: "/", Mode: mode.AsString()}
		if err := d.Validate(); err != nil {
			diags = diags.Append(attrError("mode", err.Error()))
		}
	}
	return diags
}

func planFile(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	var resp providers.PlanResourceChangeResponse
	if req.ProposedNewState.IsNull() {
		resp.PlannedState = req.ProposedNewState
		return resp
	}
	vals := req.ProposedNewState.AsValueMap()
	if vals["mode"].IsNull() {
		vals["mode"] = cty.StringVal(defaultMode)
	}
	if vals["on_remove"].IsNull() {
		vals["on_remove"] = cty.StringVal(defaultOnRemove)
	}
	if mode := vals["mode"]; mode.IsKnown() {
		vals["mode"] = cty.StringVal(file.NormalizeMode(mode.AsString()))
	}
	if content := vals["content"]; content.IsKnown() {
		vals["sha256"] = cty.StringVal(digest(content.AsString()))
	} else {
		vals["sha256"] = cty.UnknownVal(cty.String)
	}
	host, path := req.ProposedNewState.GetAttr("ssh").GetAttr("host"), vals["path"]
	if host.IsKnown() && path.IsKnown() {
		vals["id"] = cty.StringVal(host.AsString() + ":" + path.AsString())
	} else {
		vals["id"] = cty.UnknownVal(cty.String)
	}
	resp.PlannedState = cty.ObjectVal(vals)

	if !req.PriorState.IsNull() {
		for _, attr := range []string{"path"} {
			if !req.PriorState.GetAttr(attr).RawEquals(vals[attr]) {
				resp.RequiresReplace = append(resp.RequiresReplace, cty.GetAttrPath(attr))
			}
		}
		priorHost := req.PriorState.GetAttr("ssh").GetAttr("host")
		if !priorHost.RawEquals(host) {
			resp.RequiresReplace = append(resp.RequiresReplace, cty.GetAttrPath("ssh").GetAttr("host"))
		}
	}
	return resp
}

func readFile(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	resp := providers.ReadResourceResponse{NewState: req.PriorState}
	if req.PriorState.IsNull() {
		return resp
	}
	client, err := dialConnection(ctx, req.PriorState.GetAttr("ssh"))
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(attrError("ssh", err.Error()))
		return resp
	}
	defer client.Close()

	path := req.PriorState.GetAttr("path").AsString()
	actual, err := file.Read(ctx, client, path)
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("reading %s: %w", path, err))
		return resp
	}
	if !actual.Exists {
		resp.NewState = cty.NullVal(req.PriorState.Type())
		return resp
	}
	resp.NewState = stateFrom(req.PriorState, actual)
	return resp
}

func applyFile(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	var resp providers.ApplyResourceChangeResponse
	if req.PlannedState.IsNull() {
		resp.NewState = req.PlannedState
		if req.PriorState.IsNull() || req.PriorState.GetAttr("on_remove").AsString() != onRemoveDelete {
			return resp
		}
		client, err := dialConnection(ctx, req.PriorState.GetAttr("ssh"))
		if err != nil {
			resp.Diagnostics = resp.Diagnostics.Append(attrError("ssh", err.Error()))
			return resp
		}
		defer client.Close()
		if err := file.Delete(ctx, client, req.PriorState.GetAttr("path").AsString()); err != nil {
			resp.Diagnostics = resp.Diagnostics.Append(err)
		}
		return resp
	}

	planned := req.PlannedState
	client, err := dialConnection(ctx, planned.GetAttr("ssh"))
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(attrError("ssh", err.Error()))
		return resp
	}
	defer client.Close()

	desired := file.Desired{
		Path:    planned.GetAttr("path").AsString(),
		Content: planned.GetAttr("content").AsString(),
		Mode:    planned.GetAttr("mode").AsString(),
		Owner:   stringOr(planned.GetAttr("owner"), ""),
		Group:   stringOr(planned.GetAttr("group"), ""),
	}
	if err := file.Apply(ctx, client, desired); err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("writing %s: %w", desired.Path, err))
		return resp
	}
	actual, err := file.Read(ctx, client, desired.Path)
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("reading back %s: %w", desired.Path, err))
		return resp
	}
	if file.NeedsChange(desired, actual) {
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("%s does not match what was written; something else changed it", desired.Path))
		return resp
	}
	resp.NewState = stateFrom(planned, actual)
	return resp
}

// stateFrom records what is actually on the host. Owner and group are only
// tracked when the configuration manages them.
func stateFrom(base cty.Value, actual file.Actual) cty.Value {
	vals := base.AsValueMap()
	vals["content"] = cty.StringVal(actual.Content)
	vals["sha256"] = cty.StringVal(digest(actual.Content))
	vals["mode"] = cty.StringVal(actual.Mode)
	if !vals["owner"].IsNull() {
		vals["owner"] = cty.StringVal(actual.Owner)
	}
	if !vals["group"].IsNull() {
		vals["group"] = cty.StringVal(actual.Group)
	}
	return cty.ObjectVal(vals)
}

func upgradeFile(req providers.UpgradeResourceStateRequest) providers.UpgradeResourceStateResponse {
	var resp providers.UpgradeResourceStateResponse
	ty := fileSchema().Block.ImpliedType()
	val, err := ctyjson.Unmarshal(req.RawStateJSON, ty)
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(err)
		return resp
	}
	resp.UpgradedState = val
	return resp
}

func digest(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func attrError(attr, msg string) tfdiags.Diagnostic {
	return tfdiags.AttributeValue(tfdiags.Error, "Invalid "+attr, msg, cty.GetAttrPath(attr))
}
