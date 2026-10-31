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
	statePresent    = "present"
	stateAbsent     = "absent"
)

func fileSchema() providers.Schema {
	return providers.Schema{
		Block: &configschema.Block{
			Description: "A regular file on a host: its content, mode and ownership.",
			Attributes: map[string]*configschema.Attribute{
				"id":       {Type: cty.String, Computed: true},
				"revision": revisionAttr(),
				"path":     {Type: cty.String, Required: true, Description: "Absolute path of the file on the host."},
				"content":  {Type: cty.String, Optional: true, Description: "Exact content of the file. Set this or content_wo, unless state is \"absent\"."},
				"content_wo": {
					Type: cty.String, Optional: true, WriteOnly: true, Sensitive: true,
					Description: "Exact content of the file, kept out of state: state records only content_hmac. Use it for secrets. Set this or content, unless state is \"absent\".",
				},
				"content_hmac": {Type: cty.String, Computed: true, Description: "HMAC-SHA256 of content_wo, keyed by CONN3X_HMAC_KEY or ~/.config/conn3x/hmac.key. Null when content is used."},
				"mode":         {Type: cty.String, Optional: true, Computed: true, Description: "Octal permissions. Defaults to \"0644\", or \"0600\" with content_wo."},
				"owner":        {Type: cty.String, Optional: true, Description: "Owning user. Left as is when unset."},
				"group":        {Type: cty.String, Optional: true, Description: "Owning group. Left as is when unset."},
				"on_remove":    {Type: cty.String, Optional: true, Computed: true, Description: "What happens on the host when this resource is removed: \"forget\" (default) leaves the file, \"delete\" removes it."},
				"sha256":       {Type: cty.String, Computed: true, Description: "SHA-256 of the content, hex encoded."},
				"state":        {Type: cty.String, Optional: true, Description: "\"present\" (default) or \"absent\", which removes the file and keeps it gone."},
				"in_sync":      {Type: cty.Bool, Computed: true, Description: "With state \"absent\", whether the file is already gone. Null otherwise."},
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
	diags = diags.Append(validateOnRemove(cfg))
	diags = diags.Append(validateState(cfg, "content", "content_wo", "mode", "owner", "group"))
	if state := cfg.GetAttr("state"); state.IsKnown() && (state.IsNull() || state.AsString() == statePresent) &&
		cfg.GetAttr("content").IsNull() == cfg.GetAttr("content_wo").IsNull() {
		diags = diags.Append(attrError("content", "set exactly one of content and content_wo"))
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
	if vals["on_remove"].IsNull() {
		vals["on_remove"] = cty.StringVal(defaultOnRemove)
	}
	if !vals["state"].IsKnown() {
		// Whether the file should exist isn't known yet, so neither is
		// anything read from it.
		if req.Config.GetAttr("mode").IsNull() {
			vals["mode"] = cty.UnknownVal(cty.String)
		}
		vals["content_wo"] = cty.NullVal(cty.String)
		vals["sha256"], vals["content_hmac"], vals["in_sync"] = cty.UnknownVal(cty.String), cty.UnknownVal(cty.String), cty.UnknownVal(cty.Bool)
		return finishFilePlan(req, resp, vals)
	}
	if isAbsent(req.ProposedNewState) {
		return planAbsentFile(req, resp, vals)
	}
	vals["in_sync"] = cty.NullVal(cty.Bool)
	// Check the config, not the proposal: mode is computed, so the proposal
	// carries the refreshed mode and the default would never come back.
	if req.Config.GetAttr("mode").IsNull() {
		vals["mode"] = cty.StringVal(defaultMode)
		if !req.Config.GetAttr("content_wo").IsNull() {
			vals["mode"] = cty.StringVal("0600")
		}
	}
	if mode := vals["mode"]; mode.IsKnown() {
		vals["mode"] = cty.StringVal(file.NormalizeMode(mode.AsString()))
	}
	if wo := req.Config.GetAttr("content_wo"); !wo.IsNull() {
		// Write-only: the content stays out of the plan and state.
		vals["content"], vals["content_wo"], vals["sha256"] = cty.NullVal(cty.String), cty.NullVal(cty.String), cty.NullVal(cty.String)
		vals["content_hmac"] = cty.UnknownVal(cty.String)
		key, err := writeKey(req.PriorState)
		if err != nil {
			resp.Diagnostics = resp.Diagnostics.Append(attrError("content_wo", err.Error()))
			return resp
		}
		if err := hmacKeyPermissionWarning(); err != nil {
			resp.Diagnostics = resp.Diagnostics.Append(tfdiags.SimpleWarning(err.Error()))
		}
		if path := vals["path"]; wo.IsKnown() && path.IsKnown() {
			vals["content_hmac"] = cty.StringVal(contentHMAC(key, path.AsString(), wo.AsString()))
		}
	} else {
		vals["content_hmac"] = cty.NullVal(cty.String)
		if content := vals["content"]; content.IsKnown() {
			vals["sha256"] = cty.StringVal(digest(content.AsString()))
		} else {
			vals["sha256"] = cty.UnknownVal(cty.String)
		}
	}
	return finishFilePlan(req, resp, vals)
}

// planAbsentFile plans a file that must not exist. Nothing about its
// content is tracked; in_sync says whether it is already gone.
func planAbsentFile(req providers.PlanResourceChangeRequest, resp providers.PlanResourceChangeResponse, vals map[string]cty.Value) providers.PlanResourceChangeResponse {
	for _, attr := range []string{"content", "content_wo", "content_hmac", "sha256", "mode"} {
		vals[attr] = cty.NullVal(cty.String)
	}
	vals["in_sync"] = absentInSync(req)
	return finishFilePlan(req, resp, vals)
}

// finishFilePlan sets the id and replaces the file when its path or host
// changes.
func finishFilePlan(req providers.PlanResourceChangeRequest, resp providers.PlanResourceChangeResponse, vals map[string]cty.Value) providers.PlanResourceChangeResponse {
	host := req.ProposedNewState.GetAttr("ssh").GetAttr("host")
	if path := vals["path"]; path.IsKnown() {
		vals["id"] = planID(req, path.AsString())
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

// isAbsent reports whether v asks for its path to be gone.
func isAbsent(v cty.Value) bool {
	s := v.GetAttr("state")
	return s.IsKnown() && !s.IsNull() && s.AsString() == stateAbsent
}

// absentInSync plans in_sync for a path that must not exist: true when the
// last refresh found it already gone, unknown when apply has work to do.
func absentInSync(req providers.PlanResourceChangeRequest) cty.Value {
	if req.PriorState.IsNull() || !isAbsent(req.PriorState) {
		return cty.UnknownVal(cty.Bool)
	}
	if s := req.PriorState.GetAttr("in_sync"); !known(s) || s.False() {
		return cty.UnknownVal(cty.Bool)
	}
	return cty.True
}

// validateState checks that state is "present" or "absent", and that none
// of attrs is set alongside "absent".
func validateState(cfg cty.Value, attrs ...string) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	switch state := cfg.GetAttr("state"); {
	case !state.IsKnown() || state.IsNull():
	case state.AsString() == stateAbsent:
		for _, attr := range attrs {
			if !cfg.GetAttr(attr).IsNull() {
				diags = diags.Append(attrError(attr, fmt.Sprintf("%s can't be set with state = %q", attr, stateAbsent)))
			}
		}
	case state.AsString() != statePresent:
		diags = diags.Append(attrError("state", fmt.Sprintf("state must be %q or %q, not %q", statePresent, stateAbsent, state.AsString())))
	}
	return diags
}

func readFile(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	resp := providers.ReadResourceResponse{NewState: req.PriorState}
	if req.PriorState.IsNull() {
		return resp
	}
	if !req.PriorState.GetAttr("content_hmac").IsNull() {
		if err := hmacKeyPermissionWarning(); err != nil {
			resp.Diagnostics = resp.Diagnostics.Append(tfdiags.SimpleWarning(err.Error()))
		}
	}
	client, err := dialConnection(ctx, req.PriorState.GetAttr("ssh"))
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(attrError("ssh", err.Error()))
		return resp
	}

	path := req.PriorState.GetAttr("path").AsString()
	if isAbsent(req.PriorState) {
		exists, err := file.Exists(ctx, client, path)
		if err != nil {
			resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("reading %s: %w", path, err))
			return resp
		}
		vals := req.PriorState.AsValueMap()
		vals["in_sync"] = cty.BoolVal(!exists)
		resp.NewState = cty.ObjectVal(vals)
		return resp
	}
	actual, err := file.Read(ctx, client, path)
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("reading %s: %w", path, err))
		return resp
	}
	if !actual.Exists {
		resp.NewState = cty.NullVal(req.PriorState.Type())
		return resp
	}
	key, err := woKey(req.PriorState)
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(attrError("content_wo", err.Error()))
		return resp
	}
	resp.NewState = stateFrom(req.PriorState, actual, key)
	return resp
}

func applyFile(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	var resp providers.ApplyResourceChangeResponse
	if req.PlannedState.IsNull() {
		resp.NewState = req.PlannedState
		if req.PriorState.IsNull() || req.PriorState.GetAttr("on_remove").AsString() != onRemoveDelete {
			return resp
		}
		client, err := dialForApply(ctx, req.PriorState.GetAttr("ssh"))
		if err != nil {
			resp.Diagnostics = resp.Diagnostics.Append(attrError("ssh", err.Error()))
			return resp
		}
		if err := file.Delete(ctx, client, req.PriorState.GetAttr("path").AsString()); err != nil {
			resp.Diagnostics = resp.Diagnostics.Append(err)
		}
		return resp
	}

	planned := req.PlannedState
	client, err := dialForApply(ctx, planned.GetAttr("ssh"))
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(attrError("ssh", err.Error()))
		return resp
	}

	if isAbsent(planned) {
		path := planned.GetAttr("path").AsString()
		// Exists refuses a directory or anything else that isn't a file.
		exists, err := file.Exists(ctx, client, path)
		if err == nil && exists {
			err = file.Delete(ctx, client, path)
		}
		if err != nil {
			resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("removing %s: %w", path, err))
			return resp
		}
		vals := planned.AsValueMap()
		vals["in_sync"] = cty.True
		resp.NewState = cty.ObjectVal(vals)
		return resp
	}

	content := planned.GetAttr("content")
	var key []byte
	if wo := req.Config.GetAttr("content_wo"); !wo.IsNull() {
		content = wo
		if key, err = writeKey(req.PriorState); err == nil {
			// A saved plan applied elsewhere must use the key it was made with.
			err = checkHMACKey(planned.GetAttr("content_hmac").AsString(), key)
		}
		if err != nil {
			resp.Diagnostics = resp.Diagnostics.Append(attrError("content_wo", err.Error()))
			return resp
		}
	}
	desired := file.Desired{
		Path:    planned.GetAttr("path").AsString(),
		Content: content.AsString(),
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
	resp.NewState = stateFrom(planned, actual, key)
	return resp
}

// stateFrom records what is actually on the host. Owner and group are only
// tracked when the configuration manages them. With a key, the content is
// write-only and state gets its HMAC instead.
func stateFrom(base cty.Value, actual file.Actual, key []byte) cty.Value {
	vals := base.AsValueMap()
	if key != nil {
		vals["content"], vals["sha256"] = cty.NullVal(cty.String), cty.NullVal(cty.String)
		vals["content_hmac"] = cty.StringVal(contentHMAC(key, vals["path"].AsString(), actual.Content))
	} else {
		vals["content"] = cty.StringVal(actual.Content)
		vals["sha256"] = cty.StringVal(digest(actual.Content))
	}
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

func validateOnRemove(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if v := cfg.GetAttr("on_remove"); v.IsKnown() && !v.IsNull() {
		if s := v.AsString(); s != onRemoveForget && s != onRemoveDelete {
			diags = diags.Append(attrError("on_remove", fmt.Sprintf("on_remove must be %q or %q, not %q", onRemoveForget, onRemoveDelete, s)))
		}
	}
	return diags
}

// woKey returns the HMAC key when state holds write-only content, and nil
// when it holds plain content.
func woKey(state cty.Value) ([]byte, error) {
	if state.IsNull() || state.GetAttr("content_hmac").IsNull() {
		return nil, nil
	}
	// Reading never creates a key: a new one here would only mismatch.
	key, err := hmacKey(false)
	if err != nil {
		return nil, err
	}
	if stored := state.GetAttr("content_hmac"); stored.IsKnown() {
		if err := checkHMACKey(stored.AsString(), key); err != nil {
			return nil, err
		}
	}
	return key, nil
}

// writeKey returns the HMAC key, checking that prior state, if it holds
// write-only content, was hashed with the same key.
func writeKey(prior cty.Value) ([]byte, error) {
	key, err := hmacKey(true)
	if err != nil {
		return nil, err
	}
	if !prior.IsNull() {
		if stored := prior.GetAttr("content_hmac"); stored.IsKnown() && !stored.IsNull() {
			if err := checkHMACKey(stored.AsString(), key); err != nil {
				return nil, err
			}
		}
	}
	return key, nil
}
