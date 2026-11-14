// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/conn3x/modules/windows"
	"github.com/opentofu/opentofu/internal/providers"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

const winExperimental = "Experimental. "

// levelAttr is the machine-or-user choice the environment steps share.
func levelAttr(name string) *configschema.Attribute {
	return &configschema.Attribute{Type: cty.String, Optional: true, Description: "\"machine\" (default), in HKLM for every account, or \"user\", in HKCU for the account Conn3x logs in as. Changing it is a different " + name + "."}
}

func winUserLevel(v cty.Value, attr string) bool {
	return stringOr(v.GetAttr(attr), "machine") == "user"
}

func validateLevel(cfg cty.Value, attr string) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if l := cfg.GetAttr(attr); known(l) && l.AsString() != "machine" && l.AsString() != "user" {
		diags = diags.Append(attrError(attr, fmt.Sprintf(`%s must be "machine" or "user", not %q`, attr, l.AsString())))
	}
	if s := cfg.GetAttr("state"); known(s) && s.AsString() != "present" && s.AsString() != "absent" {
		diags = diags.Append(attrError("state", fmt.Sprintf(`state must be "present" or "absent", not %q`, s.AsString())))
	}
	return diags.Append(validateOnRemove(cfg))
}

func winEnvSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: winExperimental + "One environment variable on a Windows host, the machine's or the login user's, as the registry holds it, unexpanded. New logons see a change; programs already running keep the environment they started with.",
		Attributes: map[string]*configschema.Attribute{
			"id":        {Type: cty.String, Computed: true},
			"revision":  revisionAttr(),
			"name":      {Type: cty.String, Required: true, Description: "The variable, such as JAVA_HOME. Not Path: give each folder in it a windows_path step."},
			"value":     {Type: cty.String, Optional: true, Description: "Its value, compared as written: %SystemRoot% stays %SystemRoot%. A new variable with % in it is stored to expand; an existing one keeps its type. Required unless state is \"absent\"."},
			"level":     levelAttr("variable"),
			"state":     {Type: cty.String, Optional: true, Description: "\"present\" (default), or \"absent\" to remove the variable."},
			"on_remove": {Type: cty.String, Optional: true, Computed: true, Description: "What happens on the host when this resource is removed: \"forget\" (default) leaves the variable, \"delete\" removes it."},
			"in_sync":   {Type: cty.Bool, Computed: true, Description: "Whether the variable matched at the last refresh."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func winEnvFrom(v cty.Value) windows.EnvVar {
	return windows.EnvVar{Name: stringOr(v.GetAttr("name"), ""), Value: stringOr(v.GetAttr("value"), ""), User: winUserLevel(v, "level"), Absent: stringOr(v.GetAttr("state"), "present") == "absent"}
}

func validateWinEnv(cfg cty.Value) tfdiags.Diagnostics {
	if cfg.IsNull() || !cfg.IsWhollyKnown() {
		return nil
	}
	diags := validateLevel(cfg, "level")
	e := winEnvFrom(cfg)
	if err := e.Validate(); err != nil {
		return diags.Append(attrError("name", err.Error()))
	}
	if strings.EqualFold(e.Name, "Path") {
		diags = diags.Append(attrError("name", windows.ErrPathVariable.Error()))
	}
	if !e.Absent && cfg.GetAttr("value").IsNull() {
		diags = diags.Append(attrError("value", `value is required unless state is "absent"`))
	}
	return diags
}

func planWinEnv(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	return planSyncedFold(req, "windows_environment", []string{"name", "level"}, []string{"value", "state"})
}

func readWinEnv(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	resp := providers.ReadResourceResponse{NewState: req.PriorState}
	if req.PriorState.IsNull() {
		return resp
	}
	h, err := winHost(ctx, req.PriorState.GetAttr("ssh"))
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(attrError("ssh", err.Error()))
		return resp
	}
	e := winEnvFrom(req.PriorState)
	a, err := windows.ReadEnv(ctx, h.client, e.Name, e.User)
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(err)
		return resp
	}
	resp.NewState = withSync(req.PriorState, e.Matches(a))
	return resp
}

func applyWinEnv(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	return applyWinStep(ctx, req, "windows_environment", func(ctx context.Context, h *hostConn, v cty.Value, remove bool) error {
		e := winEnvFrom(v)
		if remove {
			e.Absent = true
		}
		return windows.ApplyEnv(ctx, h.client, e)
	})
}

func winPathSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: winExperimental + "One folder in a Windows host's Path, the machine's or the login user's. The other folders and their order stay as they are. New logons see a change; programs already running keep the Path they started with.",
		Attributes: map[string]*configschema.Attribute{
			"id":        {Type: cty.String, Computed: true},
			"revision":  revisionAttr(),
			"element":   {Type: cty.String, Required: true, Description: "The folder, such as C:\\Program Files\\Go\\bin. Compared as Windows does, without case and with or without a trailing backslash. Added at the end."},
			"scope":     levelAttr("Path entry"),
			"state":     {Type: cty.String, Optional: true, Description: "\"present\" (default), or \"absent\" to take every copy of the folder out."},
			"on_remove": {Type: cty.String, Optional: true, Computed: true, Description: "What happens on the host when this resource is removed: \"forget\" (default) leaves the folder in Path, \"delete\" takes it out."},
			"in_sync":   {Type: cty.Bool, Computed: true, Description: "Whether Path had the folder, or didn't for state \"absent\", at the last refresh."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func winPathFrom(v cty.Value) windows.PathEntry {
	return windows.PathEntry{Element: stringOr(v.GetAttr("element"), ""), User: winUserLevel(v, "scope"), Absent: stringOr(v.GetAttr("state"), "present") == "absent"}
}

func validateWinPath(cfg cty.Value) tfdiags.Diagnostics {
	if cfg.IsNull() || !cfg.IsWhollyKnown() {
		return nil
	}
	diags := validateLevel(cfg, "scope")
	if err := winPathFrom(cfg).Validate(); err != nil {
		diags = diags.Append(attrError("element", err.Error()))
	}
	return diags
}

func planWinPath(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	return planSyncedFold(req, "windows_path", []string{"element", "scope"}, []string{"state"})
}

func readWinPath(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	resp := providers.ReadResourceResponse{NewState: req.PriorState}
	if req.PriorState.IsNull() {
		return resp
	}
	h, err := winHost(ctx, req.PriorState.GetAttr("ssh"))
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(attrError("ssh", err.Error()))
		return resp
	}
	p := winPathFrom(req.PriorState)
	a, err := windows.ReadEnv(ctx, h.client, "Path", p.User)
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(err)
		return resp
	}
	resp.NewState = withSync(req.PriorState, p.Matches(a))
	return resp
}

func applyWinPath(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	return applyWinStep(ctx, req, "windows_path", func(ctx context.Context, h *hostConn, v cty.Value, remove bool) error {
		p := winPathFrom(v)
		if remove {
			p.Absent = true
		}
		return windows.ApplyPath(ctx, h.client, p)
	})
}

// applyWinStep makes the host match the planned state, or, when the step is
// removed with on_remove = "delete", removes what it made.
func applyWinStep(ctx context.Context, req providers.ApplyResourceChangeRequest, kind string, apply func(ctx context.Context, h *hostConn, v cty.Value, remove bool) error) providers.ApplyResourceChangeResponse {
	var resp providers.ApplyResourceChangeResponse
	v, remove := req.PlannedState, req.PlannedState.IsNull()
	if remove {
		resp.NewState = req.PlannedState
		if req.PriorState.IsNull() || req.PriorState.GetAttr("on_remove").AsString() != onRemoveDelete {
			return resp
		}
		v = req.PriorState
	}
	h, err := winHost(ctx, v.GetAttr("ssh"))
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(attrError("ssh", err.Error()))
		return resp
	}
	if err := apply(ctx, h, v, remove); err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("%s: %w", kind, err))
		return resp
	}
	if !remove {
		resp.NewState = withSync(v, true)
	}
	return resp
}
