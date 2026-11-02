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

func winTaskSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "Experimental. A scheduled task on a Windows host that runs one program.",
		Attributes: map[string]*configschema.Attribute{
			"id":                {Type: cty.String, Computed: true},
			"revision":          revisionAttr(),
			"name":              {Type: cty.String, Required: true, Description: "Task name: letters, digits, spaces and . _ ( ) -."},
			"path":              {Type: cty.String, Optional: true, Description: "Task folder, such as \\Conn3x\\. Defaults to \\. Made if it's missing."},
			"description":       {Type: cty.String, Optional: true, Description: "Description. Left as it is when unset."},
			"execute":           {Type: cty.String, Required: true, Description: "Absolute path of the program to run, such as C:\\Windows\\System32\\cmd.exe."},
			"arguments":         {Type: cty.String, Optional: true, Description: "Its arguments. They're in the task, readable by administrators, and in state: never secrets."},
			"working_directory": {Type: cty.String, Optional: true, Description: "Folder it starts in."},
			"user":              {Type: cty.String, Required: true, Description: "Account it runs as: SYSTEM, LOCAL SERVICE or NETWORK SERVICE with no password; another account with password_wo; or the login Conn3x uses, without one, to run unattended with no network access (S4U)."},
			"password_wo": {
				Type: cty.String, Optional: true, WriteOnly: true, Sensitive: true,
				Description: "The user's password, for a task that needs network access. Kept out of plan and state: state records only password_hmac. A password changed on the host isn't detected.",
			},
			"password_hmac": {Type: cty.String, Computed: true, Description: "HMAC-SHA256 of password_wo, keyed by CONN3X_HMAC_KEY or ~/.config/conn3x/hmac.key."},
			"run_level":     {Type: cty.String, Optional: true, Description: "\"limited\" (default) or \"highest\", which runs elevated."},
			"allow_interpreter": {
				Type: cty.Bool, Optional: true,
				Description: "Let execute be a program that runs code from its arguments, such as cmd.exe, powershell.exe, wscript.exe, rundll32.exe or python.exe. Conn3x checks the paths it can see in arguments, but not code inside them, such as -Command text or -EncodedCommand.",
			},
			"data_paths": {
				Type: cty.Set(cty.String), Optional: true,
				Description: "Full paths in arguments that the program only reads data from or writes output to, such as a log file. Each must appear exactly once in arguments, and skips the admin-only check, so anyone who can write there can change them. Never list a file or folder the program loads code or settings from, or runs.",
			},
			"enabled":   {Type: cty.Bool, Optional: true, Description: "Whether the task can run. Defaults to true."},
			"on_remove": {Type: cty.String, Optional: true, Computed: true, Description: "\"delete\" (default) deletes the task when the step is removed or replaced, \"forget\" leaves it."},
			"in_sync":   {Type: cty.Bool, Computed: true, Description: "Whether the task matched at the last refresh."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{
			"ssh": connectionBlock(),
			"trigger": {
				Nesting: configschema.NestingList,
				Block: configschema.Block{
					Description: "When it runs. With none, it runs only when started.",
					Attributes: map[string]*configschema.Attribute{
						"type":          {Type: cty.String, Required: true, Description: "\"boot\", \"logon\", \"daily\" or \"once\"."},
						"at":            {Type: cty.String, Optional: true, Description: "For daily and once: local time on the host, such as 2026-01-01T03:00:00."},
						"days_interval": {Type: cty.Number, Optional: true, Description: "For daily: every this many days. Defaults to 1."},
					},
				},
			},
		},
	}}
}

func winTaskFrom(v cty.Value) windows.Task {
	t := windows.Task{
		Path: stringOr(v.GetAttr("path"), `\`), Name: stringOr(v.GetAttr("name"), ""), Execute: stringOr(v.GetAttr("execute"), ""),
		Arguments: stringOr(v.GetAttr("arguments"), ""), WorkingDirectory: stringOr(v.GetAttr("working_directory"), ""),
		User: stringOr(v.GetAttr("user"), ""), Highest: stringOr(v.GetAttr("run_level"), "") == "highest", Enabled: true,
	}
	if d := v.GetAttr("description"); known(d) {
		s := d.AsString()
		t.Description = &s
	}
	if e := v.GetAttr("enabled"); known(e) {
		t.Enabled = e.True()
	}
	if a := v.GetAttr("allow_interpreter"); known(a) {
		t.AllowInterpreter = a.True()
	}
	if dp := v.GetAttr("data_paths"); known(dp) {
		for it := dp.ElementIterator(); it.Next(); {
			_, e := it.Element()
			t.DataPaths = append(t.DataPaths, e.AsString())
		}
	}
	if trs := v.GetAttr("trigger"); known(trs) {
		for it := trs.ElementIterator(); it.Next(); {
			_, e := it.Element()
			tr := windows.TaskTrigger{Type: stringOr(e.GetAttr("type"), ""), At: stringOr(e.GetAttr("at"), "")}
			if d := e.GetAttr("days_interval"); known(d) {
				n, _ := d.AsBigFloat().Int64()
				tr.DaysInterval = int(n)
			}
			t.Triggers = append(t.Triggers, tr)
		}
	}
	return t
}

func validateWinTask(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() {
		return diags
	}
	diags = diags.Append(validateOnRemove(cfg))
	if pw := cfg.GetAttr("password_wo"); known(pw) && (pw.AsString() == "" || strings.ContainsRune(pw.AsString(), 0)) {
		diags = diags.Append(attrError("password_wo", "password_wo must not be empty or contain NUL"))
	}
	if rl := cfg.GetAttr("run_level"); known(rl) && rl.AsString() != "limited" && rl.AsString() != "highest" {
		diags = diags.Append(attrError("run_level", fmt.Sprintf(`run_level %q must be "limited" or "highest"`, rl.AsString())))
	}
	for _, a := range []string{"name", "path", "description", "execute", "arguments", "working_directory", "user", "trigger", "allow_interpreter", "data_paths"} {
		if !cfg.GetAttr(a).IsWhollyKnown() {
			return diags
		}
	}
	t := winTaskFrom(cfg)
	t.HasPassword = !cfg.GetAttr("password_wo").IsNull()
	if err := t.Validate(); err != nil {
		diags = diags.Append(attrError("name", err.Error()))
	}
	return diags
}

// winTaskID is what a password's HMAC is bound to.
func winTaskID(host string, t windows.Task) string {
	return "windows_scheduled_task:" + strings.ToLower(host) + ":" + strings.ToLower(t.Path+t.Name)
}

var winTaskSettings = []string{"description", "execute", "arguments", "working_directory", "user", "password_hmac", "run_level", "enabled", "trigger", "allow_interpreter", "data_paths"}

func planWinTask(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	if req.ProposedNewState.IsNull() {
		return providers.PlanResourceChangeResponse{PlannedState: req.ProposedNewState}
	}
	var resp providers.PlanResourceChangeResponse
	vals := req.ProposedNewState.AsValueMap()
	vals["password_wo"] = cty.NullVal(cty.String)
	vals["password_hmac"] = cty.NullVal(cty.String)
	var warn error
	if wo := req.Config.GetAttr("password_wo"); !wo.IsNull() {
		vals["password_hmac"] = cty.UnknownVal(cty.String)
		key, err := hmacKey(true)
		if err == nil && !req.PriorState.IsNull() {
			if stored := req.PriorState.GetAttr("password_hmac"); known(stored) {
				err = checkHMACKey(stored.AsString(), key)
			}
		}
		if err != nil {
			resp.Diagnostics = resp.Diagnostics.Append(attrError("password_wo", err.Error()))
			return resp
		}
		warn = hmacKeyPermissionWarning()
		host := cty.NullVal(cty.String)
		if conn := vals["ssh"]; !conn.IsNull() && conn.IsKnown() {
			host = conn.GetAttr("host")
		}
		if wo.IsKnown() && known(host) && known(vals["name"]) && vals["path"].IsKnown() {
			vals["password_hmac"] = cty.StringVal(passwordHMAC(key, winTaskID(host.AsString(), winTaskFrom(cty.ObjectVal(vals))), wo.AsString()))
		}
	}
	req.ProposedNewState = cty.ObjectVal(vals)
	resp = planSyncedFold(deleteByDefault(req), "windows_scheduled_task", []string{"path", "name"}, winTaskSettings)
	if warn != nil {
		resp.Diagnostics = resp.Diagnostics.Append(tfdiags.SimpleWarning(warn.Error()))
	}
	return resp
}

func readWinTask(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	resp := providers.ReadResourceResponse{NewState: req.PriorState}
	if req.PriorState.IsNull() {
		return resp
	}
	h, err := winHost(ctx, req.PriorState.GetAttr("ssh"))
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(attrError("ssh", err.Error()))
		return resp
	}
	t := winTaskFrom(req.PriorState)
	t.HasPassword = known(req.PriorState.GetAttr("password_hmac"))
	a, err := windows.ReadTask(ctx, h.client, t)
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(err)
		return resp
	}
	resp.NewState = withSync(req.PriorState, t.Matches(a))
	return resp
}

func applyWinTask(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	var resp providers.ApplyResourceChangeResponse
	fail := func(err error) providers.ApplyResourceChangeResponse {
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("windows_scheduled_task: %w", err))
		return resp
	}
	if req.PlannedState.IsNull() {
		resp.NewState = req.PlannedState
		if req.PriorState.IsNull() || req.PriorState.GetAttr("on_remove").AsString() != onRemoveDelete {
			return resp
		}
		h, err := winHost(ctx, req.PriorState.GetAttr("ssh"))
		if err != nil {
			return fail(err)
		}
		t := winTaskFrom(req.PriorState)
		if err := windows.ApplyTaskRemove(ctx, h.client, t.Path, t.Name); err != nil {
			return fail(err)
		}
		return resp
	}
	planned := req.PlannedState
	t := winTaskFrom(planned)
	vals := planned.AsValueMap()
	vals["password_wo"] = cty.NullVal(cty.String)
	password := ""
	if wo := req.Config.GetAttr("password_wo"); !wo.IsNull() {
		// A saved plan applied elsewhere must use the key it was made with.
		key, err := hmacKey(true)
		if err != nil {
			return fail(err)
		}
		stored := []cty.Value{planned.GetAttr("password_hmac")}
		if !req.PriorState.IsNull() {
			stored = append(stored, req.PriorState.GetAttr("password_hmac"))
		}
		for _, v := range stored {
			if known(v) {
				if err := checkHMACKey(v.AsString(), key); err != nil {
					return fail(err)
				}
			}
		}
		password = wo.AsString()
		t.HasPassword = true
		vals["password_hmac"] = cty.StringVal(passwordHMAC(key, winTaskID(stringOr(planned.GetAttr("ssh").GetAttr("host"), ""), t), password))
	}
	if err := t.Validate(); err != nil {
		return fail(err)
	}
	h, err := winHost(ctx, planned.GetAttr("ssh"))
	if err != nil {
		return fail(err)
	}
	a, err := windows.ReadTask(ctx, h.client, t)
	if err != nil {
		return fail(err)
	}
	// A new password can't be compared on the host, so it always registers.
	newPassword := password != "" && (req.PriorState.IsNull() || !req.PriorState.GetAttr("password_hmac").RawEquals(vals["password_hmac"]))
	if newPassword || !t.Matches(a) {
		if err := windows.ApplyTask(ctx, h.client, t, password); err != nil {
			return fail(fmt.Errorf("task %s%s: %w", t.Path, t.Name, err))
		}
		if a, err = windows.ReadTask(ctx, h.client, t); err != nil {
			return fail(err)
		}
		if !t.Matches(a) {
			return fail(fmt.Errorf("task %s%s doesn't match what was registered; Windows may have changed a setting", t.Path, t.Name))
		}
	}
	vals["in_sync"] = cty.True
	resp.NewState = cty.ObjectVal(vals)
	return resp
}
