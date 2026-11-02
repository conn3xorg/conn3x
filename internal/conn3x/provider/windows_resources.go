// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/conn3x/modules/windows"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
	"github.com/opentofu/opentofu/internal/providers"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

const windowsTypePrefix = "conn3x_windows_"

// defaultScriptTimeout limits a windows_powershell script. Every run on Windows
// has a deadline, because a hung session can stall the whole connection.
const defaultScriptTimeout = 30 * time.Minute

// validateWindowsSSH rejects the ssh settings that have no meaning on Windows.
func validateWindowsSSH(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() || !cfg.Type().HasAttribute("ssh") {
		return diags
	}
	conn := cfg.GetAttr("ssh")
	if conn.IsNull() || !conn.IsKnown() {
		return diags
	}
	if v := conn.GetAttr("agent"); known(v) && v.True() {
		diags = diags.Append(tfdiags.AttributeValue(tfdiags.Error, "Invalid ssh setting for Windows",
			"The conn3x agent doesn't run on Windows. Remove agent from this ssh block.",
			cty.GetAttrPath("ssh").GetAttr("agent")))
	}
	if v := conn.GetAttr("become_password_file"); !v.IsNull() {
		diags = diags.Append(tfdiags.AttributeValue(tfdiags.Error, "Invalid ssh setting for Windows",
			"Windows has no sudo, so there is no password to give it. An administrator's SSH session is already elevated, and become only checks that it is. Remove become_password_file from this ssh block.",
			cty.GetAttrPath("ssh").GetAttr("become_password_file")))
	}
	return diags
}

// winHost returns the connection for a Windows step. It never attaches the
// agent, and with become it checks the login is elevated, since there is no
// user to switch to.
func winHost(ctx context.Context, conn cty.Value) (*hostConn, error) {
	h, err := pooled(ctx, conn, 0)
	if err != nil {
		if ssh.Unreachable(err) {
			return nil, fmt.Errorf("%w. On Windows, a connection reset during login can also mean this user doesn't exist or is disabled", err)
		}
		return nil, err
	}
	if v := conn.GetAttr("become"); v.IsNull() || !v.True() {
		return h, nil
	}
	h.mu.Lock()
	checked := h.elevated
	h.mu.Unlock()
	if checked {
		return h, nil
	}
	ok, err := windows.Elevated(ctx, h.client)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("become is set, but this login on %s isn't elevated. Log in as a member of Administrators", h.host)
	}
	h.mu.Lock()
	h.elevated = true
	h.mu.Unlock()
	return h, nil
}

func winWaitForSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "Experimental. Waits until a path exists, a service is running or a TCP port is listening on a Windows host. Refresh checks again, so a later apply waits again if it stopped.",
		Attributes: map[string]*configschema.Attribute{
			"id":       {Type: cty.String, Computed: true},
			"revision": revisionAttr(),
			"path":     {Type: cty.String, Optional: true, Description: "Path to wait for, such as C:\\app\\ready. Set exactly one of path, service and port."},
			"service":  {Type: cty.String, Optional: true, Description: "Name of a service to wait for until it is running. Set exactly one of path, service and port."},
			"port":     {Type: cty.Number, Optional: true, Description: "TCP port to wait for a listener on. Set exactly one of path, service and port."},
			"timeout":  {Type: cty.String, Optional: true, Description: "How long to wait. Defaults to \"5m\"."},
			"in_sync":  {Type: cty.Bool, Computed: true, Description: "Whether it was ready at the last refresh."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func winWaitForFrom(v cty.Value) (windows.WaitFor, error) {
	w := windows.WaitFor{Path: stringOr(v.GetAttr("path"), ""), Service: stringOr(v.GetAttr("service"), "")}
	if p := v.GetAttr("port"); !p.IsNull() {
		n, _ := p.AsBigFloat().Int64()
		w.Port = int(n)
	}
	var err error
	w.Timeout, err = durationOr(v.GetAttr("timeout"), windows.DefaultWait)
	return w, err
}

func validateWinWaitFor(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() || !cfg.IsWhollyKnown() {
		return diags
	}
	w, err := winWaitForFrom(cfg)
	if err == nil {
		err = w.Validate()
	}
	if err != nil {
		diags = diags.Append(attrError("path", err.Error()))
	}
	return diags
}

func planWinWaitFor(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	return planSynced(req, "windows_wait_for", []string{"path", "service", "port"}, nil)
}

func readWinWaitFor(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	resp := providers.ReadResourceResponse{NewState: req.PriorState}
	if req.PriorState.IsNull() {
		return resp
	}
	h, err := winHost(ctx, req.PriorState.GetAttr("ssh"))
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(attrError("ssh", err.Error()))
		return resp
	}
	w, err := winWaitForFrom(req.PriorState)
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(err)
		return resp
	}
	ok, err := w.Ready(ctx, h.client)
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(err)
		return resp
	}
	resp.NewState = withSync(req.PriorState, ok)
	return resp
}

// winWaitPoll is how often windows_wait_for asks. Each check starts PowerShell
// over a new session, which takes around half a second.
const winWaitPoll = 2 * time.Second

func applyWinWaitFor(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	var resp providers.ApplyResourceChangeResponse
	if req.PlannedState.IsNull() {
		resp.NewState = req.PlannedState
		return resp
	}
	fail := func(err error) providers.ApplyResourceChangeResponse {
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("windows_wait_for: %w", err))
		return resp
	}
	if s := req.PlannedState.GetAttr("in_sync"); !req.PriorState.IsNull() && s.IsKnown() && !s.IsNull() && s.True() {
		resp.NewState = req.PlannedState // only how Conn3x reaches the host changed
		return resp
	}
	w, err := winWaitForFrom(req.PlannedState)
	if err == nil {
		err = w.Validate()
	}
	if err != nil {
		return fail(err)
	}
	conn := req.PlannedState.GetAttr("ssh")
	deadline := time.Now().Add(w.Timeout)
	var last error
	for {
		// The host may just have rebooted, so failing to reach it only means
		// it isn't ready yet.
		h, err := winHost(ctx, conn)
		if err == nil {
			var ok bool
			ok, err = w.Ready(ctx, h.client)
			if err == nil && ok {
				resp.NewState = withSync(req.PlannedState, true)
				return resp
			}
		}
		if err != nil {
			last = err
		}
		if time.Now().After(deadline) {
			if last != nil {
				return fail(fmt.Errorf("timed out after %s waiting for %s: %w", w.Timeout.Round(time.Second), w, last))
			}
			return fail(fmt.Errorf("timed out after %s waiting for %s", w.Timeout.Round(time.Second), w))
		}
		select {
		case <-ctx.Done():
			return fail(ctx.Err())
		case <-time.After(winWaitPoll):
		}
	}
}

func winRebootSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "Experimental. Reboots a Windows host when created and whenever triggers change, then waits for it to come back. With only_if_pending it reboots only when Windows is waiting for one. Removing it does nothing.",
		Attributes: map[string]*configschema.Attribute{
			"id":              {Type: cty.String, Computed: true},
			"revision":        revisionAttr(),
			"triggers":        {Type: cty.Map(cty.String), Optional: true, Description: "Reboot again whenever any of these values change."},
			"timeout":         {Type: cty.String, Optional: true, Description: "How long to wait for the host to come back. Defaults to \"10m\"."},
			"only_if_pending": {Type: cty.Bool, Optional: true, Description: "Reboot only when Windows reports a reboot is pending, and plan one whenever a refresh finds that, so a reboot a failed run missed still happens."},
			"pending":         {Type: cty.Bool, Computed: true, Description: "With only_if_pending, whether a reboot was pending at the last refresh."},
			"boot_id":         {Type: cty.String, Computed: true, Description: "The host's boot ID after the last apply."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func onlyIfPending(v cty.Value) bool {
	o := v.GetAttr("only_if_pending")
	return known(o) && o.True()
}

func planWinReboot(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	var resp providers.PlanResourceChangeResponse
	if req.ProposedNewState.IsNull() {
		resp.PlannedState = req.ProposedNewState
		return resp
	}
	vals := req.ProposedNewState.AsValueMap()
	vals["id"] = planID(req, "windows_reboot")
	var reboot bool
	switch {
	case req.PriorState.IsNull():
		reboot = true
	case !req.PriorState.GetAttr("triggers").RawEquals(vals["triggers"]):
		resp.RequiresReplace = append(resp.RequiresReplace, cty.GetAttrPath("triggers"))
		reboot = true
	case !req.PriorState.GetAttr("ssh").GetAttr("host").RawEquals(req.ProposedNewState.GetAttr("ssh").GetAttr("host")):
		resp.RequiresReplace = append(resp.RequiresReplace, cty.GetAttrPath("ssh").GetAttr("host"))
		reboot = true
	case onlyIfPending(req.ProposedNewState):
		p := req.PriorState.GetAttr("pending")
		reboot = known(p) && p.True()
	}
	if reboot {
		vals["boot_id"] = cty.UnknownVal(cty.String)
		vals["pending"] = cty.UnknownVal(cty.Bool)
	}
	resp.PlannedState = cty.ObjectVal(vals)
	return resp
}

func readWinReboot(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	resp := providers.ReadResourceResponse{NewState: req.PriorState}
	if req.PriorState.IsNull() || !onlyIfPending(req.PriorState) {
		return resp
	}
	h, err := winHost(ctx, req.PriorState.GetAttr("ssh"))
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(attrError("ssh", err.Error()))
		return resp
	}
	pending, err := windows.PendingReboot(ctx, h.client)
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(err)
		return resp
	}
	vals := req.PriorState.AsValueMap()
	vals["pending"] = cty.BoolVal(pending)
	resp.NewState = cty.ObjectVal(vals)
	return resp
}

func applyWinReboot(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	var resp providers.ApplyResourceChangeResponse
	// A known boot_id means the plan did not ask for a reboot.
	if req.PlannedState.IsNull() || req.PlannedState.GetAttr("boot_id").IsKnown() {
		resp.NewState = req.PlannedState
		return resp
	}
	fail := func(err error) providers.ApplyResourceChangeResponse {
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("windows_reboot: %w", err))
		return resp
	}
	wait, err := durationOr(req.PlannedState.GetAttr("timeout"), defaultRebootWait)
	if err != nil {
		return fail(err)
	}
	conn := req.PlannedState.GetAttr("ssh")
	h, err := winHost(ctx, conn)
	if err != nil {
		return fail(err)
	}
	before, err := windows.BootID(ctx, h.client)
	if err != nil {
		return fail(err)
	}
	vals := req.PlannedState.AsValueMap()
	vals["boot_id"] = cty.StringVal(before)
	vals["pending"] = cty.False
	if onlyIfPending(req.PlannedState) {
		pending, err := windows.PendingReboot(ctx, h.client)
		if err != nil {
			return fail(err)
		}
		if !pending {
			resp.NewState = cty.ObjectVal(vals)
			return resp
		}
	}
	if err := windows.ApplyReboot(ctx, h.client); err != nil {
		return fail(err)
	}
	// Drop the pooled connection; the next dial makes a new one.
	_ = h.client.Close()
	now, err := waitForNewBoot(ctx, wait, before, func(ctx context.Context) (string, error) {
		h, err := winHost(ctx, conn)
		if err != nil {
			return "", err
		}
		// A session caught by the shutdown can hang; don't let it use the
		// whole read timeout.
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		return windows.BootID(ctx, h.client)
	})
	if err != nil {
		return fail(err)
	}
	vals["boot_id"] = cty.StringVal(now)
	if onlyIfPending(req.PlannedState) {
		h, err := winHost(ctx, conn)
		if err == nil {
			var pending bool
			if pending, err = windows.PendingReboot(ctx, h.client); err == nil {
				vals["pending"] = cty.BoolVal(pending)
			}
		}
		if err != nil {
			return fail(err)
		}
	}
	resp.NewState = cty.ObjectVal(vals)
	return resp
}

// winPowershellRerun lists the arguments whose change means "run it again".
var winPowershellRerun = []string{"script", "args", "args_hmac", "creates", "removes", "unless", "triggers"}

func winPowershellSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "Experimental. A PowerShell script on a Windows host, for what no module covers yet. Guards say when it has already done its job.",
		Attributes: map[string]*configschema.Attribute{
			"id":       {Type: cty.String, Computed: true},
			"revision": revisionAttr(),
			"script":   {Type: cty.String, Required: true, Description: "PowerShell script. Start it with param($A), and read arguments as $A.name rather than interpolating them into the text."},
			"args":     {Type: cty.Map(cty.String), Optional: true, Description: "Values the script reads as $A.name. They reach it as data, never as code."},
			"args_wo": {
				Type: cty.Map(cty.String), Optional: true, WriteOnly: true, Sensitive: true,
				Description: "Like args, but kept out of state: state records only args_hmac, and the values are blanked from output and errors. Use it for secrets.",
			},
			"args_hmac": {Type: cty.String, Computed: true, Description: "HMAC-SHA256 of args_wo, keyed by CONN3X_HMAC_KEY or ~/.config/conn3x/hmac.key. Null without args_wo."},
			"creates":   {Type: cty.String, Optional: true, Description: "Skip the script while this path exists."},
			"removes":   {Type: cty.String, Optional: true, Description: "Skip the script while this path is missing."},
			"unless":    {Type: cty.String, Optional: true, Description: "Skip the script while this PowerShell check holds: it holds unless it throws, its last output is $false, or a native program it ran last exited non-zero. It runs at every plan and gets the same args, so it must change nothing."},
			"triggers":  {Type: cty.DynamicPseudoType, Optional: true, Description: "Any value; the script runs again whenever it changes."},
			"timeout":   {Type: cty.String, Optional: true, Description: "How long the script may run before it is stopped. Defaults to \"30m\"."},
			"satisfied": {Type: cty.Bool, Computed: true, Description: "Whether the guards hold on the host."},
			"stdout":    {Type: cty.String, Computed: true, Sensitive: true, Description: "Output of the last run, truncated to 4 KiB."},
			"stderr":    {Type: cty.String, Computed: true, Sensitive: true, Description: "Error output of the last run, truncated to 4 KiB."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func winGuards(v cty.Value) windows.Guards {
	return windows.Guards{
		Creates: stringOr(v.GetAttr("creates"), ""),
		Removes: stringOr(v.GetAttr("removes"), ""),
		Unless:  stringOr(v.GetAttr("unless"), ""),
	}
}

func validateWinPowershell(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() {
		return diags
	}
	if s := cfg.GetAttr("script"); known(s) && s.AsString() == "" {
		diags = diags.Append(attrError("script", "script must not be empty"))
	}
	if t := cfg.GetAttr("timeout"); t.IsKnown() {
		if _, err := durationOr(t, defaultScriptTimeout); err != nil {
			diags = diags.Append(attrError("timeout", err.Error()))
		}
	}
	args, wo := cfg.GetAttr("args"), cfg.GetAttr("args_wo")
	if known(args) && known(wo) {
		for name := range wo.AsValueMap() {
			if _, both := args.AsValueMap()[name]; both {
				diags = diags.Append(attrError("args_wo", fmt.Sprintf("%q is in both args and args_wo", name)))
			}
		}
	}
	for _, a := range []string{"creates", "removes"} {
		if !cfg.GetAttr(a).IsKnown() {
			return diags
		}
	}
	guards := windows.Guards{Creates: stringOr(cfg.GetAttr("creates"), ""), Removes: stringOr(cfg.GetAttr("removes"), "")}
	if err := guards.Validate(); err != nil {
		diags = diags.Append(attrError("creates", err.Error()))
	}
	return diags
}

func stringMap(v cty.Value) map[string]string {
	out := map[string]string{}
	if !known(v) {
		return out
	}
	for k, e := range v.AsValueMap() {
		if !e.IsNull() {
			out[k] = e.AsString()
		}
	}
	return out
}

// argsHMAC is what state records for args_wo. json.Marshal sorts the keys, so
// the same values always give the same mac.
func argsHMAC(key []byte, wo cty.Value) (string, error) {
	b, err := json.Marshal(stringMap(wo))
	if err != nil {
		return "", err
	}
	return contentHMAC(key, "windows_powershell.args_wo", string(b)), nil
}

func planWinPowershell(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	if req.ProposedNewState.IsNull() {
		return providers.PlanResourceChangeResponse{PlannedState: req.ProposedNewState}
	}
	vals := req.ProposedNewState.AsValueMap()
	vals["args_wo"] = cty.NullVal(cty.Map(cty.String))
	vals["args_hmac"] = cty.NullVal(cty.String)
	var warning error
	if wo := req.Config.GetAttr("args_wo"); !wo.IsNull() {
		vals["args_hmac"] = cty.UnknownVal(cty.String)
		key, err := hmacKey(true)
		if err == nil && !req.PriorState.IsNull() {
			if stored := req.PriorState.GetAttr("args_hmac"); known(stored) {
				err = checkHMACKey(stored.AsString(), key)
			}
		}
		if err != nil {
			var resp providers.PlanResourceChangeResponse
			resp.Diagnostics = resp.Diagnostics.Append(attrError("args_wo", err.Error()))
			return resp
		}
		warning = hmacKeyPermissionWarning()
		if wo.IsWhollyKnown() {
			mac, err := argsHMAC(key, wo)
			if err != nil {
				var resp providers.PlanResourceChangeResponse
				resp.Diagnostics = resp.Diagnostics.Append(attrError("args_wo", err.Error()))
				return resp
			}
			vals["args_hmac"] = cty.StringVal(mac)
		}
	}
	req.ProposedNewState = cty.ObjectVal(vals)
	resp := planGuarded(req, "windows_powershell", winPowershellRerun)
	if warning != nil {
		resp.Diagnostics = resp.Diagnostics.Append(tfdiags.SimpleWarning(warning.Error()))
	}
	return resp
}

// scriptArgs joins args and args_wo for the script, and lists the secrets.
func scriptArgs(args, wo cty.Value) (map[string]any, []string) {
	out := map[string]any{}
	for k, v := range stringMap(args) {
		out[k] = v
	}
	var secrets []string
	for k, v := range stringMap(wo) {
		out[k] = v
		secrets = append(secrets, v)
	}
	// Longest first, so a secret inside another is never left half blanked.
	sort.Slice(secrets, func(i, j int) bool { return len(secrets[i]) > len(secrets[j]) })
	return out, secrets
}

func readWinPowershell(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	resp := providers.ReadResourceResponse{NewState: req.PriorState}
	if req.PriorState.IsNull() || !winGuards(req.PriorState).Any() {
		return resp
	}
	h, err := winHost(ctx, req.PriorState.GetAttr("ssh"))
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(attrError("ssh", err.Error()))
		return resp
	}
	// args_wo is never in state, so a refresh has only args to give the check.
	args, _ := scriptArgs(req.PriorState.GetAttr("args"), cty.NullVal(cty.Map(cty.String)))
	ok, err := windows.Satisfied(ctx, h.client, winGuards(req.PriorState), args)
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(err)
		return resp
	}
	vals := req.PriorState.AsValueMap()
	vals["satisfied"] = cty.BoolVal(ok)
	resp.NewState = cty.ObjectVal(vals)
	return resp
}

func applyWinPowershell(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	var resp providers.ApplyResourceChangeResponse
	// A known satisfied means the plan found nothing to rerun.
	if req.PlannedState.IsNull() || (!req.PriorState.IsNull() && req.PlannedState.GetAttr("satisfied").IsKnown()) {
		resp.NewState = req.PlannedState
		return resp
	}
	timeout, err := durationOr(req.PlannedState.GetAttr("timeout"), defaultScriptTimeout)
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(attrError("timeout", err.Error()))
		return resp
	}
	h, err := winHost(ctx, req.PlannedState.GetAttr("ssh"))
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(attrError("ssh", err.Error()))
		return resp
	}
	guards := winGuards(req.PlannedState)
	wo := req.Config.GetAttr("args_wo")
	args, secrets := scriptArgs(req.PlannedState.GetAttr("args"), wo)
	vals := req.PlannedState.AsValueMap()
	vals["args_wo"] = cty.NullVal(cty.Map(cty.String))
	if !wo.IsNull() {
		key, err := hmacKey(true)
		if err == nil {
			var mac string
			if mac, err = argsHMAC(key, wo); err == nil {
				vals["args_hmac"] = cty.StringVal(mac)
			}
		}
		if err != nil {
			resp.Diagnostics = resp.Diagnostics.Append(attrError("args_wo", err.Error()))
			return resp
		}
	}
	done, err := windows.Satisfied(ctx, h.client, guards, args)
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(errors.New(windows.Scrub(err.Error(), secrets)))
		return resp
	}
	stdout, stderr := cty.StringVal(""), cty.StringVal("")
	if !req.PriorState.IsNull() {
		stdout, stderr = req.PriorState.GetAttr("stdout"), req.PriorState.GetAttr("stderr")
	}
	if !done {
		out, err := windows.RunScript(ctx, h.client, req.PlannedState.GetAttr("script").AsString(), args, secrets, timeout)
		if err != nil {
			resp.Diagnostics = resp.Diagnostics.Append(err)
			return resp
		}
		stdout, stderr = cty.StringVal(out.Stdout), cty.StringVal(out.Stderr)
		if guards.Any() {
			if ok, err := windows.Satisfied(ctx, h.client, guards, args); err != nil || !ok {
				resp.Diagnostics = resp.Diagnostics.Append(errors.New("the script ran, but its guards still don't hold; check creates, removes and unless match what it does"))
				return resp
			}
		}
	}
	vals["satisfied"] = cty.True
	vals["stdout"], vals["stderr"] = stdout, stderr
	resp.NewState = cty.ObjectVal(vals)
	return resp
}
