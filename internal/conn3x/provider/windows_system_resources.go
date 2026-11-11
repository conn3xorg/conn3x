// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/conn3x/modules/windows"
	"github.com/opentofu/opentofu/internal/providers"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

func winRegistrySchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "Experimental. One registry value under HKLM on a Windows host. The value's type and data are compared with what's there, without expanding environment names.",
		Attributes: map[string]*configschema.Attribute{
			"id":       {Type: cty.String, Computed: true},
			"revision": revisionAttr(),
			"key":      {Type: cty.String, Required: true, Description: "Key under HKLM, such as HKLM\\SOFTWARE\\App. Created if it's missing."},
			"name":     {Type: cty.String, Optional: true, Description: "Value name. Leave unset for the key's default value."},
			"type":     {Type: cty.String, Required: true, Description: "\"string\", \"expand_string\", \"multi_string\", \"dword\", \"qword\" or \"binary\"."},
			"data":     {Type: cty.String, Optional: true, Description: "The data: a decimal number for dword and qword, hex for binary, one value per line for multi_string. Set this or data_wo."},
			"data_wo": {
				Type: cty.String, Optional: true, WriteOnly: true, Sensitive: true,
				Description: "Like data, but kept out of state: state records only data_hmac. Use it for secrets.",
			},
			"data_hmac": {Type: cty.String, Computed: true, Description: "HMAC-SHA256 of data_wo, keyed by CONN3X_HMAC_KEY or ~/.config/conn3x/hmac.key. Null when data is used."},
			"on_remove": {Type: cty.String, Optional: true, Computed: true, Description: "What happens on the host when this resource is removed: \"forget\" (default) leaves the value, \"delete\" removes the value and leaves the key."},
			"in_sync":   {Type: cty.Bool, Computed: true, Description: "Whether the value matched at the last refresh. A secret's change shows here only."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func winRegistryFrom(v cty.Value, data string) windows.RegistryValue {
	return windows.RegistryValue{
		Key:  stringOr(v.GetAttr("key"), ""),
		Name: stringOr(v.GetAttr("name"), ""),
		Type: stringOr(v.GetAttr("type"), ""),
		Data: data,
	}
}

func validateWinRegistry(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() {
		return diags
	}
	data, wo := cfg.GetAttr("data"), cfg.GetAttr("data_wo")
	if data.IsNull() == wo.IsNull() {
		diags = diags.Append(attrError("data", "set exactly one of data and data_wo"))
	}
	diags = diags.Append(validateOnRemove(cfg))
	for _, a := range []string{"key", "name", "type"} {
		if !cfg.GetAttr(a).IsKnown() {
			return diags
		}
	}
	v := winRegistryFrom(cfg, "")
	if err := v.Validate(); err != nil {
		return diags.Append(attrError("key", err.Error()))
	}
	for _, d := range []struct {
		attr string
		val  cty.Value
	}{{"data", data}, {"data_wo", wo}} {
		if known(d.val) {
			v.Data = d.val.AsString()
			if err := v.CheckData(); err != nil {
				diags = diags.Append(attrError(d.attr, err.Error()))
			}
		}
	}
	return diags
}

// winRegistryID is what a secret's HMAC is bound to.
func winRegistryID(v windows.RegistryValue) string { return v.Key + `\` + v.Name }

func planWinRegistry(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	if req.ProposedNewState.IsNull() {
		return providers.PlanResourceChangeResponse{PlannedState: req.ProposedNewState}
	}
	var resp providers.PlanResourceChangeResponse
	vals := req.ProposedNewState.AsValueMap()
	vals["data_wo"] = cty.NullVal(cty.String)
	vals["data_hmac"] = cty.NullVal(cty.String)
	var warn error
	if wo := req.Config.GetAttr("data_wo"); !wo.IsNull() {
		vals["data"] = cty.NullVal(cty.String)
		vals["data_hmac"] = cty.UnknownVal(cty.String)
		key, err := hmacKey(true)
		if err == nil && !req.PriorState.IsNull() {
			if stored := req.PriorState.GetAttr("data_hmac"); known(stored) {
				err = checkHMACKey(stored.AsString(), key)
			}
		}
		if err != nil {
			resp.Diagnostics = resp.Diagnostics.Append(attrError("data_wo", err.Error()))
			return resp
		}
		warn = hmacKeyPermissionWarning()
		if wo.IsKnown() && vals["key"].IsKnown() && vals["name"].IsKnown() && vals["type"].IsKnown() {
			v := winRegistryFrom(cty.ObjectVal(vals), wo.AsString())
			c, err := v.Canonical()
			if err != nil {
				resp.Diagnostics = resp.Diagnostics.Append(attrError("data_wo", err.Error()))
				return resp
			}
			vals["data_hmac"] = cty.StringVal(winWoHMAC(key, winRegistryID(v), digest(c)))
		}
	}
	req.ProposedNewState = cty.ObjectVal(vals)
	resp = planSynced(req, "windows_registry_value", []string{"key", "name"}, []string{"type", "data", "data_hmac"})
	if warn != nil {
		resp.Diagnostics = resp.Diagnostics.Append(tfdiags.SimpleWarning(warn.Error()))
	}
	return resp
}

func readWinRegistry(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	resp := providers.ReadResourceResponse{NewState: req.PriorState}
	if req.PriorState.IsNull() {
		return resp
	}
	h, err := winHost(ctx, req.PriorState.GetAttr("ssh"))
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(attrError("ssh", err.Error()))
		return resp
	}
	v := winRegistryFrom(req.PriorState, stringOr(req.PriorState.GetAttr("data"), ""))
	stored := req.PriorState.GetAttr("data_hmac")
	a, err := windows.ReadRegistry(ctx, h.client, v, known(stored))
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(err)
		return resp
	}
	var inSync bool
	if known(stored) {
		key, err := hmacKey(false)
		if err == nil {
			err = checkHMACKey(stored.AsString(), key)
		}
		if err != nil {
			resp.Diagnostics = resp.Diagnostics.Append(attrError("data_wo", err.Error()))
			return resp
		}
		inSync = a.Exists && a.Type == v.Type && winWoHMAC(key, winRegistryID(v), a.SHA256) == stored.AsString()
	} else if inSync, err = v.Matches(a); err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(err)
		return resp
	}
	resp.NewState = withSync(req.PriorState, inSync)
	return resp
}

func applyWinRegistry(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	var resp providers.ApplyResourceChangeResponse
	fail := func(err error) providers.ApplyResourceChangeResponse {
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("windows_registry_value: %w", err))
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
		if err := windows.ApplyRegistryRemove(ctx, h.client, winRegistryFrom(req.PriorState, "")); err != nil {
			return fail(err)
		}
		return resp
	}
	planned := req.PlannedState
	// A saved plan applied elsewhere must use the key it was made with, and a
	// value under another key must not be overwritten and rehashed.
	if !req.Config.GetAttr("data_wo").IsNull() {
		key, err := hmacKey(true)
		if err != nil {
			return fail(err)
		}
		stored := []cty.Value{planned.GetAttr("data_hmac")}
		if !req.PriorState.IsNull() {
			stored = append(stored, req.PriorState.GetAttr("data_hmac"))
		}
		for _, v := range stored {
			if known(v) {
				if err := checkHMACKey(v.AsString(), key); err != nil {
					return fail(err)
				}
			}
		}
	}
	h, err := winHost(ctx, planned.GetAttr("ssh"))
	if err != nil {
		return fail(err)
	}
	data := stringOr(planned.GetAttr("data"), "")
	vals := planned.AsValueMap()
	vals["data_wo"] = cty.NullVal(cty.String)
	wo := req.Config.GetAttr("data_wo")
	if !wo.IsNull() {
		data = wo.AsString()
	}
	v := winRegistryFrom(planned, data)
	if !wo.IsNull() {
		c, err := v.Canonical()
		if err != nil {
			return fail(err)
		}
		key, err := hmacKey(true)
		if err != nil {
			return fail(err)
		}
		vals["data_hmac"] = cty.StringVal(winWoHMAC(key, winRegistryID(v), digest(c)))
	}
	if err := windows.ApplyRegistry(ctx, h.client, v); err != nil {
		return fail(err)
	}
	a, err := windows.ReadRegistry(ctx, h.client, v, !wo.IsNull())
	if err != nil {
		return fail(err)
	}
	var ok bool
	if wo.IsNull() {
		ok, err = v.Matches(a)
	} else {
		var c string
		if c, err = v.Canonical(); err == nil {
			ok = a.Exists && a.Type == v.Type && a.SHA256 == digest(c)
		}
	}
	if err != nil || !ok {
		return fail(fmt.Errorf("the value at %s doesn't match what was written; something else changed it", winRegistryID(v)))
	}
	vals["in_sync"] = cty.True
	resp.NewState = cty.ObjectVal(vals)
	return resp
}

func winServiceSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "Experimental. A service that already exists on a Windows host: how it starts and whether it's running. Removing the step leaves it as it is.",
		Attributes: map[string]*configschema.Attribute{
			"id":         {Type: cty.String, Computed: true},
			"revision":   revisionAttr(),
			"name":       {Type: cty.String, Required: true, Description: "Service name, not its display name, such as W3SVC."},
			"start_mode": {Type: cty.String, Optional: true, Description: "\"auto\", \"delayed\", \"manual\" or \"disabled\". Left as it is when unset."},
			"state":      {Type: cty.String, Optional: true, Description: "\"running\" or \"stopped\". Left as it is when unset."},
			"in_sync":    {Type: cty.Bool, Computed: true, Description: "Whether the service matched at the last refresh."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func winServiceFrom(v cty.Value) windows.Service {
	return windows.Service{Name: stringOr(v.GetAttr("name"), ""), StartMode: stringOr(v.GetAttr("start_mode"), ""), State: stringOr(v.GetAttr("state"), "")}
}

func validateWinService(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() || !cfg.IsWhollyKnown() {
		return diags
	}
	if err := winServiceFrom(cfg).Validate(); err != nil {
		diags = diags.Append(attrError("name", err.Error()))
	}
	return diags
}

func planWinService(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	return planSynced(req, "windows_service", []string{"name"}, []string{"start_mode", "state"})
}

func readWinService(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	resp := providers.ReadResourceResponse{NewState: req.PriorState}
	if req.PriorState.IsNull() {
		return resp
	}
	h, err := winHost(ctx, req.PriorState.GetAttr("ssh"))
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(attrError("ssh", err.Error()))
		return resp
	}
	_, ok, err := windows.ServiceInSync(ctx, h.client, winServiceFrom(req.PriorState))
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(err)
		return resp
	}
	resp.NewState = withSync(req.PriorState, ok)
	return resp
}

func applyWinService(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	var resp providers.ApplyResourceChangeResponse
	if req.PlannedState.IsNull() {
		resp.NewState = req.PlannedState
		return resp
	}
	fail := func(err error) providers.ApplyResourceChangeResponse {
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("windows_service: %w", err))
		return resp
	}
	s := winServiceFrom(req.PlannedState)
	if err := s.Validate(); err != nil {
		return fail(err)
	}
	h, err := winHost(ctx, req.PlannedState.GetAttr("ssh"))
	if err != nil {
		return fail(err)
	}
	// One at a time per host, as a service can depend on another one starting.
	defer lockHost(h, "windows_service")()
	exists, ok, err := windows.ServiceInSync(ctx, h.client, s)
	if err != nil {
		return fail(err)
	}
	if !exists {
		return fail(fmt.Errorf("no service named %s on this host", s.Name))
	}
	if !ok {
		if err := windows.ApplyService(ctx, h.client, s); err != nil {
			return fail(fmt.Errorf("changing %s: %w", s.Name, err))
		}
		if _, ok, err = windows.ServiceInSync(ctx, h.client, s); err != nil {
			return fail(err)
		}
		if !ok {
			return fail(fmt.Errorf("%s doesn't match what was set; it may have stopped again right after starting", s.Name))
		}
	}
	resp.NewState = withSync(req.PlannedState, true)
	return resp
}

const defaultFeatureTimeout = 30 * time.Minute

func winFeatureSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "Experimental. A Windows Server role or feature. It never reboots: reboot_required says whether Windows wants one, and windows_reboot does it.",
		Attributes: map[string]*configschema.Attribute{
			"id":                       {Type: cty.String, Computed: true},
			"revision":                 revisionAttr(),
			"name":                     {Type: cty.String, Required: true, Description: "Feature name, such as Web-Server."},
			"state":                    {Type: cty.String, Optional: true, Description: "\"present\" (default) or \"absent\"."},
			"include_sub_features":     {Type: cty.Bool, Optional: true, Description: "Also install everything under it."},
			"include_management_tools": {Type: cty.Bool, Optional: true, Description: "Also install its management tools."},
			"timeout":                  {Type: cty.String, Optional: true, Description: "How long to allow. Defaults to \"30m\"."},
			"reboot_required":          {Type: cty.Bool, Computed: true, Description: "Whether Windows reported wanting a reboot after the last change."},
			"in_sync":                  {Type: cty.Bool, Computed: true, Description: "Whether the feature matched at the last refresh."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func winFeatureFrom(v cty.Value) windows.Feature {
	flag := func(a string) bool { x := v.GetAttr(a); return known(x) && x.True() }
	return windows.Feature{
		Name: stringOr(v.GetAttr("name"), ""), Absent: isAbsent(v),
		SubFeatures: flag("include_sub_features"), ManagementTools: flag("include_management_tools"),
	}
}

func validateWinFeature(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() {
		return diags
	}
	diags = diags.Append(validateState(cfg))
	if t := cfg.GetAttr("timeout"); t.IsKnown() {
		if _, err := durationOr(t, defaultFeatureTimeout); err != nil {
			diags = diags.Append(attrError("timeout", err.Error()))
		}
	}
	if n := cfg.GetAttr("name"); known(n) {
		if err := winFeatureFrom(cfg).Validate(); err != nil {
			diags = diags.Append(attrError("name", err.Error()))
		}
	}
	return diags
}

func planWinFeature(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	resp := planSynced(req, "windows_feature", []string{"name"}, []string{"state", "include_sub_features", "include_management_tools"})
	if resp.PlannedState.IsNull() {
		return resp
	}
	vals := resp.PlannedState.AsValueMap()
	if vals["in_sync"].IsKnown() {
		vals["reboot_required"] = req.PriorState.GetAttr("reboot_required")
	} else {
		vals["reboot_required"] = cty.UnknownVal(cty.Bool)
	}
	resp.PlannedState = cty.ObjectVal(vals)
	return resp
}

func readWinFeature(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	resp := providers.ReadResourceResponse{NewState: req.PriorState}
	if req.PriorState.IsNull() {
		return resp
	}
	h, err := winHost(ctx, req.PriorState.GetAttr("ssh"))
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(attrError("ssh", err.Error()))
		return resp
	}
	ok, _, err := windows.FeatureInSync(ctx, h.client, winFeatureFrom(req.PriorState))
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(err)
		return resp
	}
	resp.NewState = withSync(req.PriorState, ok)
	return resp
}

func applyWinFeature(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	var resp providers.ApplyResourceChangeResponse
	if req.PlannedState.IsNull() {
		resp.NewState = req.PlannedState
		return resp
	}
	fail := func(err error) providers.ApplyResourceChangeResponse {
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("windows_feature: %w", err))
		return resp
	}
	f := winFeatureFrom(req.PlannedState)
	if err := f.Validate(); err != nil {
		return fail(err)
	}
	timeout, err := durationOr(req.PlannedState.GetAttr("timeout"), defaultFeatureTimeout)
	if err != nil {
		return fail(err)
	}
	h, err := winHost(ctx, req.PlannedState.GetAttr("ssh"))
	if err != nil {
		return fail(err)
	}
	// Windows servicing takes one change at a time.
	defer lockHost(h, "windows_feature")()
	ok, pending, err := windows.FeatureInSync(ctx, h.client, f)
	if err != nil {
		return fail(err)
	}
	restart := pending
	if !ok {
		if restart, err = windows.ApplyFeature(ctx, h.client, f, timeout); err != nil {
			return fail(fmt.Errorf("changing %s: %w", f.Name, err))
		}
		if ok, _, err = windows.FeatureInSync(ctx, h.client, f); err != nil {
			return fail(err)
		}
		if !ok {
			return fail(fmt.Errorf("%s doesn't match what was asked after the change", f.Name))
		}
	}
	vals := withSync(req.PlannedState, true).AsValueMap()
	vals["reboot_required"] = cty.BoolVal(restart)
	resp.NewState = cty.ObjectVal(vals)
	return resp
}

const defaultUpdateTimeout = 2 * time.Hour

func winUpdateSchema() providers.Schema {
	list := cty.List(cty.String)
	return providers.Schema{Block: &configschema.Block{
		Description: "Experimental. The Windows updates a host should have installed, such as this month's security updates. It never reboots: reboot_required says whether Windows wants one, and windows_reboot does it.",
		Attributes: map[string]*configschema.Attribute{
			"id":              {Type: cty.String, Computed: true},
			"revision":        revisionAttr(),
			"categories":      {Type: list, Optional: true, Description: "Windows Update categories to install, such as SecurityUpdates and CriticalUpdates (the default). Also: Applications, Connectors, DefinitionUpdates, DeveloperKits, Drivers, FeaturePacks, Guidance, ServicePacks, Tools, UpdateRollups, Updates, Upgrades."},
			"accept_list":     {Type: list, Optional: true, Description: "Only these KB numbers, such as KB5034441, from those categories."},
			"reject_list":     {Type: list, Optional: true, Description: "Never these KB numbers."},
			"timeout":         {Type: cty.String, Optional: true, Description: "How long downloading and installing may take. Defaults to \"2h\"."},
			"pending":         {Type: list, Computed: true, Description: "The updates waiting at the last refresh, each as its KB number and title. A plan to install shows them here."},
			"reboot_required": {Type: cty.Bool, Computed: true, Description: "Whether Windows reported wanting a reboot after the last install."},
			"in_sync":         {Type: cty.Bool, Computed: true, Description: "Whether nothing was waiting at the last refresh."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func winUpdateFrom(v cty.Value) windows.Update {
	return windows.Update{Categories: stringList(v.GetAttr("categories")), Accept: stringList(v.GetAttr("accept_list")), Reject: stringList(v.GetAttr("reject_list"))}
}

func validateWinUpdate(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() || !cfg.IsWhollyKnown() {
		return diags
	}
	if _, err := durationOr(cfg.GetAttr("timeout"), defaultUpdateTimeout); err != nil {
		diags = diags.Append(attrError("timeout", err.Error()))
	}
	if err := winUpdateFrom(cfg).Validate(); err != nil {
		diags = diags.Append(attrError("categories", err.Error()))
	}
	return diags
}

// planWinUpdate plans an install when the last refresh found updates
// waiting. pending goes to empty, so the plan lists each update leaving it:
// what will install.
func planWinUpdate(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	resp := planSynced(req, "windows_update", nil, []string{"categories", "accept_list", "reject_list"})
	if resp.PlannedState.IsNull() {
		return resp
	}
	vals := resp.PlannedState.AsValueMap()
	if req.PriorState.IsNull() {
		vals["pending"], vals["reboot_required"] = cty.UnknownVal(cty.List(cty.String)), cty.UnknownVal(cty.Bool)
	} else {
		vals["pending"] = req.PriorState.GetAttr("pending")
		if vals["in_sync"].IsKnown() {
			vals["reboot_required"] = req.PriorState.GetAttr("reboot_required")
		} else {
			vals["pending"] = cty.ListValEmpty(cty.String)
			vals["reboot_required"] = cty.UnknownVal(cty.Bool)
		}
	}
	resp.PlannedState = cty.ObjectVal(vals)
	return resp
}

// planWinUpdateReads names, in the plan of a new step, the updates its
// apply would install. The planned state can't hold them: pending is what
// is still waiting after the apply. So they go in a warning, and only when
// the host can be reached: one that is made in the same apply can't say.
func planWinUpdateReads(ctx context.Context, req providers.PlanResourceChangeRequest, resp *providers.PlanResourceChangeResponse) {
	planned := resp.PlannedState
	if !req.PriorState.IsNull() || planned.IsNull() || !req.ProposedNewState.IsWhollyKnown() {
		return
	}
	h, err := winHost(ctx, planned.GetAttr("ssh"))
	if err != nil {
		log.Printf("[DEBUG] conn3x: windows_update: can't list the updates in the plan: %v", err)
		return
	}
	pending, err := windows.PendingUpdates(ctx, h.client, winUpdateFrom(planned))
	switch {
	case err != nil:
		// The host answered, so this is worth saying; the apply searches again.
		resp.Diagnostics = resp.Diagnostics.Append(tfdiags.SimpleWarning(fmt.Sprintf("windows_update on %s: couldn't list the updates for this plan, so the apply will find out what it installs: %v", h.host, err)))
	case len(pending) == 0:
		resp.Diagnostics = resp.Diagnostics.Append(tfdiags.SimpleWarning(fmt.Sprintf("windows_update on %s: no updates wait in these categories now, so the apply installs nothing", h.host)))
	default:
		resp.Diagnostics = resp.Diagnostics.Append(tfdiags.SimpleWarning(fmt.Sprintf("windows_update on %s: the apply installs these %d updates, as of this plan:\n  %s", h.host, len(pending), strings.Join(pending, "\n  "))))
	}
}

func readWinUpdate(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	resp := providers.ReadResourceResponse{NewState: req.PriorState}
	if req.PriorState.IsNull() {
		return resp
	}
	h, err := winHost(ctx, req.PriorState.GetAttr("ssh"))
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(attrError("ssh", err.Error()))
		return resp
	}
	pending, err := windows.PendingUpdates(ctx, h.client, winUpdateFrom(req.PriorState))
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("windows_update: %w", err))
		return resp
	}
	vals := withSync(req.PriorState, len(pending) == 0).AsValueMap()
	vals["pending"] = stringListVal(pending)
	resp.NewState = cty.ObjectVal(vals)
	return resp
}

func applyWinUpdate(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	var resp providers.ApplyResourceChangeResponse
	if req.PlannedState.IsNull() {
		resp.NewState = req.PlannedState // removing the step installs and removes nothing
		return resp
	}
	fail := func(err error) providers.ApplyResourceChangeResponse {
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("windows_update: %w", err))
		return resp
	}
	u := winUpdateFrom(req.PlannedState)
	timeout, err := durationOr(req.PlannedState.GetAttr("timeout"), defaultUpdateTimeout)
	if err != nil {
		return fail(err)
	}
	h, err := winHost(ctx, req.PlannedState.GetAttr("ssh"))
	if err != nil {
		return fail(err)
	}
	// Windows servicing takes one change at a time.
	defer lockHost(h, "windows_feature")()
	installed, restart, err := windows.ApplyUpdates(ctx, h.client, u, timeout)
	if len(installed) > 0 {
		log.Printf("[INFO] conn3x: windows_update on %s installed: %s", h.host, strings.Join(installed, "; "))
	}
	if err != nil {
		return fail(err)
	}
	vals := withSync(req.PlannedState, true).AsValueMap()
	vals["pending"] = cty.ListValEmpty(cty.String)
	vals["reboot_required"] = cty.BoolVal(restart)
	resp.NewState = cty.ObjectVal(vals)
	return resp
}

func stringListVal(s []string) cty.Value {
	if len(s) == 0 {
		return cty.ListValEmpty(cty.String)
	}
	vals := make([]cty.Value, len(s))
	for i, v := range s {
		vals[i] = cty.StringVal(v)
	}
	return cty.ListVal(vals)
}
