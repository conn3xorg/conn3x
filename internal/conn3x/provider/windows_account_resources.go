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

func winUserSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "Experimental. A local user on a Windows host. Settings left unset are left as they are.",
		Attributes: map[string]*configschema.Attribute{
			"id":          {Type: cty.String, Computed: true},
			"revision":    revisionAttr(),
			"name":        {Type: cty.String, Required: true, Description: "User name, up to 20 characters."},
			"full_name":   {Type: cty.String, Optional: true, Description: "Full name."},
			"description": {Type: cty.String, Optional: true, Description: "Description, up to 48 characters."},
			"disabled":    {Type: cty.Bool, Optional: true, Description: "true disables the account, false enables it."},
			"password_wo": {
				Type: cty.String, Optional: true, WriteOnly: true, Sensitive: true,
				Description: "Password, kept out of plan and state: state records only password_hmac. It's set when the user is made and whenever this value changes. A password changed on the host isn't detected.",
			},
			"password_hmac": {Type: cty.String, Computed: true, Description: "HMAC-SHA256 of password_wo, keyed by CONN3X_HMAC_KEY or ~/.config/conn3x/hmac.key. Null without password_wo."},
			"on_remove":     {Type: cty.String, Optional: true, Computed: true, Description: "What happens on the host when this resource is removed: \"forget\" (default) leaves the user, \"delete\" deletes it and leaves its profile folder."},
			"in_sync":       {Type: cty.Bool, Computed: true, Description: "Whether the user matched at the last refresh."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func optString(v cty.Value) *string {
	if !known(v) {
		return nil
	}
	s := v.AsString()
	return &s
}

func winUserFrom(v cty.Value) windows.User {
	u := windows.User{Name: stringOr(v.GetAttr("name"), ""), FullName: optString(v.GetAttr("full_name")), Description: optString(v.GetAttr("description"))}
	if d := v.GetAttr("disabled"); known(d) {
		b := d.True()
		u.Disabled = &b
	}
	return u
}

// isLogin reports whether a local account is the one Conn3x logs in as, which
// it must never disable or delete: that would lock it out of the host.
func isLogin(conn cty.Value, name string) bool {
	if conn.IsNull() || !conn.IsKnown() {
		return false
	}
	u := conn.GetAttr("user")
	if !known(u) {
		return false
	}
	s := u.AsString()
	if i := strings.LastIndex(s, `\`); i >= 0 {
		s = s[i+1:]
	}
	if i := strings.Index(s, "@"); i >= 0 {
		s = s[:i]
	}
	return strings.EqualFold(s, name)
}

// lockout returns why a user step would lock Conn3x out, or "".
func lockout(v cty.Value, removing bool) string {
	name := stringOr(v.GetAttr("name"), "")
	if name == "" || !isLogin(v.GetAttr("ssh"), name) {
		return ""
	}
	if d := v.GetAttr("disabled"); known(d) && d.True() {
		return fmt.Sprintf("%s is the user Conn3x logs in as; disabling it would lock Conn3x out of the host", name)
	}
	if removing {
		return fmt.Sprintf("%s is the user Conn3x logs in as; deleting it would lock Conn3x out of the host", name)
	}
	return ""
}

func validateWinUser(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() {
		return diags
	}
	diags = diags.Append(validateOnRemove(cfg))
	if pw := cfg.GetAttr("password_wo"); known(pw) && (pw.AsString() == "" || strings.ContainsRune(pw.AsString(), 0)) {
		diags = diags.Append(attrError("password_wo", "password_wo must not be empty or contain NUL"))
	}
	for _, a := range []string{"name", "full_name", "description", "disabled", "on_remove"} {
		if !cfg.GetAttr(a).IsKnown() {
			return diags
		}
	}
	if err := winUserFrom(cfg).Validate(); err != nil {
		return diags.Append(attrError("name", err.Error()))
	}
	r := cfg.GetAttr("on_remove")
	if why := lockout(cfg, known(r) && r.AsString() == onRemoveDelete); why != "" {
		diags = diags.Append(attrError("name", why))
	}
	return diags
}

// winUserID is what a password's HMAC is bound to: the host as well as the
// name, so one password on many hosts doesn't give one HMAC in state.
func winUserID(host, name string) string {
	return "windows_user:" + strings.ToLower(host) + ":" + strings.ToLower(name)
}

func planWinUser(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
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
		if wo.IsKnown() && known(vals["name"]) && known(host) {
			vals["password_hmac"] = cty.StringVal(passwordHMAC(key, winUserID(host.AsString(), vals["name"].AsString()), wo.AsString()))
		}
	}
	req.ProposedNewState = cty.ObjectVal(vals)
	resp = planSyncedFold(req, "windows_user", []string{"name"}, []string{"full_name", "description", "disabled", "password_hmac"})
	if warn != nil {
		resp.Diagnostics = resp.Diagnostics.Append(tfdiags.SimpleWarning(warn.Error()))
	}
	return resp
}

func readWinUser(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	resp := providers.ReadResourceResponse{NewState: req.PriorState}
	if req.PriorState.IsNull() {
		return resp
	}
	h, err := winHost(ctx, req.PriorState.GetAttr("ssh"))
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(attrError("ssh", err.Error()))
		return resp
	}
	u := winUserFrom(req.PriorState)
	a, err := windows.ReadUser(ctx, h.client, u.Name)
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(err)
		return resp
	}
	resp.NewState = withSync(req.PriorState, u.Matches(a))
	return resp
}

func applyWinUser(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	var resp providers.ApplyResourceChangeResponse
	fail := func(err error) providers.ApplyResourceChangeResponse {
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("windows_user: %w", err))
		return resp
	}
	if req.PlannedState.IsNull() {
		resp.NewState = req.PlannedState
		if req.PriorState.IsNull() || req.PriorState.GetAttr("on_remove").AsString() != onRemoveDelete {
			return resp
		}
		if why := lockout(req.PriorState, true); why != "" {
			return fail(fmt.Errorf("%s", why))
		}
		h, err := winHost(ctx, req.PriorState.GetAttr("ssh"))
		if err != nil {
			return fail(err)
		}
		if err := windows.ApplyUserRemove(ctx, h.client, stringOr(req.PriorState.GetAttr("name"), "")); err != nil {
			return fail(err)
		}
		return resp
	}
	planned := req.PlannedState
	u := winUserFrom(planned)
	if err := u.Validate(); err != nil {
		return fail(err)
	}
	if why := lockout(planned, false); why != "" {
		return fail(fmt.Errorf("%s", why))
	}
	vals := planned.AsValueMap()
	vals["password_wo"] = cty.NullVal(cty.String)
	var password *string
	if wo := req.Config.GetAttr("password_wo"); !wo.IsNull() {
		// A saved plan applied elsewhere must use the key it was made with.
		key, err := hmacKey(true)
		if err != nil {
			return fail(err)
		}
		var prior cty.Value
		if !req.PriorState.IsNull() {
			prior = req.PriorState.GetAttr("password_hmac")
		}
		for _, v := range []cty.Value{planned.GetAttr("password_hmac"), prior} {
			if v != cty.NilVal && known(v) {
				if err := checkHMACKey(v.AsString(), key); err != nil {
					return fail(err)
				}
			}
		}
		sum := cty.StringVal(passwordHMAC(key, winUserID(stringOr(planned.GetAttr("ssh").GetAttr("host"), ""), u.Name), wo.AsString()))
		vals["password_hmac"] = sum
		// Set only when it's new to Conn3x: Windows can refuse to reuse a
		// password, and resetting one on every run tells nobody anything.
		if prior == cty.NilVal || !prior.RawEquals(sum) {
			s := wo.AsString()
			password = &s
		}
	}
	h, err := winHost(ctx, planned.GetAttr("ssh"))
	if err != nil {
		return fail(err)
	}
	a, err := windows.ReadUser(ctx, h.client, u.Name)
	if err != nil {
		return fail(err)
	}
	// A user deleted behind Conn3x's back is made again with its password.
	if wo := req.Config.GetAttr("password_wo"); password == nil && !wo.IsNull() && !a.Exists {
		s := wo.AsString()
		password = &s
	}
	if password != nil || !u.Matches(a) {
		if err := windows.ApplyUser(ctx, h.client, u, a, password); err != nil {
			return fail(err)
		}
		if a, err = windows.ReadUser(ctx, h.client, u.Name); err != nil {
			return fail(err)
		}
		if !u.Matches(a) {
			return fail(fmt.Errorf("user %s doesn't match what was set; something else changed it", u.Name))
		}
	}
	vals["in_sync"] = cty.True
	resp.NewState = cty.ObjectVal(vals)
	return resp
}

func winGroupSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "Experimental. A local group on a Windows host, and who is in it. Settings left unset are left as they are.",
		Attributes: map[string]*configschema.Attribute{
			"id":            {Type: cty.String, Computed: true},
			"revision":      revisionAttr(),
			"name":          {Type: cty.String, Required: true, Description: "Group name, such as Remote Desktop Users."},
			"description":   {Type: cty.String, Optional: true, Description: "Description, up to 48 characters."},
			"members":       {Type: cty.Set(cty.String), Optional: true, Description: "Users and groups that must be in it, by name, such as LAB\\alice, or by SID. Others are left in unless authoritative is set."},
			"authoritative": {Type: cty.Bool, Optional: true, Description: "true makes members the complete list: anyone else is taken out. Never the login Conn3x uses."},
			"on_remove":     {Type: cty.String, Optional: true, Computed: true, Description: "What happens on the host when this resource is removed: \"forget\" (default) leaves the group, \"delete\" deletes it."},
			"in_sync":       {Type: cty.Bool, Computed: true, Description: "Whether the group matched at the last refresh."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func winGroupFrom(v cty.Value) windows.Group {
	g := windows.Group{Name: stringOr(v.GetAttr("name"), ""), Description: optString(v.GetAttr("description"))}
	if a := v.GetAttr("authoritative"); known(a) {
		g.Authoritative = a.True()
	}
	if m := v.GetAttr("members"); known(m) {
		g.Members = []string{}
		for it := m.ElementIterator(); it.Next(); {
			_, e := it.Element()
			g.Members = append(g.Members, e.AsString())
		}
	}
	return g
}

func validateWinGroup(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() {
		return diags
	}
	diags = diags.Append(validateOnRemove(cfg))
	for _, a := range []string{"name", "description", "members", "authoritative"} {
		if !cfg.GetAttr(a).IsWhollyKnown() {
			return diags
		}
	}
	if err := winGroupFrom(cfg).Validate(); err != nil {
		diags = diags.Append(attrError("name", err.Error()))
	}
	return diags
}

func planWinGroup(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	return planSyncedFold(req, "windows_group", []string{"name"}, []string{"description", "members", "authoritative"})
}

func readWinGroup(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	resp := providers.ReadResourceResponse{NewState: req.PriorState}
	if req.PriorState.IsNull() {
		return resp
	}
	h, err := winHost(ctx, req.PriorState.GetAttr("ssh"))
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(attrError("ssh", err.Error()))
		return resp
	}
	g := winGroupFrom(req.PriorState)
	a, err := windows.ReadGroup(ctx, h.client, g)
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(err)
		return resp
	}
	resp.NewState = withSync(req.PriorState, g.Matches(a))
	return resp
}

func applyWinGroup(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	var resp providers.ApplyResourceChangeResponse
	fail := func(err error) providers.ApplyResourceChangeResponse {
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("windows_group: %w", err))
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
		if err := windows.ApplyGroupRemove(ctx, h.client, stringOr(req.PriorState.GetAttr("name"), "")); err != nil {
			return fail(err)
		}
		return resp
	}
	g := winGroupFrom(req.PlannedState)
	if err := g.Validate(); err != nil {
		return fail(err)
	}
	h, err := winHost(ctx, req.PlannedState.GetAttr("ssh"))
	if err != nil {
		return fail(err)
	}
	a, err := windows.ReadGroup(ctx, h.client, g)
	if err != nil {
		return fail(err)
	}
	if !g.Matches(a) {
		if err := windows.ApplyGroup(ctx, h.client, g, a); err != nil {
			return fail(err)
		}
		if a, err = windows.ReadGroup(ctx, h.client, g); err != nil {
			return fail(err)
		}
		if !g.Matches(a) {
			return fail(fmt.Errorf("group %s doesn't match what was set; something else changed it", g.Name))
		}
	}
	resp.NewState = withSync(req.PlannedState, true)
	return resp
}
