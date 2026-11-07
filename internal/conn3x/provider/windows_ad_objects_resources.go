// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/conn3x/modules/windows"
	"github.com/opentofu/opentofu/internal/conn3x/modules/windows/ps"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
	"github.com/opentofu/opentofu/internal/providers"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

// OUs, groups and users in Active Directory, run on a domain controller.

const adPathDescription = "Distinguished name of the OU or container it's in, such as OU=Lab,DC=lab,DC=example,DC=com. Unset leaves it where it is, and a new one goes to Windows' default, CN=Users."

func adOnRemove(what string) *configschema.Attribute {
	return &configschema.Attribute{Type: cty.String, Optional: true, Computed: true, Description: fmt.Sprintf("What happens in the domain when this resource is removed: \"forget\" (default) leaves the %s, \"delete\" deletes it.", what)}
}

func optBool(v cty.Value) *bool {
	if !known(v) {
		return nil
	}
	b := v.True()
	return &b
}

// adCheck validates a step once every attribute it reads is known.
func adCheck(cfg cty.Value, attrs []string, check func() (string, error)) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() {
		return diags
	}
	diags = diags.Append(validateOnRemove(cfg))
	for _, a := range attrs {
		if !cfg.GetAttr(a).IsWhollyKnown() {
			return diags
		}
	}
	if attr, err := check(); err != nil {
		diags = diags.Append(attrError(attr, err.Error()))
	}
	return diags
}

func adRead(ctx context.Context, req providers.ReadResourceRequest, matches func(*ssh.Client) (bool, error)) providers.ReadResourceResponse {
	resp := providers.ReadResourceResponse{NewState: req.PriorState}
	if req.PriorState.IsNull() {
		return resp
	}
	h, err := winHost(ctx, req.PriorState.GetAttr("ssh"))
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(attrError("ssh", err.Error()))
		return resp
	}
	ok, err := matches(h.client)
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(err)
		return resp
	}
	resp.NewState = withSync(req.PriorState, ok)
	return resp
}

// adRemove runs remove when the step goes with on_remove = "delete".
func adRemove(ctx context.Context, req providers.ApplyResourceChangeRequest, kind string, remove func(*ssh.Client) error) providers.ApplyResourceChangeResponse {
	resp := providers.ApplyResourceChangeResponse{NewState: req.PlannedState}
	if req.PriorState.IsNull() || req.PriorState.GetAttr("on_remove").AsString() != onRemoveDelete {
		return resp
	}
	h, err := winHost(ctx, req.PriorState.GetAttr("ssh"))
	if err == nil {
		err = adWrite(ctx, h.client, func() error { return remove(h.client) })
	}
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("%s: %w", kind, err))
	}
	return resp
}

// adWrite runs write once AD on the DC answers. A write that got no answer,
// as one can straight after a DC's reboot, may still have landed, so once AD
// answers again it runs one more time; write reads first and skips what's done.
func adWrite(ctx context.Context, c ps.Runner, write func() error) error {
	if err := windows.WaitAD(ctx, c, windows.ADReadyLimit); err != nil {
		return err
	}
	err := write()
	var noResult *ps.NoResultError
	if !errors.As(err, &noResult) || ctx.Err() != nil {
		return err
	}
	if werr := windows.WaitAD(ctx, c, windows.ADReadyLimit); werr != nil {
		return fmt.Errorf("%w, and then %w", err, werr)
	}
	return write()
}

func winADOUSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "Experimental. An organizational unit in Active Directory, run on a domain controller. Settings left unset are left as they are.",
		Attributes: map[string]*configschema.Attribute{
			"id":          {Type: cty.String, Computed: true},
			"revision":    revisionAttr(),
			"name":        {Type: cty.String, Required: true, Description: "OU name, such as Servers."},
			"path":        {Type: cty.String, Optional: true, Description: "Distinguished name of the parent, such as OU=Lab,DC=lab,DC=example,DC=com. Unset is the top of the domain. Changing it makes a new OU."},
			"description": {Type: cty.String, Optional: true, Description: "Description."},
			"protected":   {Type: cty.Bool, Optional: true, Description: "Whether the OU is protected from accidental deletion. Unset, a new OU is protected, as Windows does."},
			"on_remove":   adOnRemove("OU; it never deletes one that's protected or not empty"),
			"in_sync":     {Type: cty.Bool, Computed: true, Description: "Whether the OU matched at the last refresh."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func winADOUFrom(v cty.Value) windows.OU {
	return windows.OU{Name: stringOr(v.GetAttr("name"), ""), Path: stringOr(v.GetAttr("path"), ""),
		Description: optString(v.GetAttr("description")), Protected: optBool(v.GetAttr("protected"))}
}

func validateWinADOU(cfg cty.Value) tfdiags.Diagnostics {
	return adCheck(cfg, []string{"name", "path", "description", "protected"}, func() (string, error) { return winADOUFrom(cfg).Check() })
}

func planWinADOU(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	return planSyncedFold(req, "windows_ad_ou", []string{"name", "path"}, []string{"description", "protected"})
}

func readWinADOU(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	o := winADOUFrom(req.PriorState)
	return adRead(ctx, req, func(c *ssh.Client) (bool, error) {
		a, err := windows.ReadOU(ctx, c, o)
		return o.Matches(a), err
	})
}

func applyWinADOU(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	if req.PlannedState.IsNull() {
		return adRemove(ctx, req, "windows_ad_ou", func(c *ssh.Client) error { return windows.ApplyOURemove(ctx, c, winADOUFrom(req.PriorState)) })
	}
	var resp providers.ApplyResourceChangeResponse
	fail := func(err error) providers.ApplyResourceChangeResponse {
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("windows_ad_ou: %w", err))
		return resp
	}
	o := winADOUFrom(req.PlannedState)
	if _, err := o.Check(); err != nil {
		return fail(err)
	}
	h, err := winHost(ctx, req.PlannedState.GetAttr("ssh"))
	if err != nil {
		return fail(err)
	}
	wrote := false
	err = adWrite(ctx, h.client, func() error {
		a, err := windows.ReadOU(ctx, h.client, o)
		if err != nil || o.Matches(a) {
			return err
		}
		wrote = true
		return windows.ApplyOU(ctx, h.client, o, a)
	})
	if err != nil {
		return fail(err)
	}
	if wrote {
		a, err := windows.ReadOU(ctx, h.client, o)
		if err != nil {
			return fail(err)
		}
		if !o.Matches(a) {
			return fail(fmt.Errorf("OU %s doesn't match what was set; something else changed it", o.Name))
		}
	}
	resp.NewState = withSync(req.PlannedState, true)
	return resp
}

func winADGroupSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "Experimental. A group in Active Directory, and who is in it, run on a domain controller. Settings left unset are left as they are.",
		Attributes: map[string]*configschema.Attribute{
			"id":            {Type: cty.String, Computed: true},
			"revision":      revisionAttr(),
			"name":          {Type: cty.String, Required: true, Description: "Group name, used as both its name and its sAMAccountName, such as AppAdmins."},
			"path":          {Type: cty.String, Optional: true, Description: adPathDescription + " A group found elsewhere is moved."},
			"scope":         {Type: cty.String, Optional: true, Description: "\"domainlocal\", \"global\" or \"universal\". Unset, a new group is global."},
			"category":      {Type: cty.String, Optional: true, Description: "\"security\" or \"distribution\". Unset, a new group is a security group."},
			"description":   {Type: cty.String, Optional: true, Description: "Description."},
			"members":       {Type: cty.Set(cty.String), Optional: true, Description: "Accounts that must be in it, by sAMAccountName in this domain: users, groups, and computers with their trailing $, such as alice, ops or web1$. Others are left in unless authoritative is set."},
			"authoritative": {Type: cty.Bool, Optional: true, Description: "true makes members the complete list: anyone else is taken out. Never the login Conn3x uses, in a group it gets its rights through."},
			"on_remove":     adOnRemove("group"),
			"in_sync":       {Type: cty.Bool, Computed: true, Description: "Whether the group matched at the last refresh."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func winADGroupFrom(v cty.Value) windows.ADGroup {
	g := windows.ADGroup{Name: stringOr(v.GetAttr("name"), ""), Path: stringOr(v.GetAttr("path"), ""),
		Scope: stringOr(v.GetAttr("scope"), ""), Category: stringOr(v.GetAttr("category"), ""), Description: optString(v.GetAttr("description"))}
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

func validateWinADGroup(cfg cty.Value) tfdiags.Diagnostics {
	return adCheck(cfg, []string{"name", "path", "scope", "category", "description", "members", "authoritative"}, func() (string, error) { return winADGroupFrom(cfg).Check() })
}

func planWinADGroup(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	return planSyncedFold(req, "windows_ad_group", []string{"name"}, []string{"path", "scope", "category", "description", "members", "authoritative"})
}

func readWinADGroup(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	g := winADGroupFrom(req.PriorState)
	return adRead(ctx, req, func(c *ssh.Client) (bool, error) {
		a, err := windows.ReadADGroup(ctx, c, g)
		return g.Matches(a), err
	})
}

func applyWinADGroup(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	if req.PlannedState.IsNull() {
		return adRemove(ctx, req, "windows_ad_group", func(c *ssh.Client) error {
			return windows.ApplyADGroupRemove(ctx, c, stringOr(req.PriorState.GetAttr("name"), ""))
		})
	}
	var resp providers.ApplyResourceChangeResponse
	fail := func(err error) providers.ApplyResourceChangeResponse {
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("windows_ad_group: %w", err))
		return resp
	}
	g := winADGroupFrom(req.PlannedState)
	if _, err := g.Check(); err != nil {
		return fail(err)
	}
	h, err := winHost(ctx, req.PlannedState.GetAttr("ssh"))
	if err != nil {
		return fail(err)
	}
	wrote := false
	err = adWrite(ctx, h.client, func() error {
		a, err := windows.ReadADGroup(ctx, h.client, g)
		if err != nil || g.Matches(a) {
			return err
		}
		wrote = true
		return windows.ApplyADGroup(ctx, h.client, g, a)
	})
	if err != nil {
		return fail(err)
	}
	if wrote {
		a, err := windows.ReadADGroup(ctx, h.client, g)
		if err != nil {
			return fail(err)
		}
		if !g.Matches(a) {
			return fail(fmt.Errorf("group %s doesn't match what was set; something else changed it", g.Name))
		}
	}
	resp.NewState = withSync(req.PlannedState, true)
	return resp
}

func winADUserSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "Experimental. A user in Active Directory, run on a domain controller. Settings left unset are left as they are. Groups are set with windows_ad_group.",
		Attributes: map[string]*configschema.Attribute{
			"id":                     {Type: cty.String, Computed: true},
			"revision":               revisionAttr(),
			"name":                   {Type: cty.String, Required: true, Description: "Logon name, used as both its sAMAccountName and its name in the directory, up to 20 characters, such as alice."},
			"path":                   {Type: cty.String, Optional: true, Description: adPathDescription + " A user found elsewhere is moved."},
			"upn":                    {Type: cty.String, Optional: true, Description: "User principal name, such as alice@lab.example.com."},
			"given_name":             {Type: cty.String, Optional: true, Description: "First name."},
			"surname":                {Type: cty.String, Optional: true, Description: "Last name."},
			"display_name":           {Type: cty.String, Optional: true, Description: "Display name, such as Alice Smith."},
			"description":            {Type: cty.String, Optional: true, Description: "Description."},
			"enabled":                {Type: cty.Bool, Optional: true, Description: "true enables the account, false disables it. Unset, a new user is enabled when it has password_wo, and disabled when it doesn't."},
			"password_never_expires": {Type: cty.Bool, Optional: true, Description: "true sets the password never to expire."},
			"password_wo": {
				Type: cty.String, Optional: true, WriteOnly: true, Sensitive: true,
				Description: "Password, kept out of plan and state: state records only password_hmac. It's set when the user is made and whenever this value changes. A password changed in the domain isn't detected.",
			},
			"password_hmac": {Type: cty.String, Computed: true, Description: "HMAC-SHA256 of password_wo, keyed by CONN3X_HMAC_KEY or ~/.config/conn3x/hmac.key. Null without password_wo."},
			"on_remove":     adOnRemove("user"),
			"in_sync":       {Type: cty.Bool, Computed: true, Description: "Whether the user matched at the last refresh."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

var adUserSettings = []string{"path", "upn", "given_name", "surname", "display_name", "description", "enabled", "password_never_expires"}

func winADUserFrom(v cty.Value) windows.ADUser {
	return windows.ADUser{
		Name: stringOr(v.GetAttr("name"), ""), Path: stringOr(v.GetAttr("path"), ""),
		UPN: optString(v.GetAttr("upn")), GivenName: optString(v.GetAttr("given_name")), Surname: optString(v.GetAttr("surname")),
		DisplayName: optString(v.GetAttr("display_name")), Description: optString(v.GetAttr("description")),
		Enabled: optBool(v.GetAttr("enabled")), PasswordNeverExpires: optBool(v.GetAttr("password_never_expires")),
	}
}

// adLockout returns why a user step would lock Conn3x out, or "". On a domain
// controller the bare login name is the domain account.
func adLockout(v cty.Value, removing bool) string {
	name := stringOr(v.GetAttr("name"), "")
	if name == "" || !isLogin(v.GetAttr("ssh"), name) {
		return ""
	}
	if e := v.GetAttr("enabled"); known(e) && e.False() {
		return fmt.Sprintf("%s is the user Conn3x logs in as; disabling it would lock Conn3x out of the host", name)
	}
	if removing {
		return fmt.Sprintf("%s is the user Conn3x logs in as; deleting it would lock Conn3x out of the host", name)
	}
	return ""
}

func validateWinADUser(cfg cty.Value) tfdiags.Diagnostics {
	if cfg.IsNull() {
		return nil
	}
	var diags tfdiags.Diagnostics
	if pw := cfg.GetAttr("password_wo"); known(pw) && (pw.AsString() == "" || strings.ContainsRune(pw.AsString(), 0)) {
		diags = diags.Append(attrError("password_wo", "password_wo must not be empty or contain NUL"))
	}
	diags = diags.Append(adCheck(cfg, append([]string{"name", "on_remove"}, adUserSettings...), func() (string, error) {
		if _, err := winADUserFrom(cfg).Check(); err != nil {
			return "name", err
		}
		r := cfg.GetAttr("on_remove")
		if why := adLockout(cfg, known(r) && r.AsString() == onRemoveDelete); why != "" {
			return "name", fmt.Errorf("%s", why)
		}
		return "", nil
	}))
	return diags
}

func planWinADUser(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	return planWithPassword(req, "windows_ad_user", append(adUserSettings, "password_hmac"))
}

func readWinADUser(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	u := winADUserFrom(req.PriorState)
	return adRead(ctx, req, func(c *ssh.Client) (bool, error) {
		a, err := windows.ReadADUser(ctx, c, u)
		return u.Matches(a), err
	})
}

func applyWinADUser(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	var resp providers.ApplyResourceChangeResponse
	fail := func(err error) providers.ApplyResourceChangeResponse {
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("windows_ad_user: %w", err))
		return resp
	}
	if req.PlannedState.IsNull() {
		if why := adLockout(req.PriorState, true); why != "" && !req.PriorState.IsNull() && req.PriorState.GetAttr("on_remove").AsString() == onRemoveDelete {
			return fail(fmt.Errorf("%s", why))
		}
		return adRemove(ctx, req, "windows_ad_user", func(c *ssh.Client) error {
			return windows.ApplyADUserRemove(ctx, c, stringOr(req.PriorState.GetAttr("name"), ""))
		})
	}
	planned := req.PlannedState
	u := winADUserFrom(planned)
	if _, err := u.Check(); err != nil {
		return fail(err)
	}
	if why := adLockout(planned, false); why != "" {
		return fail(fmt.Errorf("%s", why))
	}
	vals := planned.AsValueMap()
	vals["password_wo"] = cty.NullVal(cty.String)
	sum, password, err := passwordAtApply(req, "windows_ad_user", u.Name)
	if err != nil {
		return fail(err)
	}
	vals["password_hmac"] = sum
	h, err := winHost(ctx, planned.GetAttr("ssh"))
	if err != nil {
		return fail(err)
	}
	wrote := false
	err = adWrite(ctx, h.client, func() error {
		a, err := windows.ReadADUser(ctx, h.client, u)
		if err != nil {
			return err
		}
		pw := password
		// A user deleted behind Conn3x's back is made again with its password.
		if wo := req.Config.GetAttr("password_wo"); pw == nil && !wo.IsNull() && !a.Exists {
			s := wo.AsString()
			pw = &s
		}
		if pw == nil && u.Matches(a) {
			return nil
		}
		wrote = true
		return windows.ApplyADUser(ctx, h.client, u, a, pw)
	})
	if err != nil {
		return fail(err)
	}
	if wrote {
		a, err := windows.ReadADUser(ctx, h.client, u)
		if err != nil {
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
