// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/zclconf/go-cty/cty"
	gossh "golang.org/x/crypto/ssh"

	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/conn3x/modules/account"
	"github.com/opentofu/opentofu/internal/conn3x/modules/sshkey"
	"github.com/opentofu/opentofu/internal/providers"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

func authorizedKeySchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "One public key in a user's ~/.ssh/authorized_keys.",
		Attributes: map[string]*configschema.Attribute{
			"id":        {Type: cty.String, Computed: true},
			"revision":  revisionAttr(),
			"user":      {Type: cty.String, Required: true, Description: "The account the key logs in as."},
			"key":       {Type: cty.String, Required: true, Description: "Public key, in authorized_keys format. With exclusive, every key the user may log in with, one per line."},
			"exclusive": {Type: cty.Bool, Optional: true, Description: "true makes the user's authorized_keys exactly the keys in key: any other key is removed, and the plan says how many. Conn3x refuses to take away the key it logs in with."},
			"unlisted":  {Type: cty.List(cty.String), Computed: true, Description: "With exclusive, the keys in authorized_keys that key doesn't list, by type and SHA-256 fingerprint, as of the last refresh. Apply removes them."},
			"state":     {Type: cty.String, Optional: true, Description: "\"present\" (default) or \"absent\"."},
			"on_remove": {Type: cty.String, Optional: true, Computed: true, Description: "\"delete\" (default) removes the key, so a rotated key stops working; \"forget\" leaves it."},
			"in_sync":   {Type: cty.Bool, Computed: true, Description: "Whether authorized_keys already matches."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func keyPresent(v cty.Value) bool { return stringOr(v.GetAttr("state"), "present") != "absent" }

func keyExclusive(v cty.Value) bool { e := v.GetAttr("exclusive"); return known(e) && e.True() }

func validateAuthorizedKey(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() || !cfg.IsWhollyKnown() {
		return diags
	}
	diags = diags.Append(validateOnRemove(cfg))
	if s := stringOr(cfg.GetAttr("state"), "present"); s != "present" && s != "absent" {
		diags = diags.Append(attrError("state", fmt.Sprintf("state must be \"present\" or \"absent\", not %q", s)))
	}
	if err := (account.UserSpec{Name: cfg.GetAttr("user").AsString()}).Validate(); err != nil {
		diags = diags.Append(attrError("user", err.Error()))
	}
	if !keyExclusive(cfg) {
		if _, err := sshkey.Edit("", cfg.GetAttr("key").AsString(), true); err != nil {
			diags = diags.Append(attrError("key", err.Error()))
		}
		return diags
	}
	if _, _, err := sshkey.Keys(cfg.GetAttr("key").AsString()); err != nil {
		diags = diags.Append(attrError("key", err.Error()))
	}
	if !keyPresent(cfg) {
		diags = diags.Append(attrError("exclusive", "exclusive keeps the keys in key; it can't go with state = \"absent\""))
	}
	if stringOr(cfg.GetAttr("on_remove"), "") == onRemoveDelete {
		diags = diags.Append(attrError("on_remove", "an exclusive step leaves authorized_keys as it is when it's removed: deleting every key it lists would lock out everyone it was keeping in, Conn3x among them"))
	}
	return diags
}

func planAuthorizedKey(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	var resp providers.PlanResourceChangeResponse
	if req.ProposedNewState.IsNull() {
		resp.PlannedState = req.ProposedNewState
		return resp
	}
	if keyExclusive(req.ProposedNewState) && req.ProposedNewState.GetAttr("on_remove").IsNull() {
		// Removing an exclusive step leaves the file, so its default is forget.
		v := req.ProposedNewState.AsValueMap()
		v["on_remove"] = cty.StringVal(onRemoveForget)
		req.ProposedNewState = cty.ObjectVal(v)
	}
	exclusive := keyExclusive(req.ProposedNewState)
	vals := deleteByDefault(req).ProposedNewState.AsValueMap()
	host := req.ProposedNewState.GetAttr("ssh").GetAttr("host")
	if user := vals["user"]; user.IsKnown() {
		vals["id"] = planID(req, "authorized_key", user.AsString())
	} else {
		vals["id"] = cty.UnknownVal(cty.String)
	}
	stale := req.PriorState.IsNull()
	if !stale {
		keys := []string{"user", "key"}
		if exclusive {
			// Changing the list is an update: replacing would first remove
			// the old keys, and with them the way in.
			keys = []string{"user"}
			if !req.PriorState.GetAttr("key").RawEquals(vals["key"]) {
				stale = true
			}
			if u := req.PriorState.GetAttr("unlisted"); !known(u) || u.LengthInt() > 0 {
				stale = true
			}
		}
		for _, a := range keys {
			if !req.PriorState.GetAttr(a).RawEquals(vals[a]) {
				resp.RequiresReplace = append(resp.RequiresReplace, cty.GetAttrPath(a))
				stale = true
			}
		}
		if !req.PriorState.GetAttr("ssh").GetAttr("host").RawEquals(host) {
			resp.RequiresReplace = append(resp.RequiresReplace, cty.GetAttrPath("ssh").GetAttr("host"))
		}
		if s := req.PriorState.GetAttr("in_sync"); !known(s) || s.False() || !req.PriorState.GetAttr("state").RawEquals(vals["state"]) {
			stale = true
		}
	}
	vals["in_sync"] = cty.True
	if stale {
		vals["in_sync"] = cty.UnknownVal(cty.Bool)
	}
	vals["unlisted"] = cty.NullVal(cty.List(cty.String))
	if exclusive {
		vals["unlisted"] = cty.ListValEmpty(cty.String)
	}
	resp.PlannedState = cty.ObjectVal(vals)
	return resp
}

// unlistedVal is what state keeps of the keys an exclusive step doesn't
// list: type and fingerprint, never the comment.
func unlistedVal(gone []sshkey.Unlisted) cty.Value {
	if len(gone) == 0 {
		return cty.ListValEmpty(cty.String)
	}
	vals := make([]cty.Value, len(gone))
	for i, g := range gone {
		vals[i] = cty.StringVal(g.String())
	}
	return cty.ListVal(vals)
}

func readAuthorizedKey(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	var gone []sshkey.Unlisted
	resp := readPathResource(ctx, req, func(ctx context.Context, h *hostConn, prior cty.Value) (cty.Value, error) {
		vals := prior.AsValueMap()
		loc, err := sshkey.Locate(ctx, h, prior.GetAttr("user").AsString())
		if err != nil {
			vals["in_sync"] = cty.False
			return cty.ObjectVal(vals), nil
		}
		content, err := sshkey.Read(ctx, h, loc)
		if err != nil {
			return cty.NilVal, err
		}
		var edited string
		if keyExclusive(prior) {
			edited, gone, err = sshkey.EditExclusive(content, prior.GetAttr("key").AsString())
			vals["unlisted"] = unlistedVal(gone)
		} else {
			edited, err = sshkey.Edit(content, prior.GetAttr("key").AsString(), keyPresent(prior))
		}
		if err != nil {
			return cty.NilVal, err
		}
		vals["in_sync"] = cty.BoolVal(edited == content)
		return cty.ObjectVal(vals), nil
	})
	if len(gone) > 0 && !resp.Diagnostics.HasErrors() {
		// The comments are named here, where they aren't kept.
		var names []string
		for _, g := range gone {
			names = append(names, strings.TrimSpace(g.Comment+" ("+g.String()+")"))
		}
		user := req.PriorState.GetAttr("user").AsString()
		resp.Diagnostics = resp.Diagnostics.Append(tfdiags.SimpleWarning(fmt.Sprintf(
			"%s's authorized_keys has %d key(s) the exclusive step doesn't list, which apply removes: %s", user, len(gone), strings.Join(names, ", "))))
	}
	return resp
}

// keepsLogin refuses an exclusive list that leaves out the key Conn3x logged
// in with, when the step's user is the account it logs in as: the next run
// couldn't reach the host.
func keepsLogin(h *hostConn, v cty.Value, ids []string) error {
	cfg, err := sshConfig(v.GetAttr("ssh"))
	if err != nil || cfg.User != v.GetAttr("user").AsString() {
		return err
	}
	k := h.client.LoginKey()
	if k == nil {
		return fmt.Errorf("Conn3x logs in as %s, and can't tell which key it used, so it won't make that account's keys exclusive", cfg.User)
	}
	if _, ok := k.(*gossh.Certificate); ok {
		// sshd takes a certificate through its CA, not an authorized_keys
		// line for the key, so no list could be checked against it.
		return fmt.Errorf("Conn3x logs in as %s with an SSH certificate, which sshd trusts through its CA rather than a line in authorized_keys, so Conn3x can't tell whether the list keeps it in; make another account's keys exclusive, or log in as another account to do this one", cfg.User)
	}
	if slices.Contains(ids, string(gossh.MarshalAuthorizedKey(k))) {
		return nil
	}
	return fmt.Errorf("Conn3x logs in as %s with the key %s %s, which key doesn't list, so the next run couldn't log in; add it to key, or log in as another account", cfg.User, k.Type(), gossh.FingerprintSHA256(k))
}

func applyAuthorizedKey(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	run := func(ctx context.Context, h *hostConn, v cty.Value, present bool) error {
		loc, err := sshkey.Locate(ctx, h, v.GetAttr("user").AsString())
		if err != nil {
			return err
		}
		if !keyExclusive(v) {
			return sshkey.Apply(ctx, h, loc, v.GetAttr("key").AsString(), present)
		}
		if !present {
			return nil // removing an exclusive step leaves the file
		}
		_, ids, err := sshkey.Keys(v.GetAttr("key").AsString())
		if err != nil {
			return err
		}
		if err := keepsLogin(h, v, ids); err != nil {
			return err
		}
		content, err := sshkey.Read(ctx, h, loc)
		if err != nil {
			return err
		}
		edited, _, err := sshkey.EditExclusive(content, v.GetAttr("key").AsString())
		if err != nil || edited == content {
			return err
		}
		return sshkey.Write(ctx, h, loc, edited)
	}
	return applyPathResource(ctx, req,
		func(ctx context.Context, h *hostConn, planned cty.Value) (cty.Value, error) {
			if err := run(ctx, h, planned, keyPresent(planned)); err != nil {
				return cty.NilVal, fmt.Errorf("authorized key for %s: %w", planned.GetAttr("user").AsString(), err)
			}
			vals := planned.AsValueMap()
			vals["in_sync"] = cty.True
			if keyExclusive(planned) {
				vals["unlisted"] = cty.ListValEmpty(cty.String)
			}
			return cty.ObjectVal(vals), nil
		},
		func(ctx context.Context, h *hostConn, prior cty.Value) error { return run(ctx, h, prior, false) })
}
