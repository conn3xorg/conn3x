// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"errors"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/conn3x/modules/htpasswd"
	"github.com/opentofu/opentofu/internal/providers"
)

// htpasswdKind is one user's line in a password file. password_wo never
// reaches state: password_hmac records it, so a new password plans a
// change, and the read checks that the user's line is there.
var htpasswdKind = editKind{
	name: "htpasswd",
	desc: "One user's line in an Apache-style password file, as Apache's AuthUserFile and nginx's auth_basic_user_file read it. The password is hashed with bcrypt on this machine, so the host needs neither htpasswd nor passlib.",
	attrs: map[string]*configschema.Attribute{
		"name":          {Type: cty.String, Required: true, Description: "The user name."},
		"password_wo":   {Type: cty.String, Optional: true, WriteOnly: true, Sensitive: true, Description: "The user's password, up to 72 bytes. It's hashed with bcrypt and never stored in state. Required."},
		"password_hmac": {Type: cty.String, Computed: true, Description: "An HMAC of the password, so a new password plans a change without the password being stored."},
	},
	edit: func(v cty.Value) func(string) (string, error) {
		name := stringOr(v.GetAttr("name"), "")
		return func(s string) (string, error) {
			if _, ok := htpasswd.Find(s, name); ok {
				return s, nil
			}
			// What a read compares with: any change means out of sync.
			return htpasswd.Set(s, name, "*"), nil
		}
	},
	remove: func(v cty.Value) func(string) (string, error) {
		name := stringOr(v.GetAttr("name"), "")
		return func(s string) (string, error) { return htpasswd.Remove(s, name), nil }
	},
	check: func(v cty.Value) error {
		if err := htpasswd.ValidateName(stringOr(v.GetAttr("name"), "")); err != nil {
			return err
		}
		pw := v.GetAttr("password_wo")
		if pw.IsNull() {
			return errors.New("password_wo is required")
		}
		if pw.IsKnown() {
			return htpasswd.ValidatePassword(pw.AsString())
		}
		return nil
	},
}

func planHtpasswd(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	return planPasswordAs(req, "htpasswd", nil, func(req providers.PlanResourceChangeRequest, _ string, _, _ []string) providers.PlanResourceChangeResponse {
		return htpasswdKind.plan(req)
	}, passwordHMAC)
}

func applyHtpasswd(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	k := htpasswdKind
	k.applyEdit = func(planned, prior cty.Value) func(string) (string, error) {
		name := stringOr(planned.GetAttr("name"), "")
		samePassword := !prior.IsNull() && prior.GetAttr("password_hmac").RawEquals(planned.GetAttr("password_hmac")) &&
			prior.GetAttr("name").RawEquals(planned.GetAttr("name"))
		return func(s string) (string, error) {
			// A change to mode or owner keeps the hash that's there.
			if _, ok := htpasswd.Find(s, name); ok && samePassword {
				return s, nil
			}
			hash, err := htpasswd.Hash(stringOr(req.Config.GetAttr("password_wo"), ""))
			if err != nil {
				return "", err
			}
			// A renamed user's old line goes, so the old name can't still
			// log in with the old password.
			if !prior.IsNull() {
				if old := stringOr(prior.GetAttr("name"), ""); old != "" && old != name {
					return htpasswd.Rename(s, old, name, hash), nil
				}
			}
			return htpasswd.Set(s, name, hash), nil
		}
	}
	return k.apply(ctx, req)
}
