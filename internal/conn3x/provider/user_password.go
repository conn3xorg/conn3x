// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/conn3x/modules/account"
	"github.com/opentofu/opentofu/internal/conn3x/modules/eos"
	"github.com/opentofu/opentofu/internal/providers"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

// A user step's password_wo is hashed here, as eos_user's is, into the
// $6$ hash /etc/shadow holds, and state keeps only password_hmac, an HMAC
// of that hash. The salt comes from the key and passwordID, which names
// the host and the user, so the same password gives the same hash for one
// account, which a refresh can compare, and different hashes elsewhere, so
// one /etc/shadow doesn't show who else shares a password.

func userPasswordID(v cty.Value) string {
	return passwordID("user", stringOr(v.GetAttr("ssh").GetAttr("host"), ""), stringOr(v.GetAttr("name"), ""))
}

func userSecret(key []byte, id, password string) string {
	salt := hmac.New(sha256.New, key)
	salt.Write([]byte("conn3x user salt\x00" + passwordHMAC(key, id, password)))
	return eos.SecretHash(password, eos.CryptSalt(salt.Sum(nil)))
}

// userPasswordInput is the step's password: password_hash_wo, a hash to
// set as it is, or password_wo, hashed here. Null when neither is set.
func userPasswordInput(cfg cty.Value) (pw cty.Value, isHash bool) {
	if h := cfg.GetAttr("password_hash_wo"); !h.IsNull() {
		return h, true
	}
	return cfg.GetAttr("password_wo"), false
}

// userHash is the hash the host should hold for pw.
func userHash(key []byte, id, pw string, isHash bool) string {
	if isHash {
		return pw
	}
	return userSecret(key, id, pw)
}

// userSecretHMAC is what password_hmac records for a host's hash.
func userSecretHMAC(key []byte, id, hash string) string {
	return passwordTag + contentHMAC(key, id, "user secret:"+hash)
}

// validateUserPassword refuses password_wo on a step that can't read
// /etc/shadow, which needs root: a refresh couldn't say whether the host
// still has the password, and the apply couldn't set it.
func validateUserPassword(cfg cty.Value) error {
	pw, isHash := userPasswordInput(cfg)
	if pw.IsNull() {
		if b := cfg.GetAttr("password_on_create"); known(b) && b.True() {
			return errors.New("password_on_create needs password_wo or password_hash_wo")
		}
		return nil
	}
	if isHash && !cfg.GetAttr("password_wo").IsNull() {
		return errors.New("set password_wo or password_hash_wo, not both")
	}
	// The value isn't echoed: a password given here by mistake would be.
	if isHash && pw.IsKnown() && !account.IsHash(pw.AsString()) {
		return errors.New("password_hash_wo isn't a crypt hash as /etc/shadow holds one, such as $6$… or $y$…; to give the password itself, use password_wo")
	}
	conn := cfg.GetAttr("ssh")
	if conn.IsNull() || !conn.IsWhollyKnown() {
		return nil
	}
	if b := conn.GetAttr("become"); known(b) && b.True() {
		return nil
	}
	// An unset user may come from ssh_config_file, as User root often does;
	// ErrNeedsRoot then says what to do at refresh or apply.
	if u := conn.GetAttr("user"); u.IsNull() || u.AsString() == "root" {
		return nil
	}
	return errors.New("a password needs root to read and set /etc/shadow: log in as root, or set become = true in the ssh block")
}

// planUserPassword plans password_hmac: what the host should hold for
// password_wo, which plans a change when a refresh found another. With
// password_on_create, a user that already exists keeps what it has. With no
// password_wo, the password is left alone and nothing is compared.
func planUserPassword(req providers.PlanResourceChangeRequest, resp *providers.PlanResourceChangeResponse) {
	if resp.PlannedState.IsNull() {
		return
	}
	vals := resp.PlannedState.AsValueMap()
	vals["password_wo"], vals["password_hash_wo"] = cty.NullVal(cty.String), cty.NullVal(cty.String)
	prior := cty.NullVal(cty.String)
	if !req.PriorState.IsNull() {
		prior = req.PriorState.GetAttr("password_hmac")
	}
	vals["password_hmac"] = prior
	wo, isHash := userPasswordInput(req.Config)
	if wo.IsNull() {
		// The password is left alone, so nothing is read or compared.
		vals["password_hmac"] = cty.NullVal(cty.String)
	}
	onCreate := known(vals["password_on_create"]) && vals["password_on_create"].True()
	if !wo.IsNull() && (!onCreate || req.PriorState.IsNull()) {
		vals["password_hmac"] = cty.UnknownVal(cty.String)
		key, err := hmacKey(true)
		if err == nil && known(prior) {
			err = checkHMACKey(prior.AsString(), key)
		}
		if err != nil {
			resp.Diagnostics = resp.Diagnostics.Append(attrError("password_wo", err.Error()))
			return
		}
		if w := hmacKeyPermissionWarning(); w != nil {
			resp.Diagnostics = resp.Diagnostics.Append(tfdiags.SimpleWarning(w.Error()))
		}
		planned := cty.ObjectVal(vals)
		if wo.IsKnown() && known(vals["name"]) && known(planned.GetAttr("ssh").GetAttr("host")) {
			id := userPasswordID(planned)
			vals["password_hmac"] = cty.StringVal(userSecretHMAC(key, id, userHash(key, id, wo.AsString(), isHash)))
		}
	}
	resp.PlannedState = cty.ObjectVal(vals)
}

// refreshUserPassword records the HMAC of the hash the host holds, so a
// password changed by hand plans a change back. Without a stored HMAC, or
// the key that made it, nothing is compared.
func refreshUserPassword(ctx context.Context, h *hostConn, state cty.Value) (cty.Value, tfdiags.Diagnostics) {
	var diags tfdiags.Diagnostics
	stored := state.GetAttr("password_hmac")
	if !known(stored) {
		return state, diags
	}
	key, err := hmacKey(false)
	if err != nil || checkHMACKey(stored.AsString(), key) != nil {
		return state, diags
	}
	name := stringOr(state.GetAttr("name"), "")
	hash, err := account.ReadPasswordHash(ctx, h, name)
	// A locked account keeps its hash behind a !: the password is still
	// the one set, and the lock is someone's choice to keep.
	hash, _ = account.Locked(hash)
	if err != nil {
		// Not knowing isn't in sync: say why, and plan to set it again.
		diags = diags.Append(tfdiags.SimpleWarning(fmt.Sprintf("user %s: can't check its password: %s", name, err)))
		hash = ""
	}
	vals := state.AsValueMap()
	vals["password_hmac"] = cty.StringVal(userSecretHMAC(key, userPasswordID(state), hash))
	if !hmac.Equal([]byte(vals["password_hmac"].AsString()), []byte(stored.AsString())) {
		return cty.ObjectVal(vals), diags
	}
	return state, diags
}

// applyUserPassword sets password_wo's hash when the plan changed
// password_hmac: a new password, a new user, or one changed by hand. It
// returns password_hmac for state, worked out here when the plan didn't
// know the password yet.
func applyUserPassword(ctx context.Context, h *hostConn, req providers.ApplyResourceChangeRequest) (cty.Value, error) {
	wo, isHash := userPasswordInput(req.Config)
	planned := req.PlannedState.GetAttr("password_hmac")
	if wo.IsNull() || (known(planned) && !req.PriorState.IsNull() && req.PriorState.GetAttr("password_hmac").RawEquals(planned)) {
		return planned, nil
	}
	key, err := hmacKey(true)
	if err != nil {
		return cty.NilVal, err
	}
	id := userPasswordID(req.PlannedState)
	hash := userHash(key, id, wo.AsString(), isHash)
	sum := userSecretHMAC(key, id, hash)
	// A saved plan applied elsewhere must use the key it was made with.
	if known(planned) && !hmac.Equal([]byte(sum), []byte(planned.AsString())) {
		return cty.NilVal, errors.New("password_wo isn't the password the plan was made with, or the HMAC key changed; plan again")
	}
	// Setting a password never unlocks an account someone locked.
	name := stringOr(req.PlannedState.GetAttr("name"), "")
	if current, err := account.ReadPasswordHash(ctx, h, name); err != nil {
		return cty.NilVal, err
	} else if _, locked := account.Locked(current); locked {
		hash = "!" + hash
	}
	if err := account.SetPassword(ctx, h, name, hash); err != nil {
		return cty.NilVal, err
	}
	return cty.StringVal(sum), nil
}
