// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/conn3x/modules/account"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

// locked and expires are read from /etc/shadow only when the step sets
// them, since that needs root: a step that leaves them out never asks.
func userLockSet(v cty.Value) (lock, expires bool) {
	return known(v.GetAttr("locked")), known(v.GetAttr("expires"))
}

func validateUserLock(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if e := cfg.GetAttr("expires"); known(e) && !account.ValidExpiry(e.AsString()) {
		diags = diags.Append(attrError("expires", fmt.Sprintf("expires %q isn't a date as YYYY-MM-DD, or \"\" for no expiry", e.AsString())))
	}
	return diags
}

// refreshUserLock records the lock and expiry the host has, for the ones
// the step sets, so a hand change plans a change back.
func refreshUserLock(ctx context.Context, h *hostConn, state cty.Value) (cty.Value, tfdiags.Diagnostics) {
	var diags tfdiags.Diagnostics
	lock, expires := userLockSet(state)
	if !lock && !expires {
		return state, diags
	}
	name := stringOr(state.GetAttr("name"), "")
	vals := state.AsValueMap()
	sh, err := account.ReadShadow(ctx, h, name)
	if err != nil {
		// Not knowing isn't in sync: say why, and plan to set them again.
		diags = diags.Append(tfdiags.SimpleWarning(fmt.Sprintf("user %s: can't check its lock and expiry: %s", name, err)))
		if lock {
			vals["locked"] = cty.NullVal(cty.Bool)
		}
		if expires {
			vals["expires"] = cty.NullVal(cty.String)
		}
		return cty.ObjectVal(vals), diags
	}
	if lock {
		vals["locked"] = cty.BoolVal(sh.IsLocked())
	}
	if expires {
		vals["expires"] = cty.StringVal(sh.Expires)
	}
	return cty.ObjectVal(vals), diags
}

// applyUserLock locks or unlocks the account and sets its expiry, after
// the password, so a new password is in place before an unlock.
func applyUserLock(ctx context.Context, h *hostConn, name string, cfg cty.Value) error {
	lock, expires := userLockSet(cfg)
	if !lock && !expires {
		return nil
	}
	sh, err := account.ReadShadow(ctx, h, name)
	if err != nil {
		return err
	}
	if lock {
		if err := account.SetLock(ctx, h, name, cfg.GetAttr("locked").True(), sh); err != nil {
			return err
		}
	}
	if want := cfg.GetAttr("expires"); expires && want.AsString() != sh.Expires {
		if err := account.SetExpiry(ctx, h, name, want.AsString()); err != nil {
			return err
		}
	}
	after, err := account.ReadShadow(ctx, h, name)
	switch {
	case err != nil:
		return err
	case lock && after.IsLocked() != cfg.GetAttr("locked").True():
		return fmt.Errorf("its lock doesn't match locked = %t after applying", cfg.GetAttr("locked").True())
	case expires && after.Expires != cfg.GetAttr("expires").AsString():
		return fmt.Errorf("it expires %q after applying, not %q", after.Expires, cfg.GetAttr("expires").AsString())
	}
	return nil
}
