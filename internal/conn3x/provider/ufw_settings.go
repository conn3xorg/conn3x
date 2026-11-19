// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/conn3x/modules/confirm"
	"github.com/opentofu/opentofu/internal/conn3x/modules/firewall"
	"github.com/opentofu/opentofu/internal/providers"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

var ufwSettingsAttrs = []string{"enabled", "default_incoming", "default_outgoing", "default_routed"}

func ufwSettingsSchema() providers.Schema {
	policy := func(dir string) *configschema.Attribute {
		return &configschema.Attribute{Type: cty.String, Optional: true, Description: "ufw's default policy for " + dir + " traffic: allow, deny or reject. Unset leaves it as it is."}
	}
	return providers.Schema{Block: &configschema.Block{
		Description: "ufw itself, one per host: whether it's on, and its default policies. Rules come from ufw steps.",
		Attributes: map[string]*configschema.Attribute{
			"id":               {Type: cty.String, Computed: true},
			"revision":         revisionAttr(),
			"enabled":          {Type: cty.Bool, Optional: true, Description: "true turns ufw on now and at boot, with ufw --force enable; false turns it off. Unset leaves it as it is. Turning it on, or refusing incoming traffic while it's on, is refused unless a ufw rule lets in sshd's port, or confirm_after is set."},
			"default_incoming": policy("incoming"),
			"default_outgoing": policy("outgoing"),
			"default_routed":   policy("routed (forwarded)"),
			"confirm_after":    ruleConfirmAfter(),
			"in_sync":          {Type: cty.Bool, Computed: true, Description: "Whether ufw had every setting the step sets at the last refresh."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func ufwSettingsFrom(v cty.Value) firewall.UFWSettings {
	s := firewall.UFWSettings{Incoming: stringOr(v.GetAttr("default_incoming"), ""), Outgoing: stringOr(v.GetAttr("default_outgoing"), ""), Routed: stringOr(v.GetAttr("default_routed"), "")}
	if e := v.GetAttr("enabled"); known(e) {
		on := e.True()
		s.Enabled = &on
	}
	return s
}

// sshPeer reads $SSH_CONNECTION as the login user, without sudo or the
// agent, whose environments don't have it.
func sshPeer(ctx context.Context, h *hostConn) firewall.SSHPeer {
	res, err := h.client.Run(ctx, `printf '%s' "${SSH_CONNECTION:-}"`, nil)
	if err != nil || res.ExitCode != 0 {
		return firewall.SSHPeer{}
	}
	return firewall.ParseSSHConnection(string(res.Stdout))
}

func validateUFWSettings(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() || !cfg.IsWhollyKnown() {
		return diags
	}
	diags = diags.Append(validateRuleConfirmAfter(cfg))
	if err := ufwSettingsFrom(cfg).Validate(); err != nil {
		diags = diags.Append(attrError("enabled", err.Error()))
	}
	return diags
}

func planUFWSettings(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	return planSynced(req, "ufw_settings", nil, ufwSettingsAttrs)
}

func readUFWSettings(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	return readPathResource(ctx, req, func(ctx context.Context, h *hostConn, prior cty.Value) (cty.Value, error) {
		st, err := firewall.ReadUFWState(ctx, h)
		if err != nil {
			return cty.NilVal, err
		}
		return withSync(prior, ufwSettingsFrom(prior).Matches(st)), nil
	})
}

// applyUFWSettings changes ufw under confirm_after when it's set. Without
// it, a change that would leave sshd's port shut is refused before
// anything runs. Removing the step leaves ufw as it is.
func applyUFWSettings(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	return applyPathResource(ctx, req,
		func(ctx context.Context, h *hostConn, planned cty.Value) (cty.Value, error) {
			s := ufwSettingsFrom(planned)
			st, err := firewall.ReadUFWState(ctx, h)
			if err != nil {
				return cty.NilVal, err
			}
			do, undo := s.Commands(st)
			if after, _ := parseConfirmAfter(planned.GetAttr("confirm_after")); after == 0 && len(do) > 0 {
				added, err := firewall.ReadUFWAdded(ctx, h)
				if err != nil {
					return cty.NilVal, err
				}
				peer := sshPeer(ctx, h)
				if s.LocksOut(st, added, firewall.SSHPorts(ctx, h), peer) {
					from := "Conn3x's address can't be read here, so a rule with from doesn't count"
					if peer.Client != nil {
						from = "a rule with from counts only when it covers " + peer.Client.String() + ", where Conn3x logs in from"
					}
					return cty.NilVal, fmt.Errorf("ufw would refuse incoming SSH, and no ufw rule lets this connection in to sshd's port, so the next login would be shut out (%s). Add a ufw step that allows it, such as ufw { action = \"allow\", port = \"22/tcp\" }, before this one, or set confirm_after so the host takes the change back if Conn3x can't log in again", from)
				}
			}
			apply := func() error { return firewall.ApplyUFWSettings(ctx, h, s, do) }
			if after, _ := parseConfirmAfter(planned.GetAttr("confirm_after")); after > 0 && len(undo) > 0 {
				err = guarded(ctx, h, planned.GetAttr("ssh"), confirm.Guard{ID: newGuardID(), Undo: undo, After: after}, apply)
			} else {
				err = apply()
			}
			if err != nil {
				return cty.NilVal, err
			}
			return withSync(planned, true), nil
		}, nil)
}
