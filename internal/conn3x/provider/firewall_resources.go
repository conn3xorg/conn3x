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

// ruleConfirmAfter guards a rule change, in either direction: a deny on
// the SSH port and removing the rule that allows it lock you out alike.
func ruleConfirmAfter() *configschema.Attribute {
	return &configschema.Attribute{
		Type: cty.String, Optional: true,
		Description: "For a rule change that could lock Conn3x out, such as removing the rule that lets SSH in, or a ufw deny on its port: before the change, the host schedules its own undo after this long, such as \"60s\"; after it, Conn3x logs in again over a new connection and cancels it. If that login doesn't come, the host takes the change back by itself, even if Conn3x has gone away. Needs systemd.",
	}
}

// validateRuleConfirmAfter checks confirm_after on a firewall rule.
func validateRuleConfirmAfter(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if _, err := parseConfirmAfter(cfg.GetAttr("confirm_after")); err != nil {
		diags = diags.Append(attrError("confirm_after", err.Error()))
	}
	return diags
}

// guardRule runs change under confirm_after, from the rule's own state (the
// prior one when removing), with undo as the commands that take it back.
// Without confirm_after, or with nothing to undo, it just runs change.
func guardRule(ctx context.Context, h *hostConn, v cty.Value, undo func() ([]string, error), change func() error) error {
	after, _ := parseConfirmAfter(v.GetAttr("confirm_after"))
	if after == 0 {
		return change()
	}
	cmds, err := undo()
	if err != nil {
		return err
	}
	if len(cmds) == 0 {
		return change()
	}
	return guarded(ctx, h, v.GetAttr("ssh"), confirm.Guard{ID: newGuardID(), Undo: cmds, After: after}, change)
}

const ruleOnRemove = "\"delete\" (default) closes the port again when the rule is removed or replaced, \"forget\" leaves it open."

// planRule plans a firewall rule, which defaults to on_remove = "delete".
func planRule(kind string, keys []string) func(providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	return func(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
		return planSynced(deleteByDefault(req), kind, keys, nil)
	}
}

// deleteByDefault makes on_remove default to "delete", for resources that
// grant access or run things: a rotated key, a renamed job or a changed
// port must not leave the old one active.
func deleteByDefault(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeRequest {
	if !req.ProposedNewState.IsNull() && req.ProposedNewState.GetAttr("on_remove").IsNull() {
		vals := req.ProposedNewState.AsValueMap()
		vals["on_remove"] = cty.StringVal(onRemoveDelete)
		req.ProposedNewState = cty.ObjectVal(vals)
	}
	return req
}

func firewalldSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "A service, port or rich rule in firewalld, now and after reboots.",
		Attributes: map[string]*configschema.Attribute{
			"id":            {Type: cty.String, Computed: true},
			"revision":      revisionAttr(),
			"zone":          {Type: cty.String, Optional: true, Description: "Zone. Defaults to firewalld's default zone."},
			"service":       {Type: cty.String, Optional: true, Description: "firewalld service name, such as http. Set this or port, or use rich_rule instead."},
			"port":          {Type: cty.String, Optional: true, Description: "Port and protocol, such as 8080/tcp or 60000-61000/udp. Set this or service, or use rich_rule instead."},
			"rich_rule":     {Type: cty.String, Optional: true, Description: "A rule in firewalld's rich language, such as rule family=ipv4 source address=10.0.0.0/8 port port=5432 protocol=tcp accept, for a port open to one network only. Set it instead of service or port. It's checked with --query-rich-rule, which matches it however firewalld spells it back."},
			"on_remove":     {Type: cty.String, Optional: true, Computed: true, Description: ruleOnRemove},
			"in_sync":       {Type: cty.Bool, Computed: true, Description: "Whether the running and permanent firewall both allow it."},
			"confirm_after": ruleConfirmAfter(),
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func firewalldFrom(v cty.Value) firewall.Firewalld {
	return firewall.Firewalld{Zone: stringOr(v.GetAttr("zone"), ""), Service: stringOr(v.GetAttr("service"), ""), Port: stringOr(v.GetAttr("port"), ""), RichRule: stringOr(v.GetAttr("rich_rule"), "")}
}

func validateFirewalld(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() || !cfg.IsWhollyKnown() {
		return diags
	}
	diags = diags.Append(validateOnRemove(cfg))
	diags = diags.Append(validateRuleConfirmAfter(cfg))
	if err := firewalldFrom(cfg).Validate(); err != nil {
		diags = diags.Append(attrError("port", err.Error()))
	}
	return diags
}

func readFirewalld(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	return readPathResource(ctx, req, func(ctx context.Context, h *hostConn, prior cty.Value) (cty.Value, error) {
		runtime, permanent, err := firewall.ReadFirewalld(ctx, h, firewalldFrom(prior))
		if err != nil {
			return cty.NilVal, err
		}
		return withSync(prior, runtime && permanent), nil
	})
}

func applyFirewalld(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	set := func(present bool) func(context.Context, *hostConn, cty.Value) error {
		return func(ctx context.Context, h *hostConn, v cty.Value) error {
			f := firewalldFrom(v)
			undo := func() ([]string, error) {
				runtime, permanent, err := firewall.ReadFirewalld(ctx, h, f)
				return f.Undo(present, runtime, permanent), err
			}
			if err := guardRule(ctx, h, v, undo, func() error { return firewall.ApplyFirewalld(ctx, h, f, present) }); err != nil {
				return fmt.Errorf("firewalld %s%s%s: %w", f.Service, f.Port, f.RichRule, err)
			}
			return nil
		}
	}
	return applyPathResource(ctx, req,
		func(ctx context.Context, h *hostConn, planned cty.Value) (cty.Value, error) {
			if err := set(true)(ctx, h, planned); err != nil {
				return cty.NilVal, err
			}
			return withSync(planned, true), nil
		}, set(false))
}

func ufwRuleSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "A ufw rule for a port. Rules take effect once ufw is enabled; allow SSH before enabling it.",
		Attributes: map[string]*configschema.Attribute{
			"id":            {Type: cty.String, Computed: true},
			"revision":      revisionAttr(),
			"action":        {Type: cty.String, Required: true, Description: "allow, deny, reject or limit."},
			"port":          {Type: cty.String, Required: true, Description: "Port, optionally with a protocol: 22, 22/tcp or 6000:6007/tcp."},
			"from":          {Type: cty.String, Optional: true, Description: "Address or CIDR the rule applies to. Defaults to anywhere."},
			"on_remove":     {Type: cty.String, Optional: true, Computed: true, Description: ruleOnRemove},
			"in_sync":       {Type: cty.Bool, Computed: true, Description: "Whether ufw has the rule."},
			"confirm_after": ruleConfirmAfter(),
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func ufwRuleFrom(v cty.Value) firewall.UFWRule {
	return firewall.UFWRule{Action: v.GetAttr("action").AsString(), Port: v.GetAttr("port").AsString(), From: stringOr(v.GetAttr("from"), "")}
}

func validateUFWRule(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() || !cfg.IsWhollyKnown() {
		return diags
	}
	diags = diags.Append(validateOnRemove(cfg))
	diags = diags.Append(validateRuleConfirmAfter(cfg))
	if err := ufwRuleFrom(cfg).Validate(); err != nil {
		diags = diags.Append(attrError("port", err.Error()))
	}
	return diags
}

func readUFWRule(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	return readPathResource(ctx, req, func(ctx context.Context, h *hostConn, prior cty.Value) (cty.Value, error) {
		ok, err := firewall.ReadUFW(ctx, h, ufwRuleFrom(prior))
		if err != nil {
			return cty.NilVal, err
		}
		return withSync(prior, ok), nil
	})
}

func applyUFWRule(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	set := func(present bool) func(context.Context, *hostConn, cty.Value) error {
		return func(ctx context.Context, h *hostConn, v cty.Value) error {
			u := ufwRuleFrom(v)
			undo := func() ([]string, error) {
				had, err := firewall.ReadUFW(ctx, h, u)
				if err != nil || had == present {
					return nil, err
				}
				cmd, err := u.Undo(present)
				return []string{cmd}, err
			}
			if err := guardRule(ctx, h, v, undo, func() error { return firewall.ApplyUFW(ctx, h, u, present) }); err != nil {
				return fmt.Errorf("ufw %s: %w", u.Spec(), err)
			}
			return nil
		}
	}
	return applyPathResource(ctx, req,
		func(ctx context.Context, h *hostConn, planned cty.Value) (cty.Value, error) {
			if err := set(true)(ctx, h, planned); err != nil {
				return cty.NilVal, err
			}
			return withSync(planned, true), nil
		}, set(false))
}

func nftablesSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "One nftables table, owned whole: its chains, sets and rules, loaded in one nft transaction and again at every boot.",
		Attributes: map[string]*configschema.Attribute{
			"id":            {Type: cty.String, Computed: true},
			"revision":      revisionAttr(),
			"family":        {Type: cty.String, Optional: true, Description: "The table's family: \"inet\" (default), \"ip\", \"ip6\", \"arp\", \"bridge\" or \"netdev\"."},
			"table":         {Type: cty.String, Required: true, Description: "The table's name, such as filter or conn3x."},
			"content":       {Type: cty.String, Required: true, Description: "The table's body in nft syntax: its chains, sets and rules, as they'd sit inside table FAMILY NAME { ... }. nft checks it with nft -c before anything is loaded."},
			"confirm_after": ruleConfirmAfter(),
			"on_remove":     {Type: cty.String, Optional: true, Computed: true, Description: "\"delete\" (default) deletes the table, and the unit that loads it at boot, when the step goes; \"forget\" leaves them."},
			"in_sync":       {Type: cty.Bool, Computed: true, Description: "Whether the table was as loaded, and set to load at boot, at the last refresh. A rule added or deleted by hand shows here."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func nftablesFrom(v cty.Value) firewall.NFTable {
	return firewall.NFTable{Family: stringOr(v.GetAttr("family"), "inet"), Name: stringOr(v.GetAttr("table"), ""), Content: stringOr(v.GetAttr("content"), "")}
}

func validateNftables(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() || !cfg.IsWhollyKnown() {
		return diags
	}
	diags = diags.Append(validateOnRemove(cfg))
	diags = diags.Append(validateRuleConfirmAfter(cfg))
	if err := nftablesFrom(cfg).Validate(); err != nil {
		diags = diags.Append(attrError("content", err.Error()))
	}
	return diags
}

func planNftables(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	return planSynced(deleteByDefault(req), "nftables", []string{"family", "table"}, []string{"content"})
}

func readNftables(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	return readPathResource(ctx, req, func(ctx context.Context, h *hostConn, prior cty.Value) (cty.Value, error) {
		ok, err := firewall.ReadNFTable(ctx, h, nftablesFrom(prior))
		if err != nil {
			return cty.NilVal, err
		}
		return withSync(prior, ok), nil
	})
}

func applyNftables(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	set := func(present bool) func(context.Context, *hostConn, cty.Value) error {
		return func(ctx context.Context, h *hostConn, v cty.Value) error {
			t := nftablesFrom(v)
			undo := func() ([]string, error) { return firewall.SaveNFUndo(ctx, h, t) }
			change := func() error {
				if present {
					return firewall.ApplyNFTable(ctx, h, t)
				}
				return firewall.DeleteNFTable(ctx, h, t)
			}
			if err := guardRule(ctx, h, v, undo, change); err != nil {
				return fmt.Errorf("nftables %s %s: %w", t.Family, t.Name, err)
			}
			return nil
		}
	}
	return applyPathResource(ctx, req,
		func(ctx context.Context, h *hostConn, planned cty.Value) (cty.Value, error) {
			if err := set(true)(ctx, h, planned); err != nil {
				return cty.NilVal, err
			}
			return withSync(planned, true), nil
		}, set(false))
}
