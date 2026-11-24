// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"strings"

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
		Description: "A service, port, rich rule or source in firewalld, now and after reboots.",
		Attributes: map[string]*configschema.Attribute{
			"id":            {Type: cty.String, Computed: true},
			"revision":      revisionAttr(),
			"zone":          {Type: cty.String, Optional: true, Description: "Zone. Defaults to firewalld's default zone."},
			"service":       {Type: cty.String, Optional: true, Description: "firewalld service name, such as http. Set this or port, or use rich_rule instead."},
			"port":          {Type: cty.String, Optional: true, Description: "Port and protocol, such as 8080/tcp or 60000-61000/udp. Set this or service, or use rich_rule instead."},
			"rich_rule":     {Type: cty.String, Optional: true, Description: "A rule in firewalld's rich language, such as rule family=ipv4 source address=10.0.0.0/8 port port=5432 protocol=tcp accept, for a port open to one network only. Set it instead of service or port. It's checked with --query-rich-rule, which matches it however firewalld spells it back."},
			"source":        {Type: cty.String, Optional: true, Description: "An address or network, such as 10.42.0.0/16, to bind to zone, so traffic from it is handled by that zone's rules: how a cluster's pods, a management VLAN or a VPN are let in. Use it instead of service, port or rich_rule. A network is written as its own address. A source bound to another zone fails the step rather than being moved."},
			"on_remove":     {Type: cty.String, Optional: true, Computed: true, Description: ruleOnRemove},
			"in_sync":       {Type: cty.Bool, Computed: true, Description: "Whether the running and permanent firewall both allow it."},
			"confirm_after": ruleConfirmAfter(),
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func firewalldFrom(v cty.Value) firewall.Firewalld {
	return firewall.Firewalld{Zone: stringOr(v.GetAttr("zone"), ""), Service: stringOr(v.GetAttr("service"), ""), Port: stringOr(v.GetAttr("port"), ""), RichRule: stringOr(v.GetAttr("rich_rule"), ""), Source: stringOr(v.GetAttr("source"), "")}
}

func validateFirewalld(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() || !settled(cfg) {
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
				return fmt.Errorf("firewalld %s%s%s%s: %w", f.Service, f.Port, f.RichRule, f.Source, err)
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
	if cfg.IsNull() || !settled(cfg) {
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
	if cfg.IsNull() || !settled(cfg) {
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

// iptablesKeys are the arguments that make up the rule itself, so changing
// one replaces it: the old rule is deleted and the new one added.
var iptablesKeys = []string{"ip_version", "table", "chain", "protocol", "source", "destination", "source_port", "destination_port", "destination_ports", "in_interface", "out_interface", "ctstate", "jump", "comment"}

func iptablesRuleSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "One iptables or ip6tables rule in one chain, checked with iptables -C, added with -A or -I and deleted with -D. The rest of the chain is left alone.",
		Attributes: map[string]*configschema.Attribute{
			"id":                {Type: cty.String, Computed: true},
			"revision":          revisionAttr(),
			"table":             {Type: cty.String, Optional: true, Description: "filter (default), nat, mangle, raw or security."},
			"chain":             {Type: cty.String, Required: true, Description: "The chain, such as INPUT, FORWARD or a chain of your own. It must already exist."},
			"protocol":          {Type: cty.String, Optional: true, Description: "tcp, udp, icmp, all or another protocol iptables knows, as -p. Ports need tcp, udp, udplite, sctp or dccp."},
			"source":            {Type: cty.String, Optional: true, Description: "An address or CIDR network the packet comes from, as -s."},
			"destination":       {Type: cty.String, Optional: true, Description: "An address or CIDR network the packet goes to, as -d."},
			"source_port":       {Type: cty.String, Optional: true, Description: "A port, such as 53, or a range, such as 1024:65535, as --sport."},
			"destination_port":  {Type: cty.String, Optional: true, Description: "A port, such as 22, or a range, such as 6000:6007, as --dport. Set this or destination_ports."},
			"destination_ports": {Type: cty.List(cty.String), Optional: true, Description: "Up to 15 ports or ranges, as -m multiport --dports. Set this or destination_port."},
			"in_interface":      {Type: cty.String, Optional: true, Description: "The interface the packet comes in on, as -i. A trailing + matches a prefix, such as eth+."},
			"out_interface":     {Type: cty.String, Optional: true, Description: "The interface the packet goes out on, as -o."},
			"ctstate":           {Type: cty.List(cty.String), Optional: true, Description: "Connection states, such as [\"ESTABLISHED\", \"RELATED\"], as -m conntrack --ctstate."},
			"jump":              {Type: cty.String, Optional: true, Description: "The target, such as ACCEPT, DROP, REJECT or a chain of your own, as -j. Unset, the rule only counts packets."},
			"comment":           {Type: cty.String, Optional: true, Description: "A comment kept with the rule, as -m comment --comment, so iptables -L shows who added it. It's part of the rule."},
			"ip_version":        {Type: cty.String, Optional: true, Description: "\"ipv4\" (default) uses iptables, \"ipv6\" uses ip6tables. For both, use two steps."},
			"position":          {Type: cty.String, Optional: true, Description: "\"append\" (default) adds the rule at the end of the chain, \"insert\" at the top, or at rule_num. Only used when the rule is added: a rule that's there anywhere in the chain counts."},
			"rule_num":          {Type: cty.Number, Optional: true, Description: "With position = \"insert\", where the rule goes, from 1 at the top."},
			"persist":           {Type: cty.Bool, Optional: true, Description: "Save the whole table after every change, so it comes back at boot: iptables-save to /etc/iptables/rules.v4 (rules.v6) for iptables-persistent on Debian and Ubuntu, or /etc/sysconfig/iptables (ip6tables) for iptables-services on the Red Hat family. Fails when neither is installed."},
			"on_remove":         {Type: cty.String, Optional: true, Computed: true, Description: "\"delete\" (default) deletes the rule when the step is removed or replaced, \"forget\" leaves it."},
			"in_sync":           {Type: cty.Bool, Computed: true, Description: "Whether iptables -C found the rule at the last refresh."},
			"confirm_after":     ruleConfirmAfter(),
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func iptablesRuleFrom(v cty.Value) firewall.IPTablesRule {
	return firewall.IPTablesRule{
		Table:            stringOr(v.GetAttr("table"), ""),
		Chain:            stringOr(v.GetAttr("chain"), ""),
		Protocol:         stringOr(v.GetAttr("protocol"), ""),
		Source:           stringOr(v.GetAttr("source"), ""),
		Destination:      stringOr(v.GetAttr("destination"), ""),
		SourcePort:       stringOr(v.GetAttr("source_port"), ""),
		DestinationPort:  stringOr(v.GetAttr("destination_port"), ""),
		DestinationPorts: stringList(v.GetAttr("destination_ports")),
		InInterface:      stringOr(v.GetAttr("in_interface"), ""),
		OutInterface:     stringOr(v.GetAttr("out_interface"), ""),
		CTState:          stringList(v.GetAttr("ctstate")),
		Jump:             stringOr(v.GetAttr("jump"), ""),
		Comment:          stringOr(v.GetAttr("comment"), ""),
		IPv6:             stringOr(v.GetAttr("ip_version"), "") == "ipv6",
		Insert:           stringOr(v.GetAttr("position"), "") == "insert",
		RuleNum:          intOr(v.GetAttr("rule_num"), 0),
		Persist:          boolOr(v.GetAttr("persist")),
	}
}

func validateIPTablesRule(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() || !settled(cfg) {
		return diags
	}
	diags = diags.Append(validateOnRemove(cfg))
	diags = diags.Append(validateRuleConfirmAfter(cfg))
	if v := stringOr(cfg.GetAttr("ip_version"), "ipv4"); v != "ipv4" && v != "ipv6" {
		diags = diags.Append(attrError("ip_version", fmt.Sprintf(`ip_version must be "ipv4" or "ipv6", not %q; for both, use two steps`, v)))
	}
	if p := stringOr(cfg.GetAttr("position"), "append"); p != "append" && p != "insert" {
		diags = diags.Append(attrError("position", fmt.Sprintf(`position must be "append" or "insert", not %q`, p)))
	}
	if n := cfg.GetAttr("rule_num"); !n.IsNull() && !n.AsBigFloat().IsInt() {
		diags = diags.Append(attrError("rule_num", "rule_num must be a whole number"))
	}
	if err := iptablesRuleFrom(cfg).Validate(); err != nil {
		diags = diags.Append(attrError("chain", err.Error()))
	}
	return diags
}

func planIPTablesRule(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	return planSynced(deleteByDefault(req), "iptables", iptablesKeys, []string{"position", "rule_num", "persist"})
}

func readIPTablesRule(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	return readPathResource(ctx, req, func(ctx context.Context, h *hostConn, prior cty.Value) (cty.Value, error) {
		ok, err := firewall.ReadIPTables(ctx, h, iptablesRuleFrom(prior))
		if err != nil {
			return cty.NilVal, err
		}
		return withSync(prior, ok), nil
	})
}

func applyIPTablesRule(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	set := func(present bool) func(context.Context, *hostConn, cty.Value) error {
		return func(ctx context.Context, h *hostConn, v cty.Value) error {
			r := iptablesRuleFrom(v)
			undo := func() ([]string, error) {
				had, err := firewall.ReadIPTables(ctx, h, r)
				return r.Undo(present, had), err
			}
			if err := guardRule(ctx, h, v, undo, func() error { return firewall.ApplyIPTables(ctx, h, r, present) }); err != nil {
				return fmt.Errorf("iptables_rule %s %s: %w", r.Chain, strings.Join(r.Spec(), " "), err)
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
