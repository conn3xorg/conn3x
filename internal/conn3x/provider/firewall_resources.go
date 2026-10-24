// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/conn3x/modules/firewall"
	"github.com/opentofu/opentofu/internal/providers"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

const ruleOnRemove = "\"delete\" (default) closes the port again when the rule is removed or replaced, \"forget\" leaves it open."

// planRule plans a firewall rule. Unlike other resources, rules default to
// on_remove = "delete", so a changed port does not leave the old one open.
func planRule(kind string, keys []string) func(providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	return func(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
		if !req.ProposedNewState.IsNull() && req.ProposedNewState.GetAttr("on_remove").IsNull() {
			vals := req.ProposedNewState.AsValueMap()
			vals["on_remove"] = cty.StringVal(onRemoveDelete)
			req.ProposedNewState = cty.ObjectVal(vals)
		}
		return planSynced(req, kind, keys, nil)
	}
}

func firewalldSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "A service or port allowed through firewalld, now and after reboots.",
		Attributes: map[string]*configschema.Attribute{
			"id":        {Type: cty.String, Computed: true},
			"zone":      {Type: cty.String, Optional: true, Description: "Zone. Defaults to firewalld's default zone."},
			"service":   {Type: cty.String, Optional: true, Description: "firewalld service name, such as http. Set this or port."},
			"port":      {Type: cty.String, Optional: true, Description: "Port and protocol, such as 8080/tcp or 60000-61000/udp. Set this or service."},
			"on_remove": {Type: cty.String, Optional: true, Computed: true, Description: ruleOnRemove},
			"in_sync":   {Type: cty.Bool, Computed: true, Description: "Whether the running and permanent firewall both allow it."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func firewalldFrom(v cty.Value) firewall.Firewalld {
	return firewall.Firewalld{Zone: stringOr(v.GetAttr("zone"), ""), Service: stringOr(v.GetAttr("service"), ""), Port: stringOr(v.GetAttr("port"), "")}
}

func validateFirewalld(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() || !cfg.IsWhollyKnown() {
		return diags
	}
	diags = diags.Append(validateOnRemove(cfg))
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
			if err := firewall.ApplyFirewalld(ctx, h, f, present); err != nil {
				return fmt.Errorf("firewalld %s%s: %w", f.Service, f.Port, err)
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
			"id":        {Type: cty.String, Computed: true},
			"action":    {Type: cty.String, Required: true, Description: "allow, deny, reject or limit."},
			"port":      {Type: cty.String, Required: true, Description: "Port, optionally with a protocol: 22, 22/tcp or 6000:6007/tcp."},
			"from":      {Type: cty.String, Optional: true, Description: "Address or CIDR the rule applies to. Defaults to anywhere."},
			"on_remove": {Type: cty.String, Optional: true, Computed: true, Description: ruleOnRemove},
			"in_sync":   {Type: cty.Bool, Computed: true, Description: "Whether ufw has the rule."},
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
			if err := firewall.ApplyUFW(ctx, h, u, present); err != nil {
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
