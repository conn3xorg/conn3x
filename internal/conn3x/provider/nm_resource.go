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
	"github.com/opentofu/opentofu/internal/conn3x/modules/nm"
	"github.com/opentofu/opentofu/internal/providers"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

// defaultNMConfirm guards every connection change unless told otherwise:
// the connection Conn3x logs in over is the one people most often change.
const defaultNMConfirm = "60s"

func nmConnectionSchema() providers.Schema {
	str := func(desc string) *configschema.Attribute {
		return &configschema.Attribute{Type: cty.String, Optional: true, Description: desc}
	}
	list := func(desc string) *configschema.Attribute {
		return &configschema.Attribute{Type: cty.List(cty.String), Optional: true, Description: desc}
	}
	return providers.Schema{Block: &configschema.Block{
		Description: "A NetworkManager connection profile, written as a keyfile and brought up.",
		Attributes: map[string]*configschema.Attribute{
			"id":            {Type: cty.String, Computed: true},
			"revision":      revisionAttr(),
			"name":          {Type: cty.String, Required: true, Description: "The connection's name. Its keyfile is /etc/NetworkManager/system-connections/<name>.nmconnection."},
			"type":          {Type: cty.String, Required: true, Description: "\"ethernet\", \"bond\" or \"vlan\"."},
			"ifname":        {Type: cty.String, Required: true, Description: "The interface, such as eth1, bond0 or bond0.10."},
			"ip4":           list("IPv4 addresses with prefixes, such as [\"192.0.2.10/24\"], or [\"auto\"] for DHCP (the default) or [\"disabled\"]."),
			"gw4":           str("The IPv4 gateway."),
			"dns4":          list("IPv4 DNS servers."),
			"ip6":           list("IPv6 addresses with prefixes, or [\"auto\"] (the default) or [\"disabled\"]."),
			"gw6":           str("The IPv6 gateway."),
			"dns6":          list("IPv6 DNS servers."),
			"dns_search":    list("DNS search domains."),
			"mtu":           {Type: cty.Number, Optional: true, Description: "The MTU, from 576 to 65535."},
			"autoconnect":   {Type: cty.Bool, Optional: true, Description: "Bring the connection up now and at boot. Defaults to true."},
			"controller":    str("For a bond port: the name of the bond connection. A port has no addresses of its own."),
			"vlan_parent":   str("For a vlan: the parent interface."),
			"vlan_id":       {Type: cty.Number, Optional: true, Description: "For a vlan: its ID, from 1 to 4094."},
			"bond_mode":     str("For a bond: balance-rr (the default), active-backup, balance-xor, broadcast, 802.3ad, balance-tlb or balance-alb."),
			"bond_options":  {Type: cty.Map(cty.String), Optional: true, Description: "For a bond: other bonding options, such as { miimon = \"100\" }."},
			"confirm_after": {Type: cty.String, Optional: true, Computed: true, Description: "Before a change, the host keeps the old keyfile and schedules its own revert after this long; after it, Conn3x logs in again over a new connection and cancels the revert. Defaults to \"60s\", since changing the connection Conn3x logs in over is the classic lockout. \"off\" turns it off. Needs systemd."},
			"on_remove":     {Type: cty.String, Optional: true, Computed: true, Description: "\"forget\" (default) leaves the connection as it is, \"delete\" removes the profile, which takes the connection down."},
			"in_sync":       {Type: cty.Bool, Computed: true, Description: "Whether the keyfile is Conn3x's and, with autoconnect, the connection is up."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func nmConnectionFrom(v cty.Value) nm.Connection {
	c := nm.Connection{
		Name: v.GetAttr("name").AsString(), Type: v.GetAttr("type").AsString(), Ifname: v.GetAttr("ifname").AsString(),
		IP4: stringList(v.GetAttr("ip4")), GW4: stringOr(v.GetAttr("gw4"), ""), DNS4: stringList(v.GetAttr("dns4")),
		IP6: stringList(v.GetAttr("ip6")), GW6: stringOr(v.GetAttr("gw6"), ""), DNS6: stringList(v.GetAttr("dns6")),
		DNSSearch: stringList(v.GetAttr("dns_search")), MTU: intOr(v.GetAttr("mtu"), 0),
		Autoconnect: true, Controller: stringOr(v.GetAttr("controller"), ""),
		VLANParent: stringOr(v.GetAttr("vlan_parent"), ""), VLANID: intOr(v.GetAttr("vlan_id"), 0), BondMode: stringOr(v.GetAttr("bond_mode"), ""),
	}
	if a := v.GetAttr("autoconnect"); a.IsKnown() && !a.IsNull() {
		c.Autoconnect = a.True()
	}
	if o := v.GetAttr("bond_options"); o.IsKnown() && !o.IsNull() {
		c.BondOptions = map[string]string{}
		for k, e := range o.AsValueMap() {
			c.BondOptions[k] = e.AsString()
		}
	}
	return c
}

func validateNMConnection(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() || !cfg.IsWhollyKnown() {
		return diags
	}
	diags = diags.Append(validateOnRemove(cfg))
	if err := nmConnectionFrom(cfg).Validate(); err != nil {
		diags = diags.Append(attrError("name", err.Error()))
	}
	if v := cfg.GetAttr("confirm_after"); !v.IsNull() && v.AsString() != "off" {
		if _, err := parseConfirmAfter(v); err != nil {
			diags = diags.Append(attrError("confirm_after", err.Error()+`, or "off"`))
		}
	}
	return diags
}

func planNMConnection(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	resp := planSynced(req, "nm_connection", []string{"name"}, []string{"type", "ifname", "ip4", "gw4", "dns4", "ip6", "gw6", "dns6", "dns_search", "mtu", "autoconnect", "controller", "vlan_parent", "vlan_id", "bond_mode", "bond_options"})
	if resp.PlannedState.IsNull() {
		return resp
	}
	if v := resp.PlannedState.GetAttr("confirm_after"); v.IsNull() {
		vals := resp.PlannedState.AsValueMap()
		vals["confirm_after"] = cty.StringVal(defaultNMConfirm)
		resp.PlannedState = cty.ObjectVal(vals)
	}
	return resp
}

func readNMConnection(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	return readPathResource(ctx, req, func(ctx context.Context, h *hostConn, prior cty.Value) (cty.Value, error) {
		c := nmConnectionFrom(prior)
		a, err := nm.Read(ctx, h, c)
		if err != nil {
			return cty.NilVal, err
		}
		return withSync(prior, c.InSync(a)), nil
	})
}

func applyNMConnection(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	return applyPathResource(ctx, req,
		func(ctx context.Context, h *hostConn, planned cty.Value) (cty.Value, error) {
			c := nmConnectionFrom(planned)
			write := func() error { return nm.Write(ctx, h, c) }
			if s := stringOr(planned.GetAttr("confirm_after"), defaultNMConfirm); s != "off" {
				after, err := parseConfirmAfter(cty.StringVal(s))
				if err != nil {
					return cty.NilVal, err
				}
				g := confirm.Guard{ID: newGuardID(), Files: []string{c.Path()}, Reload: c.Activate(), After: after}
				if err := guarded(ctx, h, planned.GetAttr("ssh"), g, write); err != nil {
					return cty.NilVal, fmt.Errorf("connection %s: %w", c.Name, err)
				}
			} else {
				if err := write(); err != nil {
					return cty.NilVal, err
				}
				if res, err := h.Run(ctx, c.Activate(), nil); err != nil || res.ExitCode != 0 {
					if err == nil {
						err = fmt.Errorf("%s", strings.TrimSpace(string(res.Stderr)))
					}
					return cty.NilVal, fmt.Errorf("bringing connection %s up: %w", c.Name, err)
				}
			}
			a, err := nm.Read(ctx, h, c)
			if err != nil {
				return cty.NilVal, err
			}
			if !c.InSync(a) {
				return cty.NilVal, fmt.Errorf("connection %s isn't up after the change; nmcli connection show %s says why", c.Name, c.Name)
			}
			return withSync(planned, true), nil
		},
		func(ctx context.Context, h *hostConn, prior cty.Value) error {
			return nm.Delete(ctx, h, nmConnectionFrom(prior))
		})
}
