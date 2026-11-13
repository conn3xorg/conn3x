// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"time"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/conn3x/modules/setcfg"
	"github.com/opentofu/opentofu/internal/conn3x/modules/vyos"
	"github.com/opentofu/opentofu/internal/providers"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

const vyosTypePrefix = "conn3x_vyos_"

// validateVyOSSSH rejects the ssh settings a VyOS login has no use for.
func validateVyOSSSH(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() || !cfg.Type().HasAttribute("ssh") {
		return diags
	}
	conn := cfg.GetAttr("ssh")
	if conn.IsNull() || !conn.IsKnown() {
		return diags
	}
	for attr, why := range map[string]string{
		"agent":                "The conn3x agent isn't for routers. Remove agent from this ssh block.",
		"become":               "VyOS changes its configuration as its own user, in the vyattacfg group, not through sudo. Remove become from this ssh block.",
		"become_password_file": "VyOS steps don't use sudo, so there is no password to give it. Remove become_password_file from this ssh block.",
	} {
		v := conn.GetAttr(attr)
		if v.IsNull() || !v.IsKnown() || (v.Type() == cty.Bool && v.False()) {
			continue
		}
		diags = diags.Append(tfdiags.AttributeValue(tfdiags.Error, "Invalid ssh setting for a VyOS router", why,
			cty.GetAttrPath("ssh").GetAttr(attr)))
	}
	if v := optional(conn, "confirm_after"); known(v) {
		if d, err := time.ParseDuration(v.AsString()); err == nil {
			if err := vyos.CheckConfirmAfter(d); err != nil {
				diags = diags.Append(tfdiags.AttributeValue(tfdiags.Error, "Invalid ssh confirm_after", err.Error(),
					cty.GetAttrPath("ssh").GetAttr("confirm_after")))
			}
		}
	}
	return diags
}

// vyosWarnReboot is the refresh warning for a router whose commit-confirm
// would reboot it, VyOS's default, rather than reload the old config.
func vyosWarnReboot(config string) string {
	if !vyos.RebootsOnRollback(config) {
		return ""
	}
	return "this router's commit-confirm action is reboot, VyOS's default, so a change Conn3x can't confirm reboots it to undo the change. Set \"set system config-management commit-confirm action reload\" to have it reload the previous config instead"
}

func vyosConfigFrom(v cty.Value) setcfg.Config {
	return vyos.Config(stringOr(v.GetAttr("prefix"), ""), stringList(v.GetAttr("lines")), stringOr(v.GetAttr("match"), setcfg.MatchLines))
}

var vyosConfigKind = cliKind{
	p:        vyosPlatform,
	name:     "config",
	keys:     []string{"prefix"},
	settings: []string{"lines", "match"},
	config:   func(v cty.Value) cliWant { return vyosConfigFrom(v) },
	remove:   func(v cty.Value, running string) []string { return vyosConfigFrom(v).RemoveCommands(running) },
	warn:     func(_ cty.Value, config string) string { return vyosWarnReboot(config) },
}

func vyosConfigSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: junosExperimental + "Statements of a VyOS router's configuration, as set lines. Only the lines named here are owned; with match = \"block\" the statements under prefix must be exactly these.",
		Attributes: map[string]*configschema.Attribute{
			"id":        {Type: cty.String, Computed: true},
			"revision":  revisionAttr(),
			"lines":     {Type: cty.List(cty.String), Optional: true, Description: "Set statements, as show configuration commands prints them, such as \"set interfaces ethernet eth0 description 'uplink'\". Quotes are compared loosely: 'uplink', \"uplink\" and uplink are the same value."},
			"prefix":    {Type: cty.String, Optional: true, Description: "With match = \"block\": the node the lines own, such as \"protocols static\". Every line must start with set and this prefix."},
			"match":     {Type: cty.String, Optional: true, Description: "\"lines\" (default): these statements must be there, and others are left alone. \"block\": the statements under prefix must be exactly these, so others under it are deleted. Needs prefix."},
			"on_remove": {Type: cty.String, Optional: true, Computed: true, Description: "What happens on the router when this resource is removed: \"forget\" (default) leaves the statements, \"delete\" deletes them."},
			"in_sync":   {Type: cty.Bool, Computed: true, Description: "Whether the router had these statements at the last refresh."},
			"circuit":   eosCircuitAttr(),
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func validateVyOSConfig(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() || !cfg.IsWhollyKnown() {
		return diags
	}
	diags = diags.Append(validateOnRemove(cfg))
	if err := vyosConfigFrom(cfg).Validate(); err != nil {
		diags = diags.Append(attrError("lines", err.Error()))
	}
	return diags
}

var vyosHostnameKind = cliKind{
	p:        vyosPlatform,
	name:     "hostname",
	settings: []string{"name"},
	config:   func(v cty.Value) cliWant { return vyos.Hostname(v.GetAttr("name").AsString()) },
	warn:     func(_ cty.Value, config string) string { return vyosWarnReboot(config) },
}

func vyosHostnameSchema() providers.Schema {
	s := singletonSchema(junosExperimental+"A VyOS router's host name. Removing this step leaves the name as it is.",
		"Host name, such as r1. VyOS takes letters, digits and hyphens.")
	s.Block.Attributes["in_sync"].Description = "Whether the router had this name at the last refresh."
	s.Block.Attributes["circuit"] = eosCircuitAttr()
	return s
}

func validateVyOSHostname(cfg cty.Value) tfdiags.Diagnostics {
	return validateName(cfg, vyos.ValidateHostname)
}

func vyosInterfaceFrom(v cty.Value) vyos.Interface {
	i := vyos.Interface{Name: stringOr(v.GetAttr("name"), ""), Description: optString(v.GetAttr("description"))}
	if e := v.GetAttr("enabled"); known(e) {
		b := e.True()
		i.Enabled = &b
	}
	if n := v.GetAttr("mtu"); known(n) {
		x, _ := n.AsBigFloat().Int64()
		i.MTU = int(x)
	}
	if l := v.GetAttr("addresses"); known(l) {
		i.Addresses = append([]string{}, stringList(l)...)
	}
	return i
}

var vyosInterfaceKind = cliKind{
	p:        vyosPlatform,
	name:     "interface",
	keys:     []string{"name"},
	settings: []string{"description", "addresses", "enabled", "mtu"},
	config:   func(v cty.Value) cliWant { return vyosInterfaceFrom(v) },
	remove:   func(v cty.Value, running string) []string { return vyosInterfaceFrom(v).RemoveCommands(running) },
	guard:    func(v cty.Value, config, address string) error { return vyosInterfaceFrom(v).Guard(config, address) },
	warn:     func(_ cty.Value, config string) string { return vyosWarnReboot(config) },
}

func vyosInterfaceSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: junosExperimental + "The settings Conn3x owns on one VyOS interface: description, addresses, enabled and MTU. Each one left unset is left alone, and so is every other statement under the interface.",
		Attributes: map[string]*configschema.Attribute{
			"id":          {Type: cty.String, Computed: true},
			"revision":    revisionAttr(),
			"name":        {Type: cty.String, Required: true, Description: "The interface, such as eth0, bond0, br0, wg0 or lo."},
			"description": {Type: cty.String, Optional: true, Description: "Its description. No quotes or backslashes."},
			"addresses":   {Type: cty.List(cty.String), Optional: true, Description: "Its whole set of addresses, each with its prefix length, such as 192.0.2.1/24, or dhcp or dhcpv6. Addresses not listed are deleted; taking off the one Conn3x connects to is refused."},
			"enabled":     {Type: cty.Bool, Optional: true, Description: "false sets disable, true deletes it. Disabling the interface whose address Conn3x connects to is refused."},
			"mtu":         {Type: cty.Number, Optional: true, Description: "MTU, 68 to 16000."},
			"on_remove":   {Type: cty.String, Optional: true, Computed: true, Description: "What happens when this resource is removed: \"forget\" (default) leaves the interface as it is, \"delete\" deletes the statements it owns. The interface itself stays."},
			"in_sync":     {Type: cty.Bool, Computed: true, Description: "Whether the interface had these settings at the last refresh."},
			"circuit":     eosCircuitAttr(),
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func validateVyOSInterface(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() || !cfg.IsWhollyKnown() {
		return diags
	}
	diags = diags.Append(validateOnRemove(cfg))
	if err := vyosInterfaceFrom(cfg).Validate(); err != nil {
		diags = diags.Append(attrError("name", err.Error()))
	}
	return diags
}

// vyosDeviceSchema is the conn3x_vyos_device data source.
func vyosDeviceSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: junosExperimental + "Facts about a VyOS router, from show version and its configuration.",
		Attributes: map[string]*configschema.Attribute{
			"hostname": {Type: cty.String, Computed: true, Description: "The router's host name."},
			"version":  {Type: cty.String, Computed: true, Description: "VyOS version as show version prints it, such as VyOS 2026.11.13-0016-rolling."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func readVyOSDevice(ctx context.Context, req providers.ReadDataSourceRequest) providers.ReadDataSourceResponse {
	var resp providers.ReadDataSourceResponse
	h, err := pooled(ctx, req.Config.GetAttr("ssh"), 0)
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(attrError("ssh", err.Error()))
		return resp
	}
	f, err := vyos.ReadFacts(ctx, h.client)
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("conn3x_vyos_device: %w", err))
		return resp
	}
	vals := req.Config.AsValueMap()
	vals["hostname"] = cty.StringVal(f.Hostname)
	vals["version"] = cty.StringVal(f.Version)
	resp.State = cty.ObjectVal(vals)
	return resp
}

// vyosCommitTypes are the resources circuits add for VyOS routers.
var vyosCommitTypes = cliCommitTypes(vyosPlatform)
