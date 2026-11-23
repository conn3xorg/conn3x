// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"crypto/hmac"
	"errors"
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
	c := vyos.Config(stringOr(v.GetAttr("prefix"), ""), stringList(v.GetAttr("lines")), stringOr(v.GetAttr("match"), setcfg.MatchLines))
	c.Paths = stringList(v.GetAttr("lines_wo_prefixes"))
	return c
}

var vyosConfigKind = cliKind{
	p:        vyosPlatform,
	name:     "config",
	keys:     []string{"prefix"},
	settings: []string{"lines", "match", "lines_hmac", "lines_wo_prefixes"},
	config:   func(v cty.Value) cliWant { return vyosConfigFrom(v) },
	remove:   func(v cty.Value, running string) []string { return vyosConfigFrom(v).RemoveCommands(running) },
	warn:     func(_ cty.Value, config string) string { return vyosWarnReboot(config) },
}

var planVyOSConfig, applyVyOSConfig = cliLinesWO(vyosConfigKind, linesWO{kind: "vyos_config", block: "prefix", start: setcfg.SecretPath, norm: vyos.Normalize},
	func(v cty.Value, secrets, paths []string, resend bool) cliWant {
		c := vyosConfigFrom(v)
		c.Secrets, c.Paths, c.Resend = secrets, paths, resend
		return c
	})

func vyosConfigSchema() providers.Schema {
	return setLinesWO(providers.Schema{Block: &configschema.Block{
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
	}}, `"set protocols bgp 65000 neighbor 192.0.2.1 password 'MyPassword'"`)
}

func validateVyOSConfig(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() || !cfg.IsWhollyKnown() {
		return diags
	}
	diags = diags.Append(validateOnRemove(cfg))
	return diags.Append(validateSetLinesWO(cfg, vyosConfigFrom(cfg), vyos.Normalize))
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

func vyosStaticRouteFrom(v cty.Value) vyos.StaticRoute {
	r := vyos.StaticRoute{Prefix: stringOr(v.GetAttr("prefix"), ""), Distance: intOr(v.GetAttr("distance"), 0)}
	if l := v.GetAttr("next_hops"); known(l) {
		r.NextHops = stringList(l)
	}
	return r
}

var vyosStaticRouteKind = cliKind{
	p:        vyosPlatform,
	name:     "static_route",
	keys:     []string{"prefix"},
	settings: []string{"next_hops", "distance"},
	config:   func(v cty.Value) cliWant { return vyosStaticRouteFrom(v) },
	remove:   func(v cty.Value, running string) []string { return vyosStaticRouteFrom(v).RemoveCommands(running) },
	warn:     func(_ cty.Value, config string) string { return vyosWarnReboot(config) },
}

func vyosStaticRouteSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: junosExperimental + "One static route on a VyOS router, owned whole: its next hops are exactly these, and anything else under the route is deleted.",
		Attributes: map[string]*configschema.Attribute{
			"id":        {Type: cty.String, Computed: true},
			"revision":  revisionAttr(),
			"prefix":    {Type: cty.String, Required: true, Description: "The network, such as 10.20.0.0/16 or 2001:db8:20::/48. An IPv6 one goes under route6."},
			"next_hops": {Type: cty.List(cty.String), Required: true, Description: "The next hop addresses, of the prefix's family. With more than one, VyOS spreads traffic across them."},
			"distance":  {Type: cty.Number, Optional: true, Description: "Administrative distance for every next hop, 1 to 255. Unset is VyOS's default, 1; 255 disables the route."},
			"on_remove": {Type: cty.String, Optional: true, Computed: true, Description: "What happens on the router when this resource is removed: \"forget\" (default) leaves the route, \"delete\" deletes it."},
			"in_sync":   {Type: cty.Bool, Computed: true, Description: "Whether the router had this route, and nothing else under it, at the last refresh."},
			"circuit":   eosCircuitAttr(),
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func validateVyOSStaticRoute(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() || !cfg.IsWhollyKnown() {
		return diags
	}
	diags = diags.Append(validateOnRemove(cfg))
	if err := vyosStaticRouteFrom(cfg).Validate(); err != nil {
		diags = diags.Append(attrError("prefix", err.Error()))
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
	f, err := vyos.ReadFacts(ctx, h.raw())
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

func vyosUserFrom(v cty.Value) vyos.User {
	u := vyos.User{Name: stringOr(v.GetAttr("name"), ""), FullName: optString(v.GetAttr("full_name"))}
	if l := v.GetAttr("ssh_keys"); known(l) {
		u.SSHKeys = append([]string{}, stringList(l)...)
	}
	// password_hmac is unknown while a new password is planned.
	stored := v.GetAttr("password_hmac")
	u.WantSecret = !stored.IsNull()
	// Without the key that made password_hmac, a read can't tell which
	// password the router holds, only that it has one.
	if key, err := hmacKey(false); err == nil && known(stored) && checkHMACKey(stored.AsString(), key) == nil {
		id := vyosUserID(v)
		u.SecretIs = func(hash string) bool {
			return hmac.Equal([]byte(eosSecretHMAC(key, id, hash)), []byte(stored.AsString()))
		}
	}
	return u
}

func vyosUserID(v cty.Value) string {
	return passwordID("vyos_user", stringOr(v.GetAttr("ssh").GetAttr("host"), ""), stringOr(v.GetAttr("name"), ""))
}

var vyosUserKind = cliKind{
	p:        vyosPlatform,
	name:     "user",
	keys:     []string{"name"},
	settings: []string{"full_name", "ssh_keys", "password_hmac"},
	deletes:  true,
	config:   func(v cty.Value) cliWant { return vyosUserFrom(v) },
	remove:   func(v cty.Value, running string) []string { return vyosUserFrom(v).RemoveCommands(running) },
	guard: func(v cty.Value, _, _ string) error {
		return vyosUserFrom(v).Guard(stringOr(v.GetAttr("ssh").GetAttr("user"), ""))
	},
	warn: func(_ cty.Value, config string) string { return vyosWarnReboot(config) },
}

func vyosUserSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: junosExperimental + "A local account on a VyOS router: its full name, password and SSH keys. Every VyOS account can configure the router. Conn3x won't delete the account it logs in as, or take all its keys away.",
		Attributes: map[string]*configschema.Attribute{
			"id":            {Type: cty.String, Computed: true},
			"revision":      revisionAttr(),
			"name":          {Type: cty.String, Required: true, Description: "The account name: lower-case letters, digits, _ . and -. Not root."},
			"full_name":     {Type: cty.String, Optional: true, Description: "The account's full name or description. No quotes. Unset leaves it alone."},
			"password_wo":   {Type: cty.String, Optional: true, Sensitive: true, WriteOnly: true, Description: "Write-only: the password, never kept in state. Conn3x hashes it here and sends the router the salted SHA-512 crypt hash, as encrypted-password, so the password itself never reaches the CLI; a new value plans a change through password_hmac. Unset leaves the account's password alone."},
			"password_hmac": {Type: cty.String, Computed: true, Description: "An HMAC of the hash the router should hold for password_wo, keyed outside state. A new password plans a change, and a refresh finds an account with another one out of sync."},
			"ssh_keys":      {Type: cty.List(cty.String), Optional: true, Description: "The account's public keys, one line each, such as \"ssh-ed25519 AAAA... alice@laptop\". Each is labelled on the router by its comment, or by a hash of the key without one. Keys not listed are deleted; [] deletes them all, and unset leaves them alone."},
			"on_remove":     {Type: cty.String, Optional: true, Computed: true, Description: "\"delete\" (default) deletes the account when the step goes, as with every step that grants access; \"forget\" leaves it."},
			"in_sync":       {Type: cty.Bool, Computed: true, Description: "Whether the account matched at the last refresh."},
			"circuit":       eosCircuitAttr(),
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func validateVyOSUser(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() || !cfg.IsWhollyKnown() {
		return diags
	}
	diags = diags.Append(validateOnRemove(cfg))
	if err := vyosUserFrom(cfg).Validate(); err != nil {
		diags = diags.Append(attrError("name", err.Error()))
	}
	return diags
}

func planVyOSUser(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	return planPasswordAs(deleteByDefault(req), "vyos_user", vyosUserKind.settings, planSynced, eosPasswordHMAC)
}

// applyVyOSUser hashes the step's password, which only the config holds,
// as applyJunosUser does: VyOS takes the salted SHA-512 crypt hash as
// encrypted-password.
func applyVyOSUser(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	if req.PlannedState.IsNull() && !req.PriorState.IsNull() && req.PriorState.GetAttr("on_remove").AsString() == onRemoveDelete {
		if name := req.PriorState.GetAttr("name").AsString(); name == stringOr(req.PriorState.GetAttr("ssh").GetAttr("user"), "") {
			var resp providers.ApplyResourceChangeResponse
			resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("vyos_user: Conn3x logs in as %s, so it won't delete that account; set on_remove = \"forget\" to drop the step", name))
			return resp
		}
	}
	k := vyosUserKind
	var mac string
	if !req.PlannedState.IsNull() && vyosUserFrom(req.PlannedState).WantSecret {
		var resp providers.ApplyResourceChangeResponse
		password := ""
		if !req.Config.IsNull() {
			password = stringOr(req.Config.GetAttr("password_wo"), "")
		}
		if password == "" {
			resp.Diagnostics = resp.Diagnostics.Append(errors.New("vyos_user: password_wo didn't reach the apply; it's write-only, so set it in the step's config"))
			return resp
		}
		key, err := hmacKey(true)
		if err != nil {
			resp.Diagnostics = resp.Diagnostics.Append(attrError("password_wo", err.Error()))
			return resp
		}
		id := vyosUserID(req.PlannedState)
		hash := eosSecret(key, id, password)
		mac = eosSecretHMAC(key, id, hash)
		k.config = func(v cty.Value) cliWant {
			u := vyosUserFrom(v)
			u.Secret, u.SecretIs = hash, func(h string) bool { return h == hash }
			return u
		}
	}
	resp := k.apply(ctx, req)
	if !resp.NewState.IsNull() {
		vals := resp.NewState.AsValueMap()
		vals["password_wo"] = cty.NullVal(cty.String)
		if mac != "" {
			vals["password_hmac"] = cty.StringVal(mac)
		}
		resp.NewState = cty.ObjectVal(vals)
	}
	return resp
}
