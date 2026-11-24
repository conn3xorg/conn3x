// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/conn3x/modules/ios"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
	"github.com/opentofu/opentofu/internal/providers"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

const (
	iosTypePrefix   = "conn3x_ios_"
	iosExperimental = "Experimental. "
)

var iosPlatform = &cliPlatform{
	name:       "ios",
	running:    func(ctx context.Context, c cliDevice) (string, error) { return ios.RunningConfig(ctx, c) },
	pending:    func(ctx context.Context, c cliDevice) (string, error) { return ios.Pending(ctx, c) },
	pendingErr: func(says string) error { return ios.PendingError{Says: says} },
	check:      func(ctx context.Context, c cliDevice, cmds []string) error { return ios.Check(ctx, c, cmds) },
	apply: func(ctx context.Context, c cliDevice, reconnect func(context.Context) (*ssh.Client, error), base string, cmds []string, after time.Duration) (string, error) {
		return ios.Apply(ctx, c, func(ctx context.Context) (ios.Device, error) { return reconnect(ctx) }, base, cmds, after)
	},
	notLive: func(err error) bool {
		return errors.As(err, new(ios.NotLiveError)) || errors.As(err, new(ios.PendingError))
	},
	defaultConfirm: ios.DefaultConfirmAfter,
	revertAfter:    ios.RevertAfter,
	merge:          ios.WithLines,
	perCommand:     true,
}

var iosCommitTypes = cliCommitTypes(iosPlatform)

// validateIOSSSH rejects the ssh settings an IOS CLI login has no use for.
func validateIOSSSH(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() || !cfg.Type().HasAttribute("ssh") {
		return diags
	}
	conn := cfg.GetAttr("ssh")
	if conn.IsNull() || !conn.IsKnown() {
		return diags
	}
	for attr, why := range map[string]string{
		"agent":                "The conn3x agent needs a shell, and an IOS login has the CLI instead. Remove agent from this ssh block.",
		"become":               "IOS has no sudo. Log in as a user with privilege 15 (\"username ops privilege 15 ...\"), and remove become from this ssh block.",
		"become_password_file": "IOS has no sudo, so there is no password to give it. Remove become_password_file from this ssh block.",
	} {
		v := conn.GetAttr(attr)
		if v.IsNull() || !v.IsKnown() || (v.Type() == cty.Bool && v.False()) {
			continue
		}
		diags = diags.Append(tfdiags.AttributeValue(tfdiags.Error, "Invalid ssh setting for a Cisco IOS device", why,
			cty.GetAttrPath("ssh").GetAttr(attr)))
	}
	if v := optional(conn, "confirm_after"); known(v) {
		if d, err := time.ParseDuration(v.AsString()); err == nil {
			if err := ios.CheckConfirmAfter(d); err != nil {
				diags = diags.Append(tfdiags.AttributeValue(tfdiags.Error, "Invalid ssh confirm_after", err.Error(),
					cty.GetAttrPath("ssh").GetAttr("confirm_after")))
			}
		}
	}
	return diags
}

func iosConfigFrom(v cty.Value) ios.Config {
	c := ios.Config{Lines: stringList(v.GetAttr("lines")), Match: stringOr(v.GetAttr("match"), ios.MatchLines), Prefixes: stringList(v.GetAttr("lines_wo_prefixes"))}
	if p := v.GetAttr("parents"); known(p) {
		c.Parents = stringList(p)
	}
	return c
}

var iosConfigKind = cliKind{
	p:        iosPlatform,
	name:     "config",
	keys:     []string{"parents"},
	settings: []string{"lines", "match", "lines_hmac", "lines_wo_prefixes"},
	config:   func(v cty.Value) cliWant { return iosConfigFrom(v) },
	remove:   func(v cty.Value, running string) []string { return iosConfigFrom(v).RemoveCommands(running) },
}

func iosConfigSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: iosExperimental + "Lines of a Cisco IOS XE device's running configuration, under parent blocks or at the top level. Only the lines named here are owned; with match = \"block\" the block must be exactly these.",
		Attributes: map[string]*configschema.Attribute{
			"id":                {Type: cty.String, Computed: true},
			"revision":          revisionAttr(),
			"parents":           {Type: cty.List(cty.String), Optional: true, Description: "The blocks the lines sit in, outermost first, as show running-config prints them, such as [\"interface GigabitEthernet1\"]. Unset is the top level."},
			"lines":             {Type: cty.List(cty.String), Optional: true, Description: "The lines, exactly as show running-config prints them without their indent, such as \"description uplink\". A line the device prints differently never shows as in sync. State keeps them, so put lines holding a secret in lines_wo."},
			"lines_wo":          {Type: cty.List(cty.String), Optional: true, Sensitive: true, WriteOnly: true, Description: "Write-only: lines that hold a secret, such as \"tacacs-server key MyKey\", \"key MyKey\" under a tacacs server, or \"ntp authentication-key 1 md5 MyKey\", never kept in state. The device shows these encrypted or hashed, so each is matched by its start, the line up to its secret (\"tacacs-server key\", \"ntp authentication-key 1\"): it owns every line under the parents that starts that way, and is in sync when one is there. A change to any of them sends them all again, and IOS replaces each in place. snmp-server community lines are refused, since the community is its own name."},
			"lines_hmac":        {Type: cty.String, Computed: true, Description: "An HMAC of lines_wo, keyed outside state, so a change plans an update."},
			"lines_wo_prefixes": {Type: cty.List(cty.String), Computed: true, Description: "How each lines_wo line starts, up to its secret, such as \"tacacs-server key\". A refresh checks these are there, and a removal takes them out."},
			"match":             {Type: cty.String, Optional: true, Description: "\"lines\" (default): these lines must be there, and others are left alone. \"block\": the block under parents must be exactly these lines, so others are removed. Needs parents."},
			"on_remove":         {Type: cty.String, Optional: true, Computed: true, Description: "What happens on the device when this resource is removed: \"forget\" (default) leaves the lines, \"delete\" removes them with their \"no\" form."},
			"in_sync":           {Type: cty.Bool, Computed: true, Description: "Whether the device had these lines at the last refresh."},
			"circuit":           eosCircuitAttr(),
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func validateIOSConfig(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() || !settled(cfg) {
		return diags
	}
	diags = diags.Append(validateOnRemove(cfg))
	c := iosConfigFrom(cfg)
	c.Secrets = stringList(cfg.GetAttr("lines_wo"))
	if err := c.Validate(); err != nil {
		diags = diags.Append(attrError("lines", err.Error()))
	}
	return diags
}

var planIOSConfig, applyIOSConfig = cliLinesWO(iosConfigKind, linesWO{kind: "ios_config", block: "parents", start: ios.SecretPrefix},
	func(v cty.Value, secrets, prefixes []string, resend bool) cliWant {
		c := iosConfigFrom(v)
		c.Secrets, c.Prefixes, c.Resend = secrets, prefixes, resend
		return c
	})

var iosHostnameKind = cliKind{
	p:        iosPlatform,
	name:     "hostname",
	settings: []string{"name"},
	config:   func(v cty.Value) cliWant { return ios.Hostname{Name: v.GetAttr("name").AsString()} },
}

func iosHostnameSchema() providers.Schema {
	s := singletonSchema(iosExperimental+"A Cisco IOS XE device's hostname. Removing this step leaves the name as it is.",
		"Hostname, such as edge01. IOS takes letters, digits and hyphens, starting with a letter.")
	s.Block.Attributes["in_sync"].Description = "Whether the device had this name at the last refresh."
	s.Block.Attributes["circuit"] = eosCircuitAttr()
	return s
}

func validateIOSHostname(cfg cty.Value) tfdiags.Diagnostics {
	return validateName(cfg, ios.ValidateHostname)
}

func iosInterfaceFrom(v cty.Value) ios.Interface {
	i := ios.Interface{Name: stringOr(v.GetAttr("name"), ""), Description: optString(v.GetAttr("description")), Mode: stringOr(v.GetAttr("mode"), "")}
	if e := v.GetAttr("enabled"); known(e) {
		b := e.True()
		i.Enabled = &b
	}
	num := func(attr string) int {
		n := v.GetAttr(attr)
		if !known(n) {
			return 0
		}
		x, _ := n.AsBigFloat().Int64()
		return int(x)
	}
	i.AccessVLAN, i.MTU = num("access_vlan"), num("mtu")
	if l := v.GetAttr("allowed_vlans"); known(l) {
		i.AllowedVLANs = []int{}
		for _, e := range l.AsValueSlice() {
			x, _ := e.AsBigFloat().Int64()
			i.AllowedVLANs = append(i.AllowedVLANs, int(x))
		}
	}
	return i
}

var iosInterfaceKind = cliKind{
	p:        iosPlatform,
	name:     "interface",
	keys:     []string{"name"},
	settings: []string{"description", "enabled", "mode", "access_vlan", "allowed_vlans", "mtu"},
	config:   func(v cty.Value) cliWant { return iosInterfaceFrom(v) },
	remove:   func(v cty.Value, running string) []string { return iosInterfaceFrom(v).RemoveCommands(running) },
	guard:    func(v cty.Value, config, address string) error { return iosInterfaceFrom(v).Guard(config, address) },
}

func iosInterfaceSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: iosExperimental + "The settings Conn3x owns on one interface of a Cisco IOS XE device: description, enabled, switchport mode and VLANs, MTU. Each one left unset is left alone, and so is every other line under the interface.",
		Attributes: map[string]*configschema.Attribute{
			"id":            {Type: cty.String, Computed: true},
			"revision":      revisionAttr(),
			"name":          {Type: cty.String, Required: true, Description: "The interface, as show running-config names it, such as GigabitEthernet1/0/1, Port-channel10, Vlan20 or Loopback0."},
			"description":   {Type: cty.String, Optional: true, Description: "Its description."},
			"enabled":       {Type: cty.Bool, Optional: true, Description: "false shuts it down, true brings it up. Shutting down the interface whose address Conn3x connects to is refused."},
			"mode":          {Type: cty.String, Optional: true, Description: "\"access\" or \"trunk\". Ethernet and Port-channel interfaces only."},
			"access_vlan":   {Type: cty.Number, Optional: true, Description: "The VLAN of an access port, 1 to 4094."},
			"allowed_vlans": {Type: cty.List(cty.Number), Optional: true, Description: "The VLANs a trunk carries. They're compared as a set, so a list IOS prints over several add lines still reads as in sync."},
			"mtu":           {Type: cty.Number, Optional: true, Description: "MTU, 64 to 9216. The device refuses a value outside its own range."},
			"on_remove":     {Type: cty.String, Optional: true, Computed: true, Description: "What happens when this resource is removed: \"forget\" (default) leaves the interface as it is, \"delete\" takes the settings it owns back to IOS's defaults. The interface itself stays."},
			"in_sync":       {Type: cty.Bool, Computed: true, Description: "Whether the interface had these settings at the last refresh."},
			"circuit":       eosCircuitAttr(),
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func validateIOSInterface(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() || !settled(cfg) {
		return diags
	}
	diags = diags.Append(validateOnRemove(cfg))
	if err := iosInterfaceFrom(cfg).Validate(); err != nil {
		diags = diags.Append(attrError("name", err.Error()))
	}
	return diags
}

func iosVLANFrom(v cty.Value) ios.VLAN {
	id, _ := v.GetAttr("vlan_id").AsBigFloat().Int64()
	return ios.VLAN{ID: int(id), Name: stringOr(v.GetAttr("name"), "")}
}

var iosVLANKind = cliKind{
	p:        iosPlatform,
	name:     "vlan",
	keys:     []string{"vlan_id"},
	settings: []string{"name"},
	deletes:  true,
	config:   func(v cty.Value) cliWant { return iosVLANFrom(v) },
	remove:   func(v cty.Value, running string) []string { return iosVLANFrom(v).RemoveCommands(running) },
	guard:    func(_ cty.Value, config, _ string) error { return ios.VTPLocal(config) },
}

func iosVLANSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: iosExperimental + "A VLAN on a Cisco IOS XE switch, and its name. The switch must be in VTP transparent mode.",
		Attributes: map[string]*configschema.Attribute{
			"id":        {Type: cty.String, Computed: true},
			"revision":  revisionAttr(),
			"vlan_id":   {Type: cty.Number, Required: true, Description: "VLAN ID, 2 to 4094, except 1002 to 1005, which IOS keeps for itself."},
			"name":      {Type: cty.String, Optional: true, Description: "VLAN name: one word, up to 32 characters. Leave unset for the switch's default, such as VLAN0010; a name set by hand is then removed."},
			"on_remove": {Type: cty.String, Optional: true, Computed: true, Description: "What happens on the switch when this resource is removed: \"delete\" (default) removes the VLAN, \"forget\" leaves it."},
			"in_sync":   {Type: cty.Bool, Computed: true, Description: "Whether the VLAN was there, with this name, at the last refresh."},
			"circuit":   eosCircuitAttr(),
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func validateIOSVLAN(cfg cty.Value) tfdiags.Diagnostics {
	return validateWith("vlan_id", func(v cty.Value) error { return iosVLANFrom(v).Validate() })(cfg)
}

func iosStaticRouteFrom(v cty.Value) ios.StaticRoute {
	var r ios.StaticRoute
	r.Prefix = stringOr(v.GetAttr("prefix"), "")
	if l := v.GetAttr("next_hops"); known(l) {
		r.NextHops = stringList(l)
	}
	if d := v.GetAttr("distance"); known(d) {
		n, _ := d.AsBigFloat().Int64()
		r.Distance = int(n)
	}
	return r
}

var iosStaticRouteKind = cliKind{
	p:        iosPlatform,
	name:     "static_route",
	keys:     []string{"prefix"},
	settings: []string{"next_hops", "distance"},
	config:   func(v cty.Value) cliWant { return iosStaticRouteFrom(v) },
	remove:   func(v cty.Value, running string) []string { return iosStaticRouteFrom(v).RemoveCommands(running) },
}

func iosStaticRouteSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: iosExperimental + "One static route on a Cisco IOS XE device, owned whole: its next hops are exactly these, and any other next hop for the prefix, such as Null0, is removed.",
		Attributes: map[string]*configschema.Attribute{
			"id":        {Type: cty.String, Computed: true},
			"revision":  revisionAttr(),
			"prefix":    {Type: cty.String, Required: true, Description: "The network, such as 10.20.0.0/16 or 2001:db8:20::/48. Conn3x writes an IPv4 one with a dotted mask, as IOS prints it."},
			"next_hops": {Type: cty.List(cty.String), Required: true, Description: "The next hop addresses, of the prefix's family."},
			"distance":  {Type: cty.Number, Optional: true, Description: "The administrative distance of each next hop, 1 to 255; lower wins. Unset is IOS's default, 1."},
			"on_remove": {Type: cty.String, Optional: true, Computed: true, Description: "What happens on the device when this resource is removed: \"forget\" (default) leaves the route, \"delete\" removes every next hop of it."},
			"in_sync":   {Type: cty.Bool, Computed: true, Description: "Whether the device had this route, and no other next hop for it, at the last refresh."},
			"circuit":   eosCircuitAttr(),
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func validateIOSStaticRoute(cfg cty.Value) tfdiags.Diagnostics {
	return validateWith("prefix", func(v cty.Value) error { return iosStaticRouteFrom(v).Validate() })(cfg)
}

// iosDeviceSchema is the conn3x_ios_device data source: what a circuit
// checks before it changes a device.
func iosDeviceSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: iosExperimental + "Facts about a Cisco IOS or IOS XE device, from show version.",
		Attributes: map[string]*configschema.Attribute{
			"hostname": {Type: cty.String, Computed: true, Description: "The device's hostname."},
			"model":    {Type: cty.String, Computed: true, Description: "Model, such as C9300-48P, or IOL-XE in Cisco Modeling Labs."},
			"version":  {Type: cty.String, Computed: true, Description: "Software version, such as 17.18.01 or 15.9(3)M4."},
			"serial":   {Type: cty.String, Computed: true, Description: "The processor board ID."},
			"image":    {Type: cty.String, Computed: true, Description: "The system image file the device booted."},
			"ios_type": {Type: cty.String, Computed: true, Description: "\"IOS-XE\" or \"IOS\"."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func readIOSDevice(ctx context.Context, req providers.ReadDataSourceRequest) providers.ReadDataSourceResponse {
	var resp providers.ReadDataSourceResponse
	conn := req.Config.GetAttr("ssh")
	h, err := iosPlatform.hostFor(ctx, conn)
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(attrError("ssh", err.Error()))
		return resp
	}
	f, err := ios.ReadFacts(ctx, iosPlatform.device(h, conn))
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("conn3x_ios_device: %w", err))
		return resp
	}
	vals := req.Config.AsValueMap()
	for k, v := range map[string]string{"hostname": f.Hostname, "model": f.Model, "version": f.Version, "serial": f.Serial, "image": f.Image, "ios_type": f.Type} {
		vals[k] = cty.StringVal(v)
	}
	resp.State = cty.ObjectVal(vals)
	return resp
}
