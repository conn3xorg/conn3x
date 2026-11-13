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
	"github.com/opentofu/opentofu/internal/conn3x/modules/junos"
	"github.com/opentofu/opentofu/internal/providers"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

const junosTypePrefix = "conn3x_junos_"

// junosExperimental starts every Junos description, so the reference says so.
const junosExperimental = "Experimental. "

// validateJunosSSH rejects the ssh settings a Junos CLI login has no use for,
// and root, whose login starts in a shell.
func validateJunosSSH(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() || !cfg.Type().HasAttribute("ssh") {
		return diags
	}
	conn := cfg.GetAttr("ssh")
	if conn.IsNull() || !conn.IsKnown() {
		return diags
	}
	for attr, why := range map[string]string{
		"agent":                "The conn3x agent needs a shell, and a Junos login has the CLI instead. Remove agent from this ssh block.",
		"become":               "Junos has no sudo. Log in as a user of class super-user, and remove become from this ssh block.",
		"become_password_file": "Junos has no sudo, so there is no password to give it. Remove become_password_file from this ssh block.",
	} {
		v := conn.GetAttr(attr)
		if v.IsNull() || !v.IsKnown() || (v.Type() == cty.Bool && v.False()) {
			continue
		}
		diags = diags.Append(tfdiags.AttributeValue(tfdiags.Error, "Invalid ssh setting for a Junos device", why,
			cty.GetAttrPath("ssh").GetAttr(attr)))
	}
	if v := optional(conn, "user"); known(v) && v.AsString() == "root" {
		diags = diags.Append(tfdiags.AttributeValue(tfdiags.Error, "Invalid ssh user for a Junos device", junos.ErrShellLogin.Error()+".",
			cty.GetAttrPath("ssh").GetAttr("user")))
	}
	if v := optional(conn, "confirm_after"); known(v) {
		if d, err := time.ParseDuration(v.AsString()); err == nil {
			if err := junos.CheckConfirmAfter(d); err != nil {
				diags = diags.Append(tfdiags.AttributeValue(tfdiags.Error, "Invalid ssh confirm_after", err.Error(),
					cty.GetAttrPath("ssh").GetAttr("confirm_after")))
			}
		}
	}
	return diags
}

func junosConfigFrom(v cty.Value) junos.Config {
	return junos.Config{Prefix: stringOr(v.GetAttr("prefix"), ""), Lines: stringList(v.GetAttr("lines")), Match: stringOr(v.GetAttr("match"), junos.MatchLines)}
}

var junosConfigKind = cliKind{
	p:        junosPlatform,
	name:     "config",
	keys:     []string{"prefix"},
	settings: []string{"lines", "match"},
	config:   func(v cty.Value) cliWant { return junosConfigFrom(v) },
	remove:   func(v cty.Value, running string) []string { return junosConfigFrom(v).RemoveCommands(running) },
}

func junosConfigSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: junosExperimental + "Statements of a Juniper Junos device's configuration, as set lines. Only the lines named here are owned; with match = \"block\" the statements under prefix must be exactly these.",
		Attributes: map[string]*configschema.Attribute{
			"id":        {Type: cty.String, Computed: true},
			"revision":  revisionAttr(),
			"lines":     {Type: cty.List(cty.String), Optional: true, Description: "Set statements, exactly as show configuration | display set prints them, such as \"set interfaces ge-0/0/1 description uplink\". The device must print a line back exactly as written, or it never shows as in sync."},
			"prefix":    {Type: cty.String, Optional: true, Description: "With match = \"block\": the hierarchy the lines own, such as \"interfaces ge-0/0/1\". Every line must start with set and this prefix."},
			"match":     {Type: cty.String, Optional: true, Description: "\"lines\" (default): these statements must be there, and others are left alone. \"block\": the statements under prefix must be exactly these, so others under it are deleted. Needs prefix."},
			"on_remove": {Type: cty.String, Optional: true, Computed: true, Description: "What happens on the device when this resource is removed: \"forget\" (default) leaves the statements, \"delete\" deletes them."},
			"in_sync":   {Type: cty.Bool, Computed: true, Description: "Whether the device had these statements at the last refresh."},
			"circuit":   eosCircuitAttr(),
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func validateJunosConfig(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() || !cfg.IsWhollyKnown() {
		return diags
	}
	diags = diags.Append(validateOnRemove(cfg))
	if err := junosConfigFrom(cfg).Validate(); err != nil {
		diags = diags.Append(attrError("lines", err.Error()))
	}
	return diags
}

var junosHostnameKind = cliKind{
	p:        junosPlatform,
	name:     "hostname",
	settings: []string{"name"},
	config:   func(v cty.Value) cliWant { return junos.Hostname(v.GetAttr("name").AsString()) },
}

func junosHostnameSchema() providers.Schema {
	s := singletonSchema(junosExperimental+"A Juniper Junos device's host name. Removing this step leaves the name as it is.",
		"Host name, such as sw1. Junos takes letters, digits, hyphens and dots.")
	s.Block.Attributes["in_sync"].Description = "Whether the device had this name at the last refresh."
	s.Block.Attributes["circuit"] = eosCircuitAttr()
	return s
}

func validateJunosHostname(cfg cty.Value) tfdiags.Diagnostics {
	return validateName(cfg, junos.ValidateHostname)
}

func junosVLANFrom(v cty.Value) junos.VLAN {
	id, _ := v.GetAttr("vlan_id").AsBigFloat().Int64()
	return junos.VLAN{Name: stringOr(v.GetAttr("name"), ""), ID: int(id)}
}

var junosVLANKind = cliKind{
	p:        junosPlatform,
	name:     "vlan",
	keys:     []string{"name"},
	settings: []string{"vlan_id"},
	deletes:  true,
	config:   func(v cty.Value) cliWant { return junosVLANFrom(v) },
	remove:   func(v cty.Value, running string) []string { return junosVLANFrom(v).RemoveCommands(running) },
}

func junosVLANSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: junosExperimental + "A VLAN on a Juniper EX or QFX switch running ELS, by name, and its ID. Interfaces and descriptions on it are left alone.",
		Attributes: map[string]*configschema.Attribute{
			"id":        {Type: cty.String, Computed: true},
			"revision":  revisionAttr(),
			"name":      {Type: cty.String, Required: true, Description: "VLAN name, as Junos keys VLANs, such as users. It starts with a letter."},
			"vlan_id":   {Type: cty.Number, Required: true, Description: "VLAN ID, 1 to 4094."},
			"on_remove": {Type: cty.String, Optional: true, Computed: true, Description: "What happens on the device when this resource is removed: \"delete\" (default) deletes the VLAN, everything under it included; \"forget\" leaves it."},
			"in_sync":   {Type: cty.Bool, Computed: true, Description: "Whether the VLAN was there with this ID at the last refresh."},
			"circuit":   eosCircuitAttr(),
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func validateJunosVLAN(cfg cty.Value) tfdiags.Diagnostics {
	return validateWith("name", func(v cty.Value) error { return junosVLANFrom(v).Validate() })(cfg)
}

// junosDeviceSchema is the conn3x_junos_device data source: what a circuit
// checks before it changes a device.
func junosDeviceSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: junosExperimental + "Facts about a Juniper Junos device, from show version.",
		Attributes: map[string]*configschema.Attribute{
			"hostname": {Type: cty.String, Computed: true, Description: "The device's host name."},
			"model":    {Type: cty.String, Computed: true, Description: "Model, such as ex4400-48t, or ex9214 for vJunos-switch."},
			"version":  {Type: cty.String, Computed: true, Description: "Junos version, such as 26.2R1.7."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func readJunosDevice(ctx context.Context, req providers.ReadDataSourceRequest) providers.ReadDataSourceResponse {
	var resp providers.ReadDataSourceResponse
	h, err := pooled(ctx, req.Config.GetAttr("ssh"), 0)
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(attrError("ssh", err.Error()))
		return resp
	}
	f, err := junos.ReadFacts(ctx, h.client)
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("conn3x_junos_device: %w", err))
		return resp
	}
	vals := req.Config.AsValueMap()
	vals["hostname"] = cty.StringVal(f.Hostname)
	vals["model"] = cty.StringVal(f.Model)
	vals["version"] = cty.StringVal(f.Version)
	resp.State = cty.ObjectVal(vals)
	return resp
}

func junosInterfaceFrom(v cty.Value) junos.Interface {
	i := junos.Interface{Name: stringOr(v.GetAttr("name"), ""), Description: optString(v.GetAttr("description")), Mode: stringOr(v.GetAttr("mode"), ""), AccessVLAN: stringOr(v.GetAttr("access_vlan"), "")}
	if e := v.GetAttr("enabled"); known(e) {
		b := e.True()
		i.Enabled = &b
	}
	if n := v.GetAttr("mtu"); known(n) {
		x, _ := n.AsBigFloat().Int64()
		i.MTU = int(x)
	}
	if l := v.GetAttr("allowed_vlans"); known(l) {
		i.AllowedVLANs = append([]string{}, stringList(l)...)
	}
	return i
}

var junosInterfaceKind = cliKind{
	p:        junosPlatform,
	name:     "interface",
	keys:     []string{"name"},
	settings: []string{"description", "enabled", "mode", "access_vlan", "allowed_vlans", "mtu"},
	config:   func(v cty.Value) cliWant { return junosInterfaceFrom(v) },
	remove:   func(v cty.Value, running string) []string { return junosInterfaceFrom(v).RemoveCommands(running) },
	guard:    func(v cty.Value, config, address string) error { return junosInterfaceFrom(v).Guard(config, address) },
}

func junosInterfaceSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: junosExperimental + "The settings Conn3x owns on one interface of a Juniper Junos device: description, enabled, MTU, and on an ELS switch port the interface-mode and VLAN members. Each one left unset is left alone, and so is every other statement under the interface.",
		Attributes: map[string]*configschema.Attribute{
			"id":            {Type: cty.String, Computed: true},
			"revision":      revisionAttr(),
			"name":          {Type: cty.String, Required: true, Description: "The interface, such as ge-0/0/1, xe-0/0/48, ae0, irb or lo0."},
			"description":   {Type: cty.String, Optional: true, Description: "Its description. No double quotes or backslashes."},
			"enabled":       {Type: cty.Bool, Optional: true, Description: "false disables it, true deletes the disable. Disabling a management interface (fxp0, em0, me0, vme), or the one whose address Conn3x connects to, is refused."},
			"mode":          {Type: cty.String, Optional: true, Description: "\"access\" or \"trunk\": unit 0 family ethernet-switching interface-mode. Switch ports and ae interfaces only."},
			"access_vlan":   {Type: cty.String, Optional: true, Description: "The VLAN of an access port, by name or ID, as vlan members."},
			"allowed_vlans": {Type: cty.List(cty.String), Optional: true, Description: "The VLANs a trunk carries, by name, ID or range such as 20-22. Members not listed are deleted."},
			"mtu":           {Type: cty.Number, Optional: true, Description: "MTU, 256 to 9216."},
			"on_remove":     {Type: cty.String, Optional: true, Computed: true, Description: "What happens when this resource is removed: \"forget\" (default) leaves the interface as it is, \"delete\" deletes the statements it owns. The interface itself stays."},
			"in_sync":       {Type: cty.Bool, Computed: true, Description: "Whether the interface had these settings at the last refresh."},
			"circuit":       eosCircuitAttr(),
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func validateJunosInterface(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() || !cfg.IsWhollyKnown() {
		return diags
	}
	diags = diags.Append(validateOnRemove(cfg))
	if err := junosInterfaceFrom(cfg).Validate(); err != nil {
		diags = diags.Append(attrError("name", err.Error()))
	}
	return diags
}

func junosUserFrom(v cty.Value) junos.User {
	u := junos.User{Name: stringOr(v.GetAttr("name"), ""), Class: stringOr(v.GetAttr("class"), "")}
	if l := v.GetAttr("ssh_keys"); known(l) {
		u.SSHKeys = append([]string{}, stringList(l)...)
	}
	// password_hmac is unknown while a new password is planned.
	stored := v.GetAttr("password_hmac")
	u.WantSecret = !stored.IsNull()
	// Without the key that made password_hmac, a read can't tell which
	// password the device holds, only that it has one.
	if key, err := hmacKey(false); err == nil && known(stored) && checkHMACKey(stored.AsString(), key) == nil {
		id := junosUserID(v)
		u.SecretIs = func(hash string) bool {
			return hmac.Equal([]byte(eosSecretHMAC(key, id, hash)), []byte(stored.AsString()))
		}
	}
	return u
}

func junosUserID(v cty.Value) string {
	return passwordID("junos_user", stringOr(v.GetAttr("ssh").GetAttr("host"), ""), stringOr(v.GetAttr("name"), ""))
}

var junosUserKind = cliKind{
	p:        junosPlatform,
	name:     "user",
	keys:     []string{"name"},
	settings: []string{"class", "ssh_keys", "password_hmac"},
	deletes:  true,
	config:   func(v cty.Value) cliWant { return junosUserFrom(v) },
	remove:   func(v cty.Value, running string) []string { return junosUserFrom(v).RemoveCommands(running) },
	guard: func(v cty.Value, _, _ string) error {
		return junosUserFrom(v).Guard(stringOr(v.GetAttr("ssh").GetAttr("user"), ""))
	},
}

func junosUserSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: junosExperimental + "A local account on a Juniper Junos device: its login class, password and SSH keys. Conn3x won't demote or delete the account it logs in as.",
		Attributes: map[string]*configschema.Attribute{
			"id":            {Type: cty.String, Computed: true},
			"revision":      revisionAttr(),
			"name":          {Type: cty.String, Required: true, Description: "The account name. Not root."},
			"class":         {Type: cty.String, Required: true, Description: "Its login class, such as super-user, operator or read-only. Junos requires one."},
			"password_wo":   {Type: cty.String, Optional: true, Sensitive: true, WriteOnly: true, Description: "Write-only: the password, never kept in state. Conn3x hashes it here and sends the device the salted SHA-512 hash, as encrypted-password, so the password itself never reaches the CLI; a new value plans a change through password_hmac. Unset leaves the account's password alone."},
			"password_hmac": {Type: cty.String, Computed: true, Description: "An HMAC of the hash the device should hold for password_wo, keyed outside state. A new password plans a change, and a refresh finds an account with another one out of sync."},
			"ssh_keys":      {Type: cty.List(cty.String), Optional: true, Description: "The account's public keys, one line each, such as \"ssh-ed25519 AAAA... alice@laptop\". Keys not listed are deleted; [] deletes them all, and unset leaves them alone."},
			"on_remove":     {Type: cty.String, Optional: true, Computed: true, Description: "\"delete\" (default) deletes the account when the step goes, as with every step that grants access; \"forget\" leaves it."},
			"in_sync":       {Type: cty.Bool, Computed: true, Description: "Whether the account matched at the last refresh."},
			"circuit":       eosCircuitAttr(),
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func validateJunosUser(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() || !cfg.IsWhollyKnown() {
		return diags
	}
	diags = diags.Append(validateOnRemove(cfg))
	if err := junosUserFrom(cfg).Validate(); err != nil {
		diags = diags.Append(attrError("name", err.Error()))
	}
	return diags
}

func planJunosUser(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	return planPasswordAs(deleteByDefault(req), "junos_user", junosUserKind.settings, planSyncedFold, eosPasswordHMAC)
}

// applyJunosUser hashes the step's password, which only the config holds,
// as applyEOSUser does: the same salted SHA-512 crypt, which Junos takes as
// encrypted-password.
func applyJunosUser(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	if req.PlannedState.IsNull() && !req.PriorState.IsNull() && req.PriorState.GetAttr("on_remove").AsString() == onRemoveDelete {
		if name := req.PriorState.GetAttr("name").AsString(); name == stringOr(req.PriorState.GetAttr("ssh").GetAttr("user"), "") {
			var resp providers.ApplyResourceChangeResponse
			resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("junos_user: Conn3x logs in as %s, so it won't delete that account; set on_remove = \"forget\" to drop the step", name))
			return resp
		}
	}
	k := junosUserKind
	var mac string
	if !req.PlannedState.IsNull() && junosUserFrom(req.PlannedState).WantSecret {
		var resp providers.ApplyResourceChangeResponse
		password := ""
		if !req.Config.IsNull() {
			password = stringOr(req.Config.GetAttr("password_wo"), "")
		}
		if password == "" {
			resp.Diagnostics = resp.Diagnostics.Append(errors.New("junos_user: password_wo didn't reach the apply; it's write-only, so set it in the step's config"))
			return resp
		}
		key, err := hmacKey(true)
		if err != nil {
			resp.Diagnostics = resp.Diagnostics.Append(attrError("password_wo", err.Error()))
			return resp
		}
		id := junosUserID(req.PlannedState)
		hash := eosSecret(key, id, password)
		mac = eosSecretHMAC(key, id, hash)
		k.config = func(v cty.Value) cliWant {
			u := junosUserFrom(v)
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
