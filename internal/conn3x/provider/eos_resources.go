// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/conn3x/modules/eos"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
	"github.com/opentofu/opentofu/internal/providers"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

const eosTypePrefix = "conn3x_eos_"

// eosExperimental starts every EOS description, so the reference says so.
const eosExperimental = "Experimental. "

// validateEOSSSH rejects the ssh settings a switch's CLI has no use for:
// there is no shell for the agent and no sudo for become.
func validateEOSSSH(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() || !cfg.Type().HasAttribute("ssh") {
		return diags
	}
	conn := cfg.GetAttr("ssh")
	if conn.IsNull() || !conn.IsKnown() {
		return diags
	}
	for attr, why := range map[string]string{
		"agent":                "The conn3x agent needs a shell, and an EOS login has the switch's CLI instead. Remove agent from this ssh block.",
		"become":               "EOS has no sudo. Log in as a user with privilege 15 (\"username x privilege 15 role network-admin\") on a switch with \"aaa authorization exec default local\", so the login starts privileged, and remove become from this ssh block.",
		"become_password_file": "EOS has no sudo, so there is no password to give it. Remove become_password_file from this ssh block.",
	} {
		v := conn.GetAttr(attr)
		if v.IsNull() || !v.IsKnown() || (v.Type() == cty.Bool && v.False()) {
			continue
		}
		diags = diags.Append(tfdiags.AttributeValue(tfdiags.Error, "Invalid ssh setting for an EOS switch", why,
			cty.GetAttrPath("ssh").GetAttr(attr)))
	}
	if v := optional(conn, "confirm_after"); known(v) {
		if d, err := time.ParseDuration(v.AsString()); err == nil {
			if err := eos.CheckConfirmAfter(d); err != nil {
				diags = diags.Append(tfdiags.AttributeValue(tfdiags.Error, "Invalid ssh confirm_after", err.Error(),
					cty.GetAttrPath("ssh").GetAttr("confirm_after")))
			}
		}
	}
	return diags
}

// validateNotEOS refuses confirm_after on a step that isn't an EOS step:
// nothing else commits with a revert timer, so it would do nothing.
func validateNotEOS(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() || !cfg.Type().HasAttribute("ssh") {
		return diags
	}
	if conn := cfg.GetAttr("ssh"); !conn.IsNull() && conn.IsKnown() && !optional(conn, "confirm_after").IsNull() {
		diags = diags.Append(tfdiags.AttributeValue(tfdiags.Error, "Invalid ssh setting",
			"confirm_after only applies to eos_* steps, which commit with a revert timer. Remove it from this ssh block, or put the switches in their own circuit.",
			cty.GetAttrPath("ssh").GetAttr("confirm_after")))
	}
	return diags
}

// eosDevice returns the pooled connection to a switch. It never attaches the
// agent, whatever CONN3X_AGENT says.
func eosDevice(ctx context.Context, conn cty.Value) (*hostConn, error) {
	return pooled(ctx, conn, 0)
}

// confirmAfter is the ssh block's confirm_after, already checked by
// validateEOSSSH, or the default.
func confirmAfter(conn cty.Value) time.Duration {
	if d, err := time.ParseDuration(stringOr(optional(conn, "confirm_after"), "")); err == nil {
		return d
	}
	return eos.DefaultConfirmAfter
}

// eosReconnect dials a new connection, outside the pool, for confirming a
// commit: that the login still works is the point.
func eosReconnect(conn cty.Value) func(context.Context) (eos.Device, error) {
	return func(ctx context.Context) (eos.Device, error) {
		cfg, err := sshConfig(conn)
		if err != nil {
			return nil, err
		}
		return ssh.Dial(ctx, cfg)
	}
}

// eosKind is one EOS step module: how to read its wanted lines from a
// resource's state, and what removing it takes, when it can be removed.
type eosKind struct {
	name     string
	keys     []string // changing one of these is a new resource
	settings []string // changing one of these is an update
	deletes  bool     // on_remove defaults to "delete"
	config   func(cty.Value) eos.Config
	remove   func(cty.Value, string) []string // nil: removing only forgets
}

func (k eosKind) plan(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	if k.deletes {
		req = deleteByDefault(req)
	}
	return planSynced(req, "eos_"+k.name, k.keys, k.settings)
}

func (k eosKind) read(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	resp := providers.ReadResourceResponse{NewState: req.PriorState}
	if req.PriorState.IsNull() {
		return resp
	}
	h, err := eosDevice(ctx, req.PriorState.GetAttr("ssh"))
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(attrError("ssh", err.Error()))
		return resp
	}
	running, err := eos.RunningConfig(ctx, h.client)
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("eos_%s: %w", k.name, err))
		return resp
	}
	resp.NewState = withSync(req.PriorState, k.config(req.PriorState).InSync(running))
	return resp
}

func (k eosKind) apply(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	var resp providers.ApplyResourceChangeResponse
	fail := func(err error) providers.ApplyResourceChangeResponse {
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("eos_%s: %w", k.name, err))
		return resp
	}
	target := req.PlannedState
	if target.IsNull() {
		resp.NewState = target
		if k.remove == nil || req.PriorState.IsNull() || req.PriorState.GetAttr("on_remove").AsString() != onRemoveDelete {
			return resp
		}
		target = req.PriorState
	}
	conn := target.GetAttr("ssh")
	h, err := eosDevice(ctx, conn)
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(attrError("ssh", err.Error()))
		return resp
	}
	// One config session per switch at a time: EOS allows several, but two
	// commit timers waiting on each other's confirm would be hard to reason about.
	defer lockHost(h, "eos")()
	running, err := eos.RunningConfig(ctx, h.client)
	if err != nil {
		return fail(err)
	}
	var cmds []string
	if req.PlannedState.IsNull() {
		cmds = k.remove(target, running)
	} else {
		cmds = k.config(target).Commands(running)
	}
	diff, err := eos.Apply(ctx, h.client, eosReconnect(conn), cmds, confirmAfter(conn))
	if diff != "" {
		log.Printf("[INFO] conn3x: eos_%s on %s: session diff:\n%s", k.name, h.host, diff)
	}
	if err != nil {
		return fail(err)
	}
	if !req.PlannedState.IsNull() {
		resp.NewState = withSync(req.PlannedState, true)
	}
	return resp
}

func (k eosKind) entry(schema func() providers.Schema, validate func(cty.Value) tfdiags.Diagnostics) resourceType {
	return resourceType{schema, validate, k.plan, k.read, k.apply, upgradeWith(schema)}
}

func stringList(v cty.Value) []string {
	if v.IsNull() || !v.IsKnown() {
		return nil
	}
	var out []string
	for _, e := range v.AsValueSlice() {
		out = append(out, e.AsString())
	}
	return out
}

func eosConfigFrom(v cty.Value) eos.Config {
	return eos.Config{Parents: stringList(v.GetAttr("parents")), Lines: stringList(v.GetAttr("lines")), Match: stringOr(v.GetAttr("match"), eos.MatchLines)}
}

var eosConfigKind = eosKind{
	name:     "config",
	keys:     []string{"parents"},
	settings: []string{"lines", "match"},
	config:   eosConfigFrom,
	remove:   func(v cty.Value, running string) []string { return eosConfigFrom(v).RemoveCommands(running) },
}

func eosConfigSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: eosExperimental + "Lines of an Arista EOS switch's configuration, under a parent block such as an interface. Only the lines named here are owned; with match = \"block\" the block must hold exactly these.",
		Attributes: map[string]*configschema.Attribute{
			"id":        {Type: cty.String, Computed: true},
			"revision":  revisionAttr(),
			"parents":   {Type: cty.List(cty.String), Optional: true, Description: "The block the lines go under, outermost first, as show running-config prints it, such as [\"interface Ethernet1\"] or [\"router bgp 65000\", \"address-family ipv4\"]. Leave unset for top-level lines."},
			"lines":     {Type: cty.List(cty.String), Optional: true, Description: "The lines, as show running-config prints them, without the indent. The switch must print a line back exactly as written, or it never shows as in sync."},
			"match":     {Type: cty.String, Optional: true, Description: "\"lines\" (default): these lines must be there, and others under the parent are left alone. \"block\": the block must be exactly these lines, so others under it are removed. Needs parents."},
			"on_remove": {Type: cty.String, Optional: true, Computed: true, Description: "What happens on the switch when this resource is removed: \"forget\" (default) leaves the lines, \"delete\" removes them with \"no\" and leaves the parent."},
			"in_sync":   {Type: cty.Bool, Computed: true, Description: "Whether the switch had these lines at the last refresh."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func validateEOSConfig(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() || !cfg.IsWhollyKnown() {
		return diags
	}
	diags = diags.Append(validateOnRemove(cfg))
	if err := eosConfigFrom(cfg).Validate(); err != nil {
		diags = diags.Append(attrError("lines", err.Error()))
	}
	return diags
}

var eosHostnameKind = eosKind{
	name:     "hostname",
	settings: []string{"name"},
	config:   func(v cty.Value) eos.Config { return eos.Hostname(v.GetAttr("name").AsString()) },
}

func eosHostnameSchema() providers.Schema {
	s := singletonSchema(eosExperimental+"An Arista EOS switch's hostname. Removing this step leaves the name as it is.",
		"Hostname, such as leaf1. EOS takes letters, digits, hyphens and dots.")
	s.Block.Attributes["in_sync"].Description = "Whether the switch had this name at the last refresh."
	return s
}

func validateEOSHostname(cfg cty.Value) tfdiags.Diagnostics {
	return validateName(cfg, eos.ValidateHostname)
}

func eosVLANFrom(v cty.Value) eos.VLAN {
	id, _ := v.GetAttr("vlan_id").AsBigFloat().Int64()
	return eos.VLAN{ID: int(id), Name: stringOr(v.GetAttr("name"), "")}
}

var eosVLANKind = eosKind{
	name:     "vlan",
	keys:     []string{"vlan_id"},
	settings: []string{"name"},
	deletes:  true,
	config:   func(v cty.Value) eos.Config { return eosVLANFrom(v).Config() },
	remove:   func(v cty.Value, running string) []string { return eosVLANFrom(v).RemoveCommands(running) },
}

func eosVLANSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: eosExperimental + "A VLAN on an Arista EOS switch, and its name.",
		Attributes: map[string]*configschema.Attribute{
			"id":        {Type: cty.String, Computed: true},
			"revision":  revisionAttr(),
			"vlan_id":   {Type: cty.Number, Required: true, Description: "VLAN ID, 1 to 4094."},
			"name":      {Type: cty.String, Optional: true, Description: "VLAN name: one word, up to 32 characters. Leave unset for the switch's default, such as VLAN0010; a name set by hand is then removed."},
			"on_remove": {Type: cty.String, Optional: true, Computed: true, Description: "What happens on the switch when this resource is removed: \"delete\" (default) removes the VLAN, \"forget\" leaves it."},
			"in_sync":   {Type: cty.Bool, Computed: true, Description: "Whether the VLAN was there, with this name, at the last refresh."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func validateEOSVLAN(cfg cty.Value) tfdiags.Diagnostics {
	return validateWith("vlan_id", func(v cty.Value) error { return eosVLANFrom(v).Validate() })(cfg)
}

// eosDeviceSchema is the conn3x_eos_device data source: what a circuit
// checks before it changes a switch.
func eosDeviceSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: eosExperimental + "Facts about an Arista EOS switch, from show version and show hostname.",
		Attributes: map[string]*configschema.Attribute{
			"hostname":   {Type: cty.String, Computed: true, Description: "The switch's hostname."},
			"model":      {Type: cty.String, Computed: true, Description: "Model, such as DCS-7050SX3-48YC8, or cEOSLab."},
			"version":    {Type: cty.String, Computed: true, Description: "EOS version as show version prints it, such as 4.37.0F or 4.37.0F-51574443.4370F.1 (engineering build)."},
			"serial":     {Type: cty.String, Computed: true, Description: "Serial number. cEOS-lab reports a made-up one."},
			"system_mac": {Type: cty.String, Computed: true, Description: "System MAC address."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func readEOSDevice(ctx context.Context, req providers.ReadDataSourceRequest) providers.ReadDataSourceResponse {
	var resp providers.ReadDataSourceResponse
	h, err := eosDevice(ctx, req.Config.GetAttr("ssh"))
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(attrError("ssh", err.Error()))
		return resp
	}
	f, err := eos.ReadFacts(ctx, h.client)
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("conn3x_eos_device: %w", err))
		return resp
	}
	vals := req.Config.AsValueMap()
	vals["hostname"] = cty.StringVal(f.Hostname)
	vals["model"] = cty.StringVal(f.Model)
	vals["version"] = cty.StringVal(f.Version)
	vals["serial"] = cty.StringVal(f.Serial)
	vals["system_mac"] = cty.StringVal(f.SystemMAC)
	resp.State = cty.ObjectVal(vals)
	return resp
}
