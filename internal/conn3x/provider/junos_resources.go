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
	"github.com/opentofu/opentofu/internal/conn3x/modules/junos"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
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

func junosConfirmAfter(conn cty.Value) time.Duration {
	if d, err := time.ParseDuration(stringOr(optional(conn, "confirm_after"), "")); err == nil {
		return d
	}
	return junos.DefaultConfirmAfter
}

// junosReconnect dials a new connection, outside the pool, for confirming a
// commit: that the login still works is the point.
func junosReconnect(conn cty.Value) func(context.Context) (junos.Device, error) {
	return func(ctx context.Context) (junos.Device, error) {
		cfg, err := sshConfig(conn)
		if err != nil {
			return nil, err
		}
		return ssh.Dial(ctx, cfg)
	}
}

// junosKind is one Junos step module. Each step commits on its own, with
// commit confirmed and a confirm over a new login.
type junosKind struct {
	name     string
	keys     []string // changing one of these is a new resource
	settings []string // changing one of these is an update
	deletes  bool     // on_remove defaults to "delete"
	config   func(cty.Value) junosWant
	remove   func(cty.Value, string) []string // nil: removing only forgets
}

// junosWant is what a step wants of a device's configuration.
type junosWant interface {
	InSync(config string) bool
	Commands(config string) []string
}

func (k junosKind) plan(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	if k.deletes {
		req = deleteByDefault(req)
	}
	return planSynced(req, "junos_"+k.name, k.keys, k.settings)
}

func (k junosKind) read(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	resp := providers.ReadResourceResponse{NewState: req.PriorState}
	if req.PriorState.IsNull() {
		return resp
	}
	h, err := pooled(ctx, req.PriorState.GetAttr("ssh"), 0)
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(attrError("ssh", err.Error()))
		return resp
	}
	running, err := junos.RunningConfig(ctx, h.client)
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("junos_%s: %w", k.name, err))
		return resp
	}
	resp.NewState = withSync(req.PriorState, k.config(req.PriorState).InSync(running))
	return resp
}

func (k junosKind) apply(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	var resp providers.ApplyResourceChangeResponse
	target := req.PlannedState
	removing := target.IsNull()
	if removing {
		resp.NewState = target
		if k.remove == nil || req.PriorState.IsNull() || req.PriorState.GetAttr("on_remove").AsString() != onRemoveDelete {
			return resp
		}
		target = req.PriorState
	}
	conn := target.GetAttr("ssh")
	h, err := pooled(ctx, conn, 0)
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(attrError("ssh", err.Error()))
		return resp
	}
	// One change at a time: configure exclusive refuses a second one anyway.
	defer lockHost(h, "junos")()
	base, err := junos.RunningConfig(ctx, h.client)
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("junos_%s: %w", k.name, err))
		return resp
	}
	var cmds []string
	if removing {
		cmds = k.remove(target, base)
	} else {
		cmds = k.config(target).Commands(base)
	}
	diff, err := junos.Apply(ctx, h.client, junosReconnect(conn), base, cmds, junosConfirmAfter(conn))
	if diff != "" {
		log.Printf("[INFO] conn3x: junos_%s on %s: lines sent:\n%s", k.name, h.host, diff)
	}
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("junos_%s: %w", k.name, err))
		return resp
	}
	if !removing {
		resp.NewState = withSync(req.PlannedState, true)
	}
	return resp
}

func (k junosKind) entry(schema func() providers.Schema, validate func(cty.Value) tfdiags.Diagnostics) resourceType {
	return resourceType{schema, validate, k.plan, k.read, k.apply, upgradeWith(schema)}
}

func junosConfigFrom(v cty.Value) junos.Config {
	return junos.Config{Prefix: stringOr(v.GetAttr("prefix"), ""), Lines: stringList(v.GetAttr("lines")), Match: stringOr(v.GetAttr("match"), junos.MatchLines)}
}

var junosConfigKind = junosKind{
	name:     "config",
	keys:     []string{"prefix"},
	settings: []string{"lines", "match"},
	config:   func(v cty.Value) junosWant { return junosConfigFrom(v) },
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

var junosHostnameKind = junosKind{
	name:     "hostname",
	settings: []string{"name"},
	config:   func(v cty.Value) junosWant { return junos.Hostname(v.GetAttr("name").AsString()) },
}

func junosHostnameSchema() providers.Schema {
	s := singletonSchema(junosExperimental+"A Juniper Junos device's host name. Removing this step leaves the name as it is.",
		"Host name, such as sw1. Junos takes letters, digits, hyphens and dots.")
	s.Block.Attributes["in_sync"].Description = "Whether the device had this name at the last refresh."
	return s
}

func validateJunosHostname(cfg cty.Value) tfdiags.Diagnostics {
	return validateName(cfg, junos.ValidateHostname)
}

func junosVLANFrom(v cty.Value) junos.VLAN {
	id, _ := v.GetAttr("vlan_id").AsBigFloat().Int64()
	return junos.VLAN{Name: stringOr(v.GetAttr("name"), ""), ID: int(id)}
}

var junosVLANKind = junosKind{
	name:     "vlan",
	keys:     []string{"name"},
	settings: []string{"vlan_id"},
	deletes:  true,
	config:   func(v cty.Value) junosWant { return junosVLANFrom(v) },
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
