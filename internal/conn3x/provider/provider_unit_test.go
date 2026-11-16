// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"strings"
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/providers"
)

// Each data source checks the ssh settings its kind of host takes, and its
// own arguments; one the provider doesn't have is refused.
func TestValidateDataResourceConfig(t *testing.T) {
	p, _ := New()
	validate := func(typeName string, attrs, ssh map[string]cty.Value) error {
		return p.ValidateDataResourceConfig(ctx, providers.ValidateDataResourceConfigRequest{TypeName: typeName, Config: brData(typeName, attrs, ssh)}).Diagnostics.Err()
	}
	confirm := map[string]cty.Value{"confirm_after": cty.StringVal("60s")}
	agent := map[string]cty.Value{"agent": cty.True}
	for _, c := range []struct {
		typeName string
		attrs    map[string]cty.Value
		ssh      map[string]cty.Value
		want     string // "" for valid
	}{
		{"conn3x_host", nil, nil, ""},
		{"conn3x_host", nil, confirm, "confirm_after only applies to eos_* steps"},
		{"conn3x_host", map[string]cty.Value{"allow_windows": cty.True}, nil, ""},
		{"conn3x_host", map[string]cty.Value{"allow_windows": cty.True}, agent, "doesn't run on Windows"},
		{"conn3x_host", map[string]cty.Value{"allow_windows": cty.False}, agent, ""},
		{"conn3x_vyos_device", nil, nil, ""},
		{"conn3x_vyos_device", nil, agent, "VyOS router"},
		{"conn3x_junos_device", nil, map[string]cty.Value{"user": cty.StringVal("ops")}, ""},
		{"conn3x_junos_device", nil, map[string]cty.Value{"user": cty.StringVal("root")}, "Invalid ssh user for a Junos device"},
		{"conn3x_eos_device", nil, nil, ""},
		{"conn3x_eos_device", nil, agent, "EOS switch"},
		{"conn3x_file", map[string]cty.Value{"path": cty.StringVal("/etc/hostname")}, nil, ""},
		{"conn3x_file", map[string]cty.Value{"path": cty.StringVal("etc/hostname")}, nil, `path "etc/hostname" must be absolute`},
		{"conn3x_file", map[string]cty.Value{"path": cty.StringVal("/etc/hostname"), "max_size": cty.NumberIntVal(0)}, nil, "max_size must be at least 1"},
		{"conn3x_file", map[string]cty.Value{"path": cty.StringVal("/etc/hostname")}, confirm, "confirm_after only applies"},
		{"conn3x_command", map[string]cty.Value{"command": cty.StringVal("uptime")}, nil, ""},
		{"conn3x_command", map[string]cty.Value{"command": cty.StringVal("")}, nil, "command must not be empty"},
		{"conn3x_packages", nil, nil, ""},
		{"conn3x_services", nil, confirm, "confirm_after only applies"},
	} {
		err := validate(c.typeName, c.attrs, c.ssh)
		if c.want == "" && err != nil {
			t.Errorf("%s %v %v: %v", c.typeName, c.attrs, c.ssh, err)
		}
		if c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)) {
			t.Errorf("%s %v %v: %v, want %q", c.typeName, c.attrs, c.ssh, err, c.want)
		}
	}
	if d := p.ValidateDataResourceConfig(ctx, providers.ValidateDataResourceConfigRequest{TypeName: "conn3x_printer", Config: cty.EmptyObjectVal}); !d.Diagnostics.HasErrors() {
		t.Error("validated a data source the provider doesn't have")
	}
}

// A Cisco IOS step's login has the CLI, so the shell's ssh settings are
// refused, and confirm_after must suit the device's rollback timer.
func TestValidateIOSSSH(t *testing.T) {
	p, _ := New()
	lines := map[string]cty.Value{"lines": cty.ListVal([]cty.Value{cty.StringVal("ntp server 192.0.2.1")})}
	validate := func(attrs, ssh map[string]cty.Value) error {
		cfg := eosStep("conn3x_ios_config", attrs, ssh)
		return p.ValidateResourceConfig(ctx, providers.ValidateResourceConfigRequest{TypeName: "conn3x_ios_config", Config: cfg}).Diagnostics.Err()
	}
	if err := validate(lines, map[string]cty.Value{"agent": cty.False, "confirm_after": cty.StringVal("60s")}); err != nil {
		t.Fatal(err)
	}
	for want, ssh := range map[string]map[string]cty.Value{
		"an IOS login has the CLI":  {"agent": cty.True},
		"IOS has no sudo. Log in":   {"become": cty.True},
		"no password to give it":    {"become_password_file": cty.StringVal("pw")},
		"Invalid ssh confirm_after": {"confirm_after": cty.StringVal("4m")},
	} {
		if err := validate(lines, ssh); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%v: %v, want %q", ssh, err, want)
		}
	}
	// The lines themselves are the module's to check, once they're known.
	if err := validate(map[string]cty.Value{"lines": cty.ListValEmpty(cty.String)}, nil); err == nil {
		t.Error("accepted no lines")
	}
	unknown := map[string]cty.Value{"lines": cty.UnknownVal(cty.List(cty.String))}
	if err := validate(unknown, nil); err != nil {
		t.Errorf("unknown lines: %v", err)
	}
	if d := validateIOSSSH(cty.NullVal(cty.EmptyObject)); d.HasErrors() {
		t.Error(d.Err())
	}
	unknownSSH := eosStep("conn3x_ios_config", lines, nil).AsValueMap()
	unknownSSH["ssh"] = cty.UnknownVal(unknownSSH["ssh"].Type())
	if d := validateIOSSSH(cty.ObjectVal(unknownSSH)); d.HasErrors() {
		t.Errorf("an unknown ssh block: %v", d.Err())
	}
}

func TestValidateEphemeralConfig(t *testing.T) {
	p, _ := New()
	schemas := p.GetProviderSchema(ctx).EphemeralResources
	validate := func(typeName string, attrs map[string]cty.Value) error {
		vals := map[string]cty.Value{}
		for name, ty := range schemas[typeName].Block.ImpliedType().AttributeTypes() {
			vals[name] = cty.NullVal(ty)
		}
		if typeName == tunnelType {
			vals = objFor(schemas[typeName], nil).AsValueMap()
		}
		for k, v := range attrs {
			vals[k] = v
		}
		return p.ValidateEphemeralConfig(ctx, providers.ValidateEphemeralConfigRequest{TypeName: typeName, Config: cty.ObjectVal(vals)}).Diagnostics.Err()
	}
	for _, c := range []struct {
		typeName string
		attrs    map[string]cty.Value
		want     string
	}{
		{tunnelType, map[string]cty.Value{"remote": cty.StringVal("127.0.0.1:5432")}, ""},
		{tunnelType, map[string]cty.Value{"remote": cty.StringVal("127.0.0.1:99999")}, "must be host:port"},
		{tunnelType, map[string]cty.Value{"remote": cty.StringVal(":5432")}, "must be host:port"},
		{hostdataType, map[string]cty.Value{"dir": cty.StringVal("data"), "vars": cty.ObjectVal(map[string]cty.Value{"host": cty.StringVal("web1"), "group": cty.TupleVal([]cty.Value{cty.StringVal("web")})})}, ""},
		{hostdataType, map[string]cty.Value{"dir": cty.StringVal("data"), "vars": cty.StringVal("web1")}, "vars must be a map or object"},
		{hostdataType, map[string]cty.Value{"dir": cty.StringVal("data"), "vars": cty.ObjectVal(map[string]cty.Value{"port": cty.NumberIntVal(22)})}, "vars.port must be a string"},
		{secretsType, map[string]cty.Value{"file": cty.StringVal("secrets.enc.yaml")}, ""},
	} {
		err := validate(c.typeName, c.attrs)
		if c.want == "" && err != nil {
			t.Errorf("%s %v: %v", c.typeName, c.attrs, err)
		}
		if c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)) {
			t.Errorf("%s %v: %v, want %q", c.typeName, c.attrs, err, c.want)
		}
	}
	if d := p.ValidateEphemeralConfig(ctx, providers.ValidateEphemeralConfigRequest{TypeName: "conn3x_vault", Config: cty.EmptyObjectVal}); !d.Diagnostics.HasErrors() {
		t.Error("validated an ephemeral resource the provider doesn't have")
	}
}

// Every entry point refuses a type the provider doesn't serve, rather than
// panic on it.
func TestProviderRefusesUnknownTypes(t *testing.T) {
	p, _ := New()
	const nope = "conn3x_nope"
	for name, d := range map[string]interface{ HasErrors() bool }{
		"validate": p.ValidateResourceConfig(ctx, providers.ValidateResourceConfigRequest{TypeName: nope}).Diagnostics,
		"upgrade":  p.UpgradeResourceState(ctx, providers.UpgradeResourceStateRequest{TypeName: nope}).Diagnostics,
		"read":     p.ReadResource(ctx, providers.ReadResourceRequest{TypeName: nope}).Diagnostics,
		"plan":     p.PlanResourceChange(ctx, providers.PlanResourceChangeRequest{TypeName: nope}).Diagnostics,
		"apply":    p.ApplyResourceChange(ctx, providers.ApplyResourceChangeRequest{TypeName: nope}).Diagnostics,
		"data":     p.ReadDataSource(ctx, providers.ReadDataSourceRequest{TypeName: nope}).Diagnostics,
		"identity": p.UpgradeResourceIdentity(ctx, providers.UpgradeResourceIdentityRequest{TypeName: nope}).Diagnostics,
		"move":     p.MoveResourceState(ctx, providers.MoveResourceStateRequest{TargetTypeName: nope}).Diagnostics,
		"open":     p.OpenEphemeralResource(ctx, providers.OpenEphemeralResourceRequest{TypeName: nope}).Diagnostics,
	} {
		if !d.HasErrors() {
			t.Errorf("%s accepted %s", name, nope)
		}
	}
	// Closing anything but a tunnel has nothing to close.
	if d := p.CloseEphemeralResource(ctx, providers.CloseEphemeralResourceRequest{TypeName: secretsType}).Diagnostics; d.HasErrors() {
		t.Error(d.Err())
	}
}

// A step's ssh block counts only when it's wholly known.
func TestPriorSSH(t *testing.T) {
	step := eosStep("conn3x_command", map[string]cty.Value{"command": cty.StringVal("true")}, nil)
	if conn := priorSSH(step); conn.IsNull() || conn.GetAttr("host").AsString() != "leaf1" {
		t.Errorf("known: %#v", conn)
	}
	vals := step.AsValueMap()
	ssh := vals["ssh"].AsValueMap()
	ssh["host"] = cty.UnknownVal(cty.String)
	vals["ssh"] = cty.ObjectVal(ssh)
	for name, v := range map[string]cty.Value{
		"unknown host": cty.ObjectVal(vals),
		"null":         cty.NullVal(step.Type()),
		"unknown":      cty.UnknownVal(step.Type()),
		"no ssh":       cty.ObjectVal(map[string]cty.Value{"id": cty.StringVal("x")}),
		"not object":   cty.StringVal("x"),
	} {
		if !priorSSH(v).IsNull() {
			t.Errorf("%s: an ssh block", name)
		}
	}
}
