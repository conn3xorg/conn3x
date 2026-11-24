// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/providers"
)

// stepConfig is a typeName config with attrs set, every other required
// attribute a placeholder and the rest null, and an ssh block whose host is
// host, as a circuit's step has one.
func stepConfig(typeName string, attrs map[string]cty.Value, host cty.Value) cty.Value {
	block := resourceSchemas()[typeName].Block
	ty := block.ImpliedType()
	vals := map[string]cty.Value{}
	for name, at := range ty.AttributeTypes() {
		vals[name] = cty.NullVal(at)
		if a := block.Attributes[name]; a != nil && a.Required {
			vals[name] = placeholder(at)
		}
	}
	maps.Copy(vals, attrs)
	if ty.HasAttribute("ssh") {
		sv := map[string]cty.Value{}
		for name, at := range ty.AttributeType("ssh").AttributeTypes() {
			sv[name] = cty.NullVal(at)
		}
		sv["host"] = host
		sv["user"] = cty.StringVal("admin")
		vals["ssh"] = cty.ObjectVal(sv)
	}
	return cty.ObjectVal(vals)
}

// placeholder is a plausible value of type at for a required attribute.
func placeholder(at cty.Type) cty.Value {
	switch {
	case at == cty.String:
		return cty.StringVal("x")
	case at == cty.Number:
		return cty.NumberIntVal(1)
	case at == cty.Bool:
		return cty.False
	case at.IsListType():
		return cty.ListVal([]cty.Value{placeholder(at.ElementType())})
	case at.IsSetType():
		return cty.SetVal([]cty.Value{placeholder(at.ElementType())})
	case at.IsMapType():
		return cty.MapVal(map[string]cty.Value{"x": placeholder(at.ElementType())})
	}
	return cty.UnknownVal(at)
}

// validated runs typeName's checks on cfg; a panic, from a placeholder the
// checks can't take, counts as passing.
func validated(t *testing.T, typeName string, cfg cty.Value) (failed bool) {
	defer func() {
		if r := recover(); r != nil {
			failed = false
		}
	}()
	return resourceTypes[typeName].validate(cfg).HasErrors()
}

// A circuit's step gets its host from hosts and each, unknown at validate,
// and that used to skip all of the step's own checks (#1354): a literal
// mistake passed validate and only failed at plan.
func TestValidateChecksLiteralsWhenHostUnknown(t *testing.T) {
	unknownHost, knownHost := cty.UnknownVal(cty.String), cty.StringVal("web1")
	var checked, unchecked []string
	for _, typeName := range slices.Sorted(maps.Keys(resourceTypes)) {
		ty := resourceTypes[typeName].schema().Block.ImpliedType()
		if !ty.HasAttribute("ssh") {
			continue
		}
		// Find a config that fails with the host known: the placeholders
		// alone, or one string setting set to junk.
		bad := map[string]cty.Value{}
		if !validated(t, typeName, stepConfig(typeName, bad, knownHost)) {
			bad = nil
			for _, name := range slices.Sorted(maps.Keys(ty.AttributeTypes())) {
				junk := cty.StringVal("\x01 not valid")
				switch at := ty.AttributeType(name); {
				case at == cty.String:
				case at.Equals(cty.List(cty.String)):
					junk = cty.ListVal([]cty.Value{junk})
				case at.Equals(cty.Set(cty.String)):
					junk = cty.SetVal([]cty.Value{junk})
				default:
					continue
				}
				try := map[string]cty.Value{name: junk}
				if validated(t, typeName, stepConfig(typeName, try, knownHost)) {
					bad = try
					break
				}
			}
		}
		if bad == nil {
			unchecked = append(unchecked, typeName)
			continue
		}
		checked = append(checked, typeName)
		if !validated(t, typeName, stepConfig(typeName, bad, unknownHost)) {
			t.Errorf("%s: %v fails with the host known but passes with it unknown", typeName, bad)
		}
	}
	t.Logf("checked %d types; no failing config found for %d: %s", len(checked), len(unchecked), strings.Join(unchecked, " "))
}

// An unknown setting is never treated as unset: a check that needs it waits
// for plan, so a required or either-or setting can't fail on it.
func TestValidateWaitsForUnknownSettings(t *testing.T) {
	host := cty.UnknownVal(cty.String)
	for _, typeName := range slices.Sorted(maps.Keys(resourceTypes)) {
		rt := resourceTypes[typeName]
		ty := rt.schema().Block.ImpliedType()
		// These refuse a value and its _wo twin both written, whatever they
		// turn out to be, and setting everything writes both.
		if !ty.HasAttribute("ssh") || slices.Contains([]string{"conn3x_uri", "conn3x_windows_file", "conn3x_windows_registry_value"}, typeName) {
			continue
		}
		all := map[string]cty.Value{}
		for name, at := range ty.AttributeTypes() {
			if name == "ssh" {
				continue
			}
			all[name] = cty.UnknownVal(at)
		}
		if d := rt.validate(stepConfig(typeName, all, host)); d.HasErrors() {
			t.Errorf("%s: every setting unknown: %v", typeName, d.Err())
		}
	}
	// Either-or and needs-another checks, with the other side unknown.
	for _, c := range []struct {
		typeName string
		attrs    map[string]cty.Value
	}{
		{"conn3x_debconf", map[string]cty.Value{"name": cty.StringVal("tzdata"), "question": cty.StringVal("tzdata/Areas"), "vtype": cty.StringVal("select"), "value": cty.UnknownVal(cty.String)}},
		{"conn3x_user", map[string]cty.Value{"name": cty.StringVal("deploy"), "append": cty.True, "groups": cty.UnknownVal(cty.Set(cty.String))}},
		{"conn3x_ufw_rule", map[string]cty.Value{"action": cty.StringVal("allow"), "port": cty.UnknownVal(cty.String)}},
	} {
		if d := resourceTypes[c.typeName].validate(stepConfig(c.typeName, c.attrs, host)); d.HasErrors() {
			t.Errorf("%s %v: %v", c.typeName, c.attrs, d.Err())
		}
	}
}

// The issue's own step, through the provider as validate calls it.
func TestValidateUFWPortWithHostUnknown(t *testing.T) {
	p := &Provider{}
	for _, c := range []struct {
		port    cty.Value
		wantErr bool
	}{
		{cty.StringVal("ssh/tcp"), true},
		{cty.StringVal("22/tcp"), false},
		{cty.UnknownVal(cty.String), false},
	} {
		cfg := stepConfig("conn3x_ufw_rule", map[string]cty.Value{"action": cty.StringVal("limit"), "port": c.port}, cty.UnknownVal(cty.String))
		d := p.ValidateResourceConfig(t.Context(), providers.ValidateResourceConfigRequest{TypeName: "conn3x_ufw_rule", Config: cfg}).Diagnostics
		if d.HasErrors() != c.wantErr || (c.wantErr && !strings.Contains(d.Err().Error(), "must look like")) {
			t.Errorf("port %#v: want error %v, got %v", c.port, c.wantErr, d.Err())
		}
	}
}
