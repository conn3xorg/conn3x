// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/providers"
)

func packageObj(t *testing.T, attrs map[string]cty.Value) cty.Value {
	t.Helper()
	ty := packageSchema().Block.ImpliedType()
	vals := map[string]cty.Value{}
	for name, at := range ty.AttributeTypes() {
		vals[name] = cty.NullVal(at)
	}
	sshTy := ty.AttributeType("ssh")
	sshVals := map[string]cty.Value{}
	for name, at := range sshTy.AttributeTypes() {
		sshVals[name] = cty.NullVal(at)
	}
	sshVals["host"] = cty.StringVal("203.0.113.10")
	sshVals["user"] = cty.StringVal("root")
	vals["ssh"] = cty.ObjectVal(sshVals)
	for k, v := range attrs {
		vals[k] = v
	}
	return cty.ObjectVal(vals)
}

func planPkg(t *testing.T, prior, config cty.Value) cty.Value {
	t.Helper()
	proposed := config
	if !prior.IsNull() {
		vals := config.AsValueMap()
		for _, n := range []string{"id", "state", "on_remove", "installed_version", "latest_version"} {
			if vals[n].IsNull() {
				vals[n] = prior.GetAttr(n)
			}
		}
		proposed = cty.ObjectVal(vals)
	}
	resp := planPackage(providers.PlanResourceChangeRequest{PriorState: prior, ProposedNewState: proposed, Config: config})
	if resp.Diagnostics.HasErrors() {
		t.Fatal(resp.Diagnostics.Err())
	}
	return resp.PlannedState
}

func TestPackagePlanCreate(t *testing.T) {
	cfg := packageObj(t, map[string]cty.Value{"name": cty.StringVal("nginx")})
	planned := planPkg(t, cty.NullVal(cfg.Type()), cfg)
	if !planned.GetAttr("state").RawEquals(cty.StringVal("present")) {
		t.Fatalf("state = %#v", planned.GetAttr("state"))
	}
	if planned.GetAttr("installed_version").IsKnown() {
		t.Fatal("installed_version known before install")
	}
}

func TestPackagePlanNoChangeWhenInstalled(t *testing.T) {
	prior := packageObj(t, map[string]cty.Value{
		"id": cty.StringVal("h:package:nginx"), "name": cty.StringVal("nginx"), "state": cty.StringVal("present"),
		"on_remove": cty.StringVal("forget"), "installed_version": cty.StringVal("1:1.26.3-2.el10"),
	})
	cfg := packageObj(t, map[string]cty.Value{"name": cty.StringVal("nginx")})
	planned := planPkg(t, prior, cfg)
	if !planned.GetAttr("installed_version").RawEquals(cty.StringVal("1:1.26.3-2.el10")) {
		t.Fatalf("installed_version = %#v, want unchanged", planned.GetAttr("installed_version"))
	}
}

func TestPackagePlanReinstallsWhenRemovedByHand(t *testing.T) {
	prior := packageObj(t, map[string]cty.Value{
		"id": cty.StringVal("h:package:nginx"), "name": cty.StringVal("nginx"), "state": cty.StringVal("present"),
		"on_remove": cty.StringVal("forget"),
	})
	cfg := packageObj(t, map[string]cty.Value{"name": cty.StringVal("nginx")})
	if planPkg(t, prior, cfg).GetAttr("installed_version").IsKnown() {
		t.Fatal("a missing package was not planned for install")
	}
}

func TestPackagePlanLatestUpgrades(t *testing.T) {
	prior := packageObj(t, map[string]cty.Value{
		"id": cty.StringVal("h:package:nginx"), "name": cty.StringVal("nginx"), "state": cty.StringVal("latest"),
		"on_remove": cty.StringVal("forget"), "installed_version": cty.StringVal("1.0-1"), "latest_version": cty.StringVal("1.1-1"),
	})
	cfg := packageObj(t, map[string]cty.Value{"name": cty.StringVal("nginx"), "state": cty.StringVal("latest")})
	if planPkg(t, prior, cfg).GetAttr("installed_version").IsKnown() {
		t.Fatal("an available upgrade was not planned")
	}
}

func TestPackagePlanCreateAbsent(t *testing.T) {
	cfg := packageObj(t, map[string]cty.Value{"name": cty.StringVal("telnet"), "state": cty.StringVal("absent")})
	planned := planPkg(t, cty.NullVal(cfg.Type()), cfg)
	if !planned.GetAttr("installed_version").IsNull() {
		t.Fatalf("installed_version = %#v, want null", planned.GetAttr("installed_version"))
	}
}

func TestPackageValidate(t *testing.T) {
	for name, attrs := range map[string]map[string]cty.Value{
		"bad name":          {"name": cty.StringVal("nginx; reboot")},
		"bad state":         {"name": cty.StringVal("nginx"), "state": cty.StringVal("installed")},
		"version on absent": {"name": cty.StringVal("nginx"), "state": cty.StringVal("absent"), "version": cty.StringVal("1")},
		"bad on_remove":     {"name": cty.StringVal("nginx"), "on_remove": cty.StringVal("purge")},
	} {
		if !validatePackage(packageObj(t, attrs)).HasErrors() {
			t.Errorf("%s accepted", name)
		}
	}
	if d := validatePackage(packageObj(t, map[string]cty.Value{"name": cty.StringVal("nginx")})); d.HasErrors() {
		t.Errorf("valid config rejected: %s", d.Err())
	}
}
