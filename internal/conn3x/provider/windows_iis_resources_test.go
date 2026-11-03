// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/providers"
)

func TestWinAppPoolValidate(t *testing.T) {
	r := resourceTypes["conn3x_windows_iis_app_pool"]
	if d := r.validate(objFor(r.schema(), map[string]cty.Value{
		"name": cty.StringVal("shop"), "managed_runtime_version": cty.StringVal(""), "pipeline_mode": cty.StringVal("classic"),
		"identity": cty.StringVal("NetworkService"), "state": cty.StringVal("stopped"),
	})); d.HasErrors() {
		t.Fatal(d.Err())
	}
	for name, a := range map[string]map[string]cty.Value{
		"wildcard":  {"name": cty.StringVal("shop*")},
		"state":     {"name": cty.StringVal("a"), "state": cty.StringVal("restarted")},
		"identity":  {"name": cty.StringVal("a"), "identity": cty.StringVal("SpecificUser")},
		"runtime":   {"name": cty.StringVal("a"), "managed_runtime_version": cty.StringVal("4")},
		"on_remove": {"name": cty.StringVal("a"), "on_remove": cty.StringVal("purge")},
	} {
		if d := r.validate(objFor(r.schema(), a)); !d.HasErrors() {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The defaults are IIS's own for a new pool.
func TestWinAppPoolDefaults(t *testing.T) {
	r := resourceTypes["conn3x_windows_iis_app_pool"]
	p := winAppPoolFrom(objFor(r.schema(), map[string]cty.Value{"name": cty.StringVal("shop")}))
	if !p.Started || p.RuntimeVersion != "v4.0" || p.PipelineMode != "integrated" || p.Identity != "ApplicationPoolIdentity" {
		t.Errorf("%+v", p)
	}
}

func siteObj(r resourceType, attrs map[string]cty.Value, bindings ...map[string]cty.Value) cty.Value {
	c := objFor(r.schema(), attrs).AsValueMap()
	ety := r.schema().Block.BlockTypes["binding"].Block.ImpliedType()
	var bs []cty.Value
	for _, b := range bindings {
		vals := map[string]cty.Value{}
		for k, ty := range ety.AttributeTypes() {
			vals[k] = cty.NullVal(ty)
		}
		for k, v := range b {
			vals[k] = v
		}
		bs = append(bs, cty.ObjectVal(vals))
	}
	if len(bs) == 0 {
		c["binding"] = cty.ListValEmpty(ety)
	} else {
		c["binding"] = cty.ListVal(bs)
	}
	return cty.ObjectVal(c)
}

func TestWinSiteValidate(t *testing.T) {
	r := resourceTypes["conn3x_windows_iis_site"]
	base := map[string]cty.Value{"name": cty.StringVal("shop"), "physical_path": cty.StringVal(`C:\sites\shop`)}
	port80 := map[string]cty.Value{"port": cty.NumberIntVal(80), "host_header": cty.StringVal("shop.example.com")}
	if d := r.validate(siteObj(r, base, port80)); d.HasErrors() {
		t.Fatal(d.Err())
	}
	if p := winSiteFrom(siteObj(r, base, port80)); len(p.Bindings) != 1 || p.Bindings[0].Protocol != "http" || p.Bindings[0].IP != "*" || !p.Started {
		t.Errorf("defaults: %+v", p)
	}
	for name, c := range map[string]cty.Value{
		"no binding": siteObj(r, base),
		"https":      siteObj(r, base, map[string]cty.Value{"port": cty.NumberIntVal(443), "protocol": cty.StringVal("https")}),
		"bad ip":     siteObj(r, base, map[string]cty.Value{"port": cty.NumberIntVal(80), "ip": cty.StringVal("any")}),
		"unc path":   siteObj(r, map[string]cty.Value{"name": cty.StringVal("shop"), "physical_path": cty.StringVal(`\\s\x`)}, port80),
		"state":      siteObj(r, map[string]cty.Value{"name": cty.StringVal("shop"), "physical_path": cty.StringVal(`C:\x`), "state": cty.StringVal("absent")}, port80),
		"twice":      siteObj(r, base, port80, port80),
	} {
		if d := r.validate(c); !d.HasErrors() {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestWinIISDeletesByDefaultAndIgnoresCase(t *testing.T) {
	for _, kind := range []string{"conn3x_windows_iis_app_pool", "conn3x_windows_iis_site"} {
		r := resourceTypes[kind]
		c := objFor(r.schema(), map[string]cty.Value{"name": cty.StringVal("Shop")})
		p := r.plan(providers.PlanResourceChangeRequest{PriorState: cty.NullVal(c.Type()), ProposedNewState: c, Config: c}).PlannedState
		if p.GetAttr("on_remove").AsString() != "delete" {
			t.Errorf("%s: on_remove = %#v", kind, p.GetAttr("on_remove"))
		}
		vals := p.AsValueMap()
		vals["revision"], vals["in_sync"] = cty.StringVal("r"), cty.True
		lower := objFor(r.schema(), map[string]cty.Value{"name": cty.StringVal("shop")})
		if resp := r.plan(providers.PlanResourceChangeRequest{PriorState: cty.ObjectVal(vals), ProposedNewState: lower, Config: lower}); len(resp.RequiresReplace) != 0 {
			t.Errorf("%s: replaces: %v", kind, resp.RequiresReplace)
		}
	}
}
