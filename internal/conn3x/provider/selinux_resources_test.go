// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/providers"
)

func TestSELinuxPlan(t *testing.T) {
	for rt, c := range map[string]struct {
		key, setting  string
		before, after cty.Value
	}{
		"conn3x_selinux_boolean":  {"name", "value", cty.False, cty.True},
		"conn3x_selinux_fcontext": {"target", "setype", cty.StringVal("var_t"), cty.StringVal("httpd_sys_content_t")},
	} {
		r := resourceTypes[rt]
		keyVal := cty.StringVal("/srv/www(/.*)?")
		if c.key == "name" {
			keyVal = cty.StringVal("httpd_can_network_connect")
		}
		cfg := objFor(r.schema(), map[string]cty.Value{c.key: keyVal, c.setting: c.before})
		created := r.plan(providers.PlanResourceChangeRequest{PriorState: cty.NullVal(cfg.Type()), ProposedNewState: cfg, Config: cfg}).PlannedState
		if got := created.GetAttr("id"); !got.RawEquals(cty.StringVal("203.0.113.10:" + rt[len("conn3x_"):] + ":" + keyVal.AsString())) {
			t.Errorf("%s: id = %#v", rt, got)
		}
		prior := withSync(created, true)
		next := objFor(r.schema(), map[string]cty.Value{c.key: keyVal, c.setting: c.after})
		resp := r.plan(providers.PlanResourceChangeRequest{PriorState: prior, ProposedNewState: next, Config: next})
		if len(resp.RequiresReplace) != 0 || resp.PlannedState.GetAttr("in_sync").IsKnown() {
			t.Errorf("%s: changing %s must update in place: %v", rt, c.setting, resp.RequiresReplace)
		}
	}
}

func TestSELinuxValidate(t *testing.T) {
	for rt, cfg := range map[string]map[string]cty.Value{
		"conn3x_selinux_boolean":  {"name": cty.StringVal("bad name"), "value": cty.True},
		"conn3x_selinux_fcontext": {"target": cty.StringVal("srv/www"), "setype": cty.StringVal("httpd_sys_content_t")},
	} {
		if diags := resourceTypes[rt].validate(objFor(resourceTypes[rt].schema(), cfg)); !diags.HasErrors() {
			t.Errorf("%s accepted %v", rt, cfg)
		}
	}
}
