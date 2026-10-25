// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/providers"
)

// withSSH returns v with its ssh block's user (and a short dial timeout) set.
func withSSH(v cty.Value, user string) cty.Value {
	vals := v.AsValueMap()
	s := vals["ssh"].AsValueMap()
	s["user"], s["timeout"] = cty.StringVal(user), cty.StringVal("1s")
	vals["ssh"] = cty.ObjectVal(s)
	return cty.ObjectVal(vals)
}

// Changing only how Conn3x logs in is an update with nothing to do on the
// host: no command rerun, no re-extract, no forced checkout, no reboot. The
// test host is unreachable, so touching it would fail.
func TestUpdateWithNothingStaleLeavesTheHostAlone(t *testing.T) {
	for rt, attrs := range map[string]map[string]cty.Value{
		"conn3x_command": {"command": cty.StringVal("touch /x"), "satisfied": cty.True, "stdout": cty.StringVal(""), "stderr": cty.StringVal("")},
		"conn3x_archive": {"src": cty.StringVal("/tmp/a.tgz"), "dest": cty.StringVal("/opt/a"), "creates": cty.StringVal("/opt/a/x")},
		"conn3x_git":     {"repo": cty.StringVal("https://example.com/a.git"), "dest": cty.StringVal("/srv/a"), "commit": cty.StringVal("7fd1a60b01f91b314f59955a4e4d4e80d8edf11d")},
		"conn3x_reboot":  {"boot_id": cty.StringVal("b1")},
	} {
		r := resourceTypes[rt]
		attrs["id"] = cty.StringVal("x")
		if r.schema().Block.Attributes["in_sync"] != nil {
			attrs["in_sync"] = cty.True
		}
		prior := withSSH(objFor(r.schema(), attrs), "root")
		next := withSSH(prior, "deploy")
		plan := r.plan(providers.PlanResourceChangeRequest{PriorState: prior, ProposedNewState: next, Config: next})
		if len(plan.RequiresReplace) != 0 {
			t.Errorf("%s: a login change requires replace: %v", rt, plan.RequiresReplace)
			continue
		}
		resp := r.apply(context.Background(), providers.ApplyResourceChangeRequest{PriorState: prior, PlannedState: plan.PlannedState, Config: next})
		if resp.Diagnostics.HasErrors() {
			t.Errorf("%s: apply touched the host: %v", rt, resp.Diagnostics.Err())
			continue
		}
		if !resp.NewState.RawEquals(plan.PlannedState) {
			t.Errorf("%s: new state differs from the plan", rt)
		}
	}
}

func TestModeMustBeFourDigits(t *testing.T) {
	for _, rt := range []string{"conn3x_file", "conn3x_directory"} {
		r := resourceTypes[rt]
		cfg := objFor(r.schema(), map[string]cty.Value{"path": cty.StringVal("/etc/x"), "mode": cty.StringVal("755"), "content": cty.StringVal("")})
		if !r.validate(cfg).HasErrors() {
			t.Errorf("%s accepted mode 755, which plan would rewrite", rt)
		}
	}
}

// Resources that grant access or run jobs clean up after themselves, so a
// rotated key or a renamed job does not leave the old one active.
func TestAccessAndJobsDeleteOnRemove(t *testing.T) {
	for rt, attrs := range map[string]map[string]cty.Value{
		"conn3x_authorized_key": {"user": cty.StringVal("alice"), "key": cty.StringVal("ssh-ed25519 AAAA")},
		"conn3x_cron":           {"name": cty.StringVal("x"), "schedule": cty.StringVal("@daily"), "command": cty.StringVal("true")},
		"conn3x_timer":          {"name": cty.StringVal("x"), "on_calendar": cty.StringVal("daily"), "command": cty.StringVal("true")},
	} {
		r := resourceTypes[rt]
		cfg := objFor(r.schema(), attrs)
		planned := r.plan(providers.PlanResourceChangeRequest{PriorState: cty.NullVal(cfg.Type()), ProposedNewState: cfg, Config: cfg}).PlannedState
		if got := planned.GetAttr("on_remove"); !got.RawEquals(cty.StringVal(onRemoveDelete)) {
			t.Errorf("%s: on_remove defaults to %#v", rt, got)
		}
	}
}
