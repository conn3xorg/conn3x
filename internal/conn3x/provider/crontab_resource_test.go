// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"strings"
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/providers"
)

func crontabJobs(jobs ...[3]string) cty.Value {
	vals := make([]cty.Value, len(jobs))
	for i, j := range jobs {
		vals[i] = cty.ObjectVal(map[string]cty.Value{"name": cty.StringVal(j[0]), "schedule": cty.StringVal(j[1]), "command": cty.StringVal(j[2])})
	}
	return cty.ListVal(vals)
}

// A crontab step leaves the crontab when removed unless told otherwise,
// plans the unlisted lines away, updates in place when its jobs change,
// and replaces when its user does.
func TestPlanCrontab(t *testing.T) {
	r := resourceTypes["conn3x_crontab"]
	cfg := objFor(r.schema(), map[string]cty.Value{"user": cty.StringVal("deploy"), "job": crontabJobs([3]string{"backup", "@daily", "/opt/backup"})})
	if diags := r.validate(cfg); diags.HasErrors() {
		t.Fatal(diags.Err())
	}
	created := r.plan(providers.PlanResourceChangeRequest{PriorState: cty.NullVal(cfg.Type()), ProposedNewState: cfg, Config: cfg}).PlannedState
	if got := created.GetAttr("on_remove"); !got.RawEquals(cty.StringVal(onRemoveForget)) {
		t.Errorf("on_remove defaults to %#v", got)
	}
	if got := created.GetAttr("unlisted"); !got.RawEquals(cty.ListValEmpty(cty.String)) {
		t.Errorf("unlisted planned as %#v", got)
	}
	prior := created.AsValueMap()
	prior["id"], prior["in_sync"] = cty.StringVal("203.0.113.10:crontab:deploy"), cty.True
	prior["unlisted"] = cty.ListValEmpty(cty.String)

	more := objFor(r.schema(), map[string]cty.Value{"user": cty.StringVal("deploy"), "job": crontabJobs([3]string{"backup", "@daily", "/opt/backup"}, [3]string{"rotate", "@weekly", "/opt/rotate"})})
	resp := r.plan(providers.PlanResourceChangeRequest{PriorState: cty.ObjectVal(prior), ProposedNewState: more, Config: more})
	if len(resp.RequiresReplace) != 0 || resp.PlannedState.GetAttr("in_sync").IsKnown() {
		t.Errorf("a new job: replace %v, in_sync %#v", resp.RequiresReplace, resp.PlannedState.GetAttr("in_sync"))
	}
	prior["unlisted"] = cty.ListVal([]cty.Value{cty.StringVal("@hourly sha256:x")})
	if resp := r.plan(providers.PlanResourceChangeRequest{PriorState: cty.ObjectVal(prior), ProposedNewState: cfg, Config: cfg}); resp.PlannedState.GetAttr("in_sync").IsKnown() {
		t.Error("an unlisted line plans no change")
	}
	other := objFor(r.schema(), map[string]cty.Value{"user": cty.StringVal("ops"), "job": crontabJobs([3]string{"backup", "@daily", "/opt/backup"})})
	if resp := r.plan(providers.PlanResourceChangeRequest{PriorState: cty.ObjectVal(prior), ProposedNewState: other, Config: other}); len(resp.RequiresReplace) != 1 {
		t.Errorf("a new user doesn't replace: %v", resp.RequiresReplace)
	}

	bad := objFor(r.schema(), map[string]cty.Value{"user": cty.StringVal("deploy"), "job": crontabJobs([3]string{"a", "@daily", "x"}, [3]string{"a", "@daily", "y"})})
	if diags := r.validate(bad); !diags.HasErrors() || !strings.Contains(diags.Err().Error(), "two jobs are named") {
		t.Errorf("two jobs with one name: %v", diags.Err())
	}
}
