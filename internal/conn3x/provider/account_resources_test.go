// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/providers"
)

func userObj(attrs map[string]cty.Value) cty.Value {
	ty := userSchema().Block.ImpliedType()
	vals := map[string]cty.Value{}
	for name, at := range ty.AttributeTypes() {
		vals[name] = cty.NullVal(at)
	}
	sshVals := map[string]cty.Value{}
	for name, at := range ty.AttributeType("ssh").AttributeTypes() {
		sshVals[name] = cty.NullVal(at)
	}
	sshVals["host"], sshVals["user"] = cty.StringVal("203.0.113.10"), cty.StringVal("root")
	vals["ssh"] = cty.ObjectVal(sshVals)
	for k, v := range attrs {
		vals[k] = v
	}
	return cty.ObjectVal(vals)
}

var deployState = map[string]cty.Value{
	"id": cty.StringVal("203.0.113.10:user:deploy"), "name": cty.StringVal("deploy"), "on_remove": cty.StringVal("forget"),
	"uid": cty.NumberIntVal(1001), "group": cty.StringVal("deploy"), "groups": cty.SetVal([]cty.Value{cty.StringVal("wheel")}),
	"home": cty.StringVal("/home/deploy"), "shell": cty.StringVal("/bin/bash"),
}

func planUsr(prior, cfg cty.Value) cty.Value {
	proposed := cfg
	if !prior.IsNull() {
		vals := cfg.AsValueMap()
		for _, n := range append([]string{"id", "on_remove"}, userObserved...) {
			if vals[n].IsNull() {
				vals[n] = prior.GetAttr(n)
			}
		}
		proposed = cty.ObjectVal(vals)
	}
	return planUser(providers.PlanResourceChangeRequest{PriorState: prior, ProposedNewState: proposed, Config: cfg}).PlannedState
}

func TestUserPlanIgnoresUnmanagedFields(t *testing.T) {
	prior := userObj(deployState)
	cfg := userObj(map[string]cty.Value{"name": cty.StringVal("deploy"), "shell": cty.StringVal("/bin/bash")})
	if planned := planUsr(prior, cfg); !planned.RawEquals(prior) {
		t.Fatalf("no-op plan changed state:\n%#v", planned)
	}
}

func TestUserPlanShellChange(t *testing.T) {
	prior := userObj(deployState)
	cfg := userObj(map[string]cty.Value{"name": cty.StringVal("deploy"), "shell": cty.StringVal("/bin/zsh")})
	planned := planUsr(prior, cfg)
	if !planned.GetAttr("shell").RawEquals(cty.StringVal("/bin/zsh")) {
		t.Fatalf("shell = %#v", planned.GetAttr("shell"))
	}
	if planned.GetAttr("uid").IsKnown() {
		t.Fatal("unmanaged uid should be unknown during a change")
	}
}

func TestUserPlanRecreatesDeletedAccount(t *testing.T) {
	gone := map[string]cty.Value{"id": deployState["id"], "name": deployState["name"], "on_remove": deployState["on_remove"]}
	prior := userObj(gone)
	cfg := userObj(map[string]cty.Value{"name": cty.StringVal("deploy")})
	if planUsr(prior, cfg).GetAttr("uid").IsKnown() {
		t.Fatal("a deleted account was not planned for creation")
	}
}

func TestUserValidate(t *testing.T) {
	if !validateUser(userObj(map[string]cty.Value{"name": cty.StringVal("Deploy")})).HasErrors() {
		t.Error("uppercase name accepted")
	}
	if !validateUser(userObj(map[string]cty.Value{"name": cty.StringVal("deploy"), "shell": cty.StringVal("zsh")})).HasErrors() {
		t.Error("relative shell accepted")
	}
}

// Apply gets the raw config, not the one ignore_changes was applied to, so
// an ignored argument must take its planned (prior) value.
func TestWithIgnoredKeepsPlannedValues(t *testing.T) {
	cfg := userObj(map[string]cty.Value{"name": cty.StringVal("deploy"), "shell": cty.StringVal("/bin/sh")})
	planned := userObj(deployState) // shell ignored: planned carries the prior /bin/bash
	got := userSpec(withIgnored(cfg, planned))
	if got.Shell == nil || *got.Shell != "/bin/bash" {
		t.Fatalf("shell = %v, want the planned /bin/bash", got.Shell)
	}
	if got.Home != nil || got.UID != nil {
		t.Fatalf("arguments the config leaves out became managed: %+v", got)
	}
}
