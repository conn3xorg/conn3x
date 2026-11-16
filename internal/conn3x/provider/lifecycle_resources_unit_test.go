// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"strings"
	"sync"
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/providers"
)

// unitBooting answers a reboot step as a host whose boot ID changes when
// the reboot it schedules happens, unless stuck.
type unitBooting struct {
	mu      sync.Mutex
	boot    string
	stuck   bool
	reboots int
}

func (b *unitBooting) answer(script string) (string, int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	switch {
	case strings.Contains(script, "/proc/sys/kernel/random/boot_id"):
		return b.boot + "\n", 0
	case strings.Contains(script, "systemctl reboot"):
		b.reboots++
		if !b.stuck {
			b.boot += "-next"
		}
	}
	return "", 0
}

func rebootStep(ssh map[string]cty.Value, timeout string) cty.Value {
	attrs := map[string]cty.Value{"triggers": cty.MapVal(map[string]cty.Value{"kernel": cty.StringVal("6.12")})}
	if timeout != "" {
		attrs["timeout"] = cty.StringVal(timeout)
	}
	return eosStep("conn3x_reboot", attrs, ssh)
}

// A reboot waits for the host to come back with a new boot ID, and records
// it.
func TestRebootWaitsForANewBoot(t *testing.T) {
	t.Parallel()
	b := &unitBooting{boot: "b1"}
	state, err := unitCreate(t, "conn3x_reboot", rebootStep(unitHost(t, b.answer), ""))
	if err != nil {
		t.Fatal(err)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if got := state.GetAttr("boot_id"); !got.RawEquals(cty.StringVal("b1-next")) || b.reboots != 1 {
		t.Errorf("boot_id %#v after %d reboots", got, b.reboots)
	}
	if read, err := unitRead("conn3x_reboot", state); err != nil || !read.RawEquals(state) {
		t.Errorf("read changed the state: %#v, %v", read, err)
	}
}

// A host that never comes back with a new boot ID fails the step once the
// timeout is up.
func TestRebootGivesUpOnAHostThatDoesntReboot(t *testing.T) {
	t.Parallel()
	b := &unitBooting{boot: "b1", stuck: true}
	_, err := unitCreate(t, "conn3x_reboot", rebootStep(unitHost(t, b.answer), "1s"))
	if err == nil || !strings.Contains(err.Error(), "did not come back within 1s") {
		t.Errorf("err = %v", err)
	}
}

func TestRebootStopsAtTheFirstError(t *testing.T) {
	for name, c := range map[string]struct {
		answer  func(string) (string, int)
		timeout string
		want    string
	}{
		"no boot id":       {(&unitScripts{}).on("boot_id", "!cat: no such file").answer, "", "reading the boot id"},
		"refused":          {(&unitScripts{}).on("boot_id", "b1").on("systemctl reboot", "!not allowed").answer, "", "scheduling a reboot"},
		"negative timeout": {(&unitScripts{}).answer, "-1m", "positive duration"},
	} {
		_, err := applyRebootErr(t, rebootStep(unitHost(t, c.answer), c.timeout))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	bad := eosStep("conn3x_reboot", nil, map[string]cty.Value{"private_key_file": cty.StringVal(t.TempDir() + "/missing")})
	if _, err := applyRebootErr(t, bad); err == nil {
		t.Error("a login with a missing key rebooted")
	}
}

// applyRebootErr applies a reboot planned from nothing, without the
// provider's validate, so a bad timeout reaches the apply.
func applyRebootErr(t *testing.T, cfg cty.Value) (cty.Value, error) {
	t.Helper()
	null := cty.NullVal(cfg.Type())
	planned := planReboot(providers.PlanResourceChangeRequest{PriorState: null, ProposedNewState: cfg, Config: cfg}).PlannedState
	resp := applyReboot(ctx, providers.ApplyResourceChangeRequest{PriorState: null, PlannedState: planned, Config: cfg})
	return resp.NewState, resp.Diagnostics.Err()
}

// Moving the step to another host reboots that one; destroying it plans
// nothing.
func TestRebootPlansForANewHost(t *testing.T) {
	r := resourceTypes["conn3x_reboot"]
	prior := objFor(r.schema(), map[string]cty.Value{"id": cty.StringVal("203.0.113.10:reboot"), "boot_id": cty.StringVal("b1")})
	vals := prior.AsValueMap()
	ssh := vals["ssh"].AsValueMap()
	ssh["host"] = cty.StringVal("203.0.113.11")
	vals["ssh"] = cty.ObjectVal(ssh)
	moved := cty.ObjectVal(vals)
	resp := r.plan(providers.PlanResourceChangeRequest{PriorState: prior, ProposedNewState: moved, Config: moved})
	if len(resp.RequiresReplace) != 1 || resp.PlannedState.GetAttr("boot_id").IsKnown() {
		t.Errorf("another host: replace %v, boot_id %#v", resp.RequiresReplace, resp.PlannedState.GetAttr("boot_id"))
	}
	if gone := r.plan(providers.PlanResourceChangeRequest{PriorState: prior, ProposedNewState: cty.NullVal(prior.Type())}); !gone.PlannedState.IsNull() {
		t.Errorf("destroy planned %#v", gone.PlannedState)
	}
	if resp := applyReboot(ctx, providers.ApplyResourceChangeRequest{PriorState: prior, PlannedState: prior}); !resp.NewState.RawEquals(prior) {
		t.Error("a known boot_id rebooted")
	}
}
