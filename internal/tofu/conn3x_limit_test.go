// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package tofu

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/opentofu/opentofu/internal/addrs"
	"github.com/opentofu/opentofu/internal/conn3x/hostpattern"
	"github.com/opentofu/opentofu/internal/plans"
	"github.com/opentofu/opentofu/internal/states"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

func limitPlan(t *testing.T, pattern string, mode plans.Mode) (*plans.Plan, []string) {
	t.Helper()
	src := strings.NewReplacer("STRATEGY", "", "EXTRA", "").Replace(chainCircuit) + `
resource "conn3x_command" "other" {
  command = "other"
}
`
	m := testModuleInline(t, map[string]string{"main.circuit.hcl": src})
	limit, err := hostpattern.Parse(pattern)
	if err != nil {
		t.Fatal(err)
	}
	opts := &PlanOpts{Mode: mode, Limit: limit}
	plan, diags := chainContext(t, newChainProvider()).Plan(context.Background(), m, states.NewState(), opts)
	var msgs []string
	for _, d := range diags {
		msgs = append(msgs, d.Description().Summary)
	}
	if diags.HasErrors() {
		return nil, msgs
	}
	return plan, msgs
}

func plannedAddrs(plan *plans.Plan) []string {
	var out []string
	for _, rc := range plan.Changes.Resources {
		if rc.Action != plans.NoOp {
			out = append(out, rc.Addr.String())
		}
	}
	slices.Sort(out)
	return out
}

func TestConn3xLimit(t *testing.T) {
	plan, msgs := limitPlan(t, "a", plans.NormalMode)
	got := plannedAddrs(plan)
	want := []string{
		`conn3x_command.web__items["a/x"]`,
		`conn3x_command.web__items["a/y"]`,
		`conn3x_command.web__one["a"]`,
		`conn3x_command.web__two["a"]`,
		`conn3x_service_action.web__restart["a"]`,
	}
	if !slices.Equal(got, want) {
		t.Errorf("planned %v\nwant %v", got, want)
	}
	if !slices.Contains(msgs, "Limited to some hosts") || slices.Contains(msgs, "Resource targeting is in effect") {
		t.Errorf("diagnostics %v: want the limit's warning and not -target's", msgs)
	}
	if len(plan.TargetAddrs) == 0 {
		t.Error("the plan records no targets, so an apply of it would reach other resources")
	}
}

func TestConn3xLimitNoMatch(t *testing.T) {
	plan, msgs := limitPlan(t, "web*", plans.NormalMode)
	if got := plannedAddrs(plan); len(got) != 0 {
		t.Errorf("planned %v, want nothing", got)
	}
	if !slices.Contains(msgs, "-limit matched no host") {
		t.Errorf("diagnostics %v: want a warning that nothing matched", msgs)
	}
}

func TestConn3xLimitDestroy(t *testing.T) {
	if _, msgs := limitPlan(t, "a", plans.DestroyMode); !slices.Contains(msgs, "-limit can't be used with -destroy") {
		t.Errorf("diagnostics %v: want -destroy refused", msgs)
	}
}

// An apply of a limited plan leaves the other hosts' steps, and resources
// the steps don't need, out of state.
func TestConn3xLimitApply(t *testing.T) {
	src := strings.NewReplacer("STRATEGY", "", "EXTRA", "").Replace(chainCircuit) + `
resource "conn3x_command" "other" {
  command = "other"
}
`
	m := testModuleInline(t, map[string]string{"main.circuit.hcl": src})
	limit, err := hostpattern.Parse("b")
	if err != nil {
		t.Fatal(err)
	}
	ctx := chainContext(t, newChainProvider())
	plan, diags := ctx.Plan(context.Background(), m, states.NewState(), &PlanOpts{Mode: plans.NormalMode, Limit: limit})
	assertNoErrors(t, diags)
	state, diags := ctx.Apply(context.Background(), plan, m, nil)
	assertNoErrors(t, diags)
	var got []string
	for _, r := range state.RootModule().Resources {
		for k := range r.Instances {
			got = append(got, r.Addr.Instance(k).String())
		}
	}
	slices.Sort(got)
	want := []string{
		`conn3x_command.web__items["b/x"]`,
		`conn3x_command.web__items["b/y"]`,
		`conn3x_command.web__one["b"]`,
		`conn3x_command.web__two["b"]`,
		`conn3x_service_action.web__restart["b"]`,
	}
	if !slices.Equal(got, want) {
		t.Errorf("state has %v\nwant %v", got, want)
	}
}

// A change limited to one host leaves the other host's steps in state as
// they were, rather than dropping or changing them.
func TestConn3xLimitKeepsOtherHosts(t *testing.T) {
	module := func(cmd string) string {
		return strings.NewReplacer("STRATEGY", "", "EXTRA", "", `"one-${each.key}"`, cmd).Replace(chainCircuit)
	}
	ctx := chainContext(t, newChainProvider())
	m := testModuleInline(t, map[string]string{"main.circuit.hcl": module(`"old"`)})
	plan, diags := ctx.Plan(context.Background(), m, states.NewState(), DefaultPlanOpts)
	assertNoErrors(t, diags)
	state, diags := ctx.Apply(context.Background(), plan, m, nil)
	assertNoErrors(t, diags)

	limit, _ := hostpattern.Parse("a")
	m = testModuleInline(t, map[string]string{"main.circuit.hcl": module(`"new"`)})
	plan, diags = ctx.Plan(context.Background(), m, state, &PlanOpts{Mode: plans.NormalMode, Limit: limit})
	assertNoErrors(t, diags)
	if got := plannedAddrs(plan); !slices.Equal(got, []string{`conn3x_command.web__one["a"]`}) {
		t.Errorf("planned %v, want only a's step", got)
	}
	state, diags = ctx.Apply(context.Background(), plan, m, nil)
	assertNoErrors(t, diags)
	one := state.RootModule().Resources[`conn3x_command.web__one`]
	for host, want := range map[string]string{"a": "new", "b": "old"} {
		inst := one.Instances[addrs.StringKey(host)]
		if inst == nil || !strings.Contains(string(inst.Current.AttrsJSON), `"command":"`+want+`"`) {
			t.Errorf("%s: want command %q in state, got %v", host, want, inst)
		}
	}
}

// Review findings on #685: deposed objects, host names with "/", removed
// steps and moved blocks.
func TestConn3xLimitEdges(t *testing.T) {
	limitOf := func(p string) *hostpattern.Pattern {
		l, err := hostpattern.Parse(p)
		if err != nil {
			t.Fatal(err)
		}
		return l
	}
	msgsOf := func(diags tfdiags.Diagnostics) []string {
		var out []string
		for _, d := range diags {
			out = append(out, d.Description().Summary)
		}
		return out
	}

	t.Run("deposed on another host", func(t *testing.T) {
		m := chainModule(t, "", "")
		state := states.NewState()
		state.SyncWrapper().SetResourceInstanceDeposed(mustResourceInstanceAddr(`conn3x_command.web__one["b"]`), states.DeposedKey("00000001"),
			&states.ResourceInstanceObjectSrc{Status: states.ObjectReady, AttrsJSON: []byte(`{"id":"old","command":"one-b"}`)},
			mustProviderConfig(`provider["terraform.io/builtin/conn3x"]`), addrs.NoKey)
		plan, diags := chainContext(t, newChainProvider()).Plan(context.Background(), m, state, &PlanOpts{Mode: plans.NormalMode, Limit: limitOf("a")})
		assertNoErrors(t, diags)
		for _, rc := range plan.Changes.Resources {
			if rc.DeposedKey != states.NotDeposed {
				t.Errorf("planned %s for deposed %s on a host outside -limit", rc.Action, rc.Addr)
			}
		}
	})

	t.Run("host name with a slash", func(t *testing.T) {
		src := strings.NewReplacer("STRATEGY", "", "EXTRA", "", `a = "10.0.0.1", b = "10.0.0.2"`, `a = "10.0.0.1", "a/b" = "10.0.0.2"`).Replace(chainCircuit)
		m := testModuleInline(t, map[string]string{"main.circuit.hcl": src})
		plan, diags := chainContext(t, newChainProvider()).Plan(context.Background(), m, states.NewState(), &PlanOpts{Mode: plans.NormalMode, Limit: limitOf("a")})
		assertNoErrors(t, diags)
		for _, a := range plannedAddrs(plan) {
			if strings.Contains(a, `"a/b`) {
				t.Errorf("planned %s, on host a/b, for -limit=a", a)
			}
		}
	})

	t.Run("removed step", func(t *testing.T) {
		m := chainModule(t, "", "")
		state := states.NewState()
		state.SyncWrapper().SetResourceInstanceCurrent(mustResourceInstanceAddr(`conn3x_command.web__gone["a"]`),
			&states.ResourceInstanceObjectSrc{Status: states.ObjectReady, AttrsJSON: []byte(`{"id":"x","command":"gone"}`)},
			mustProviderConfig(`provider["terraform.io/builtin/conn3x"]`), addrs.NoKey)
		_, diags := chainContext(t, newChainProvider()).Plan(context.Background(), m, state, &PlanOpts{Mode: plans.NormalMode, Limit: limitOf("a")})
		assertNoErrors(t, diags)
		if !slices.Contains(msgsOf(diags), "Removed steps stay on their hosts") {
			t.Errorf("diagnostics %v: want a warning that web__gone stays", msgsOf(diags))
		}
	})

	t.Run("moved block outside the circuits", func(t *testing.T) {
		src := strings.NewReplacer("STRATEGY", "", "EXTRA", "").Replace(chainCircuit) + `
resource "conn3x_command" "new" {
  command = "x"
}
moved {
  from = conn3x_command.old
  to   = conn3x_command.new
}
`
		m := testModuleInline(t, map[string]string{"main.circuit.hcl": src})
		state := states.NewState()
		state.SyncWrapper().SetResourceInstanceCurrent(mustResourceInstanceAddr(`conn3x_command.old`),
			&states.ResourceInstanceObjectSrc{Status: states.ObjectReady, AttrsJSON: []byte(`{"id":"x","command":"x"}`)},
			mustProviderConfig(`provider["terraform.io/builtin/conn3x"]`), addrs.NoKey)
		_, diags := chainContext(t, newChainProvider()).Plan(context.Background(), m, state, &PlanOpts{Mode: plans.NormalMode, Limit: limitOf("a")})
		if !slices.Contains(msgsOf(diags), "moved blocks need a plan without -limit") {
			t.Errorf("diagnostics %v: want -limit's own advice for moved blocks", msgsOf(diags))
		}
	})

	t.Run("with -target", func(t *testing.T) {
		m := chainModule(t, "", "")
		opts := &PlanOpts{Mode: plans.NormalMode, Limit: limitOf("a"), Targets: []addrs.Targetable{mustResourceInstanceAddr(`conn3x_command.web__one["b"]`)}}
		_, diags := chainContext(t, newChainProvider()).Plan(context.Background(), m, states.NewState(), opts)
		if !slices.Contains(msgsOf(diags), "-limit can't be used with -target or -exclude") {
			t.Errorf("diagnostics %v: want -limit and -target refused together", msgsOf(diags))
		}
	})

	t.Run("same options twice", func(t *testing.T) {
		m := chainModule(t, "", "")
		opts := &PlanOpts{Mode: plans.NormalMode, Limit: limitOf("a")}
		ctx := chainContext(t, newChainProvider())
		for range 2 {
			_, diags := ctx.Plan(context.Background(), m, states.NewState(), opts)
			assertNoErrors(t, diags)
			if slices.Contains(msgsOf(diags), "Resource targeting is in effect") {
				t.Errorf("a second plan with the same options warned as if -target were set")
			}
		}
	})
}
