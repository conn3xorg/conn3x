// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package tofu

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/addrs"
	"github.com/opentofu/opentofu/internal/configs"
	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/dag"
	"github.com/opentofu/opentofu/internal/plugins"
	"github.com/opentofu/opentofu/internal/providers"
	"github.com/opentofu/opentofu/internal/states"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

// chainCircuit is a circuit on hosts a and b: a plain step, a looping step,
// a plain step after it and a handler. STRATEGY and EXTRA are replaced.
const chainCircuit = `
circuit "web" {
  hosts = { a = "10.0.0.1", b = "10.0.0.2" }
  STRATEGY
  ssh {
    user = "root"
  }
  step "one" {
    command {
      command = "one-${each.key}"
    }
  }
  step "items" {
    for_each = ["x", "y"]
    command {
      command = "items-${each.key}"
    }
  }
  step "two" {
    command {
      command = "two-${each.key}"
      EXTRA
    }
    notify = [handler.restart]
  }
  handler "restart" {
    service {
      name = "nginx"
    }
  }
}
`

func chainModule(t *testing.T, strategy, extra string) *configs.Config {
	t.Helper()
	src := strings.NewReplacer("STRATEGY", strategy, "EXTRA", extra).Replace(chainCircuit)
	return testModuleInline(t, map[string]string{"main.circuit.hcl": src})
}

// chainProvider is a mock conn3x provider. Its apply runs outside
// MockProvider's mutex, which serialises every call, and records when each
// command finished.
type chainProvider struct {
	*MockProvider
	slow string // command that takes 300 ms
	fail string // command that fails

	mu   sync.Mutex
	done map[string]time.Time
}

func newChainProvider() *chainProvider {
	ssh := &configschema.Block{Attributes: map[string]*configschema.Attribute{}}
	for _, name := range append(configs.Conn3xSSHSettings(), "host") {
		ssh.Attributes[name] = &configschema.Attribute{Type: cty.DynamicPseudoType, Optional: true}
	}
	block := func(attrs map[string]*configschema.Attribute) *configschema.Block {
		attrs["id"] = &configschema.Attribute{Type: cty.String, Computed: true}
		attrs["revision"] = &configschema.Attribute{Type: cty.String, Computed: true}
		return &configschema.Block{
			Attributes: attrs,
			BlockTypes: map[string]*configschema.NestedBlock{"ssh": {Block: *ssh, Nesting: configschema.NestingSingle}},
		}
	}
	p := &MockProvider{GetProviderSchemaResponse: getProviderSchemaResponseFromProviderSchema(&ProviderSchema{
		ResourceTypes: map[string]*configschema.Block{
			"conn3x_command": block(map[string]*configschema.Attribute{
				"command": {Type: cty.String, Optional: true},
				"creates": {Type: cty.String, Optional: true},
			}),
			"conn3x_eos_vlan": block(map[string]*configschema.Attribute{
				"vlan_id": {Type: cty.Number, Optional: true},
			}),
			"conn3x_eos_commit": block(map[string]*configschema.Attribute{
				"triggers": {Type: cty.DynamicPseudoType, Optional: true},
				"removals": {Type: cty.String, Optional: true},
			}),
			"conn3x_eos_removals": block(map[string]*configschema.Attribute{}),
			"conn3x_service_action": block(map[string]*configschema.Attribute{
				"name":     {Type: cty.String, Optional: true},
				"action":   {Type: cty.String, Optional: true},
				"serial":   {Type: cty.Bool, Optional: true},
				"triggers": {Type: cty.DynamicPseudoType, Optional: true},
			}),
		},
	})}
	p.PlanResourceChangeFn = testDiffFn
	p.ApplyResourceChangeFn = testApplyFn
	return &chainProvider{MockProvider: p, done: map[string]time.Time{}}
}

func (p *chainProvider) ApplyResourceChange(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	id := req.TypeName
	if req.TypeName == "conn3x_command" {
		id = req.PlannedState.GetAttr("command").AsString()
	}
	if id == p.slow {
		time.Sleep(300 * time.Millisecond)
	}
	var resp providers.ApplyResourceChangeResponse
	if id == p.fail {
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("%s failed", id))
	} else {
		resp = p.MockProvider.ApplyResourceChange(ctx, req)
	}
	p.mu.Lock()
	p.done[id] = time.Now()
	p.mu.Unlock()
	return resp
}

func chainContext(t *testing.T, p *chainProvider) *Context {
	return testContext2(t, &ContextOpts{Plugins: plugins.NewLibrary(map[addrs.Provider]providers.Factory{
		addrs.NewBuiltInProvider("conn3x"): func() (providers.Interface, error) { return p, nil },
	}, nil)})
}

// chainDeps maps each apply-graph vertex to everything it waits for.
func chainDeps(t *testing.T, m *configs.Config) map[string]map[string]bool {
	t.Helper()
	ctx := chainContext(t, newChainProvider())
	plan, diags := ctx.Plan(context.Background(), m, states.NewState(), DefaultPlanOpts)
	assertNoErrors(t, diags)
	g, _, diags := ctx.applyGraph(context.Background(), plan, m, ProviderFunctionMapping{}, nil)
	assertNoErrors(t, diags)
	out := map[string]map[string]bool{}
	for _, v := range g.Vertices() {
		anc, err := g.Ancestors(v)
		if err != nil {
			t.Fatal(err)
		}
		deps := map[string]bool{}
		for _, a := range anc {
			deps[dag.VertexName(a)] = true
		}
		out[dag.VertexName(v)] = deps
	}
	return out
}

func TestConn3xChainPerHostGraph(t *testing.T) {
	deps := chainDeps(t, chainModule(t, `strategy = "per_host"`, ""))
	for node, want := range map[string]map[string]bool{
		`conn3x_command.web__items["a/x"]`: {`conn3x_command.web__one["a"]`: true, `conn3x_command.web__one["b"]`: false},
		`conn3x_command.web__two["a"]`: {
			`conn3x_command.web__items["a/x"]`: true, `conn3x_command.web__items["a/y"]`: true,
			`conn3x_command.web__items["b/x"]`: false, `conn3x_command.web__one["b"]`: false,
		},
		`conn3x_command.web__two (expand)`:        {`conn3x_command.web__items (expand)`: true, `conn3x_command.web__items["a/x"]`: false},
		`conn3x_service_action.web__restart["a"]`: {`conn3x_command.web__two["a"]`: true, `conn3x_command.web__two["b"]`: false},
	} {
		checkChainDeps(t, deps, node, want)
	}
}

func TestConn3xChainLockstepGraph(t *testing.T) {
	for name, strategy := range map[string]string{"default": "", "lockstep": `strategy = "lockstep"`} {
		t.Run(name, func(t *testing.T) {
			deps := chainDeps(t, chainModule(t, strategy, ""))
			checkChainDeps(t, deps, `conn3x_command.web__two["a"]`, map[string]bool{`conn3x_command.web__items["b/y"]`: true, `conn3x_command.web__one["b"]`: true})
			checkChainDeps(t, deps, `conn3x_service_action.web__restart["a"]`, map[string]bool{`conn3x_command.web__two["b"]`: true})
		})
	}
}

// A looping step with no items has no instance on a host to carry the
// wait, so the step after it still waits for the one before it, and so
// does a handler after an empty last step. Seen on Azure: circuit-iis's
// app_pool started with IIS's install when url_rewrite was off.
func TestConn3xChainPerHostEmptyLoop(t *testing.T) {
	src := strings.NewReplacer("STRATEGY", `strategy = "per_host"`, "EXTRA", "", `for_each = ["x", "y"]`, "for_each = []",
		"    notify = [handler.restart]\n  }", "    notify = [handler.restart]\n  }\n  step \"tail\" {\n    for_each = []\n    command {\n      command = \"tail\"\n    }\n  }").Replace(chainCircuit)
	deps := chainDeps(t, testModuleInline(t, map[string]string{"main.circuit.hcl": src}))
	checkChainDeps(t, deps, `conn3x_command.web__two["a"]`, map[string]bool{`conn3x_command.web__one["a"]`: true, `conn3x_command.web__one["b"]`: false})
	checkChainDeps(t, deps, `conn3x_service_action.web__restart["a"]`, map[string]bool{`conn3x_command.web__two["a"]`: true, `conn3x_command.web__two["b"]`: false})
}

// A switch's EOS commit waits for that switch's eos steps only per host,
// and for every switch's in lockstep. The steps wait for the switch's
// conn3x_eos_removals the same way, so a destroy reaches it last.
func TestConn3xChainEOSCommit(t *testing.T) {
	src := `
circuit "sw" {
  hosts = { a = "10.0.0.1", b = "10.0.0.2" }
  STRATEGY
  ssh {
    user = "admin"
  }
  step "one" {
    eos_vlan {
      vlan_id = 10
    }
  }
  step "many" {
    for_each = { x = 20, y = 30 }
    eos_vlan {
      vlan_id = item.value
    }
  }
}
`
	for strategy, other := range map[string]bool{`strategy = "per_host"`: false, "": true} {
		deps := chainDeps(t, testModuleInline(t, map[string]string{"main.circuit.hcl": strings.Replace(src, "STRATEGY", strategy, 1)}))
		checkChainDeps(t, deps, `conn3x_eos_commit.sw__commit["a"]`, map[string]bool{
			`conn3x_eos_vlan.sw__one["a"]`: true, `conn3x_eos_vlan.sw__many["a/x"]`: true, `conn3x_eos_vlan.sw__many["a/y"]`: true,
			`conn3x_eos_vlan.sw__one["b"]`: other, `conn3x_eos_vlan.sw__many["b/x"]`: other,
			`conn3x_eos_removals.sw__removals["a"]`: true,
		})
		for _, step := range []string{`conn3x_eos_vlan.sw__one["a"]`, `conn3x_eos_vlan.sw__many["a/x"]`} {
			checkChainDeps(t, deps, step, map[string]bool{
				`conn3x_eos_removals.sw__removals["a"]`: true, `conn3x_eos_removals.sw__removals["b"]`: other,
			})
		}
	}
}

// A step that reads another host's value still waits for that host.
func TestConn3xChainPerHostKeepsUserReferences(t *testing.T) {
	deps := chainDeps(t, chainModule(t, `strategy = "per_host"`, `creates = conn3x_command.web__one["b"].revision`))
	checkChainDeps(t, deps, `conn3x_command.web__two["a"]`, map[string]bool{`conn3x_command.web__one["b"]`: true, `conn3x_command.web__items["b/x"]`: false})
}

func checkChainDeps(t *testing.T, deps map[string]map[string]bool, node string, want map[string]bool) {
	t.Helper()
	got, ok := deps[node]
	if !ok {
		t.Fatalf("no %s in the apply graph", node)
	}
	for dep, wait := range want {
		if got[dep] != wait {
			t.Errorf("%s waits for %s = %v, want %v", node, dep, got[dep], wait)
		}
	}
}

func applyChain(t *testing.T, strategy string, p *chainProvider) (*states.State, tfdiags.Diagnostics) {
	t.Helper()
	m := chainModule(t, strategy, "")
	ctx := chainContext(t, p)
	plan, diags := ctx.Plan(context.Background(), m, states.NewState(), DefaultPlanOpts)
	assertNoErrors(t, diags)
	return ctx.Apply(context.Background(), plan, m, nil)
}

func TestConn3xChainPerHostTiming(t *testing.T) {
	for strategy, ahead := range map[string]bool{`strategy = "per_host"`: true, "": false} {
		p := newChainProvider()
		p.slow = "one-b"
		_, diags := applyChain(t, strategy, p)
		assertNoErrors(t, diags)
		lead := p.done["one-b"].Sub(p.done["two-a"])
		t.Logf("%q: a finished two %v before b finished one", strategy, lead.Round(time.Millisecond))
		if (lead > 0) != ahead {
			t.Errorf("%q: a finished two %v before b finished one, want ahead = %v", strategy, lead, ahead)
		}
	}
}

// A host that fails stops only its own chain; the run still fails.
func TestConn3xChainPerHostFailure(t *testing.T) {
	p := newChainProvider()
	p.fail = "one-b"
	state, diags := applyChain(t, `strategy = "per_host"`, p)
	if !diags.HasErrors() {
		t.Fatal("apply succeeded with a failed step")
	}
	has := func(addr string) bool {
		return state.ResourceInstance(mustResourceInstanceAddr(addr)) != nil
	}
	for addr, want := range map[string]bool{
		`conn3x_command.web__two["a"]`:            true,
		`conn3x_service_action.web__restart["a"]`: true,
		`conn3x_command.web__items["b/x"]`:        false,
		`conn3x_command.web__two["b"]`:            false,
	} {
		if has(addr) != want {
			t.Errorf("%s in state = %v, want %v", addr, has(addr), want)
		}
	}
}
