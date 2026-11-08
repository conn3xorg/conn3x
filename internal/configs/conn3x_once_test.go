// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package configs

import (
	"strings"
	"testing"

	"github.com/hashicorp/hcl/v2"
)

func onceCircuit(strategy, steps string) string {
	return `circuit "app" {
  hosts = { web2 = "203.0.113.12", db1 = "203.0.113.20", web1 = "203.0.113.11" }
` + strategy + `
  ssh {
    user = "root"
  }
  ` + steps + `
}`
}

func TestStepRunOncePicksAHost(t *testing.T) {
	for want, extra := range map[string]string{
		"db1":  "",            // the first host key in sort order
		"web2": `on = "web2"`, // the one named
	} {
		mod, diags := loadCircuitModule(t, map[string]string{"main.circuit.hcl": onceCircuit("", `step "migrate" {
    run_once = true
    `+extra+`
    command {
      command = "true"
    }
  }`)})
		if diags.HasErrors() {
			t.Fatal(diags.Error())
		}
		keys, d := instanceKeys(t, mod.ManagedResources["conn3x_command.app__migrate"].ForEach, nil)
		if d.HasErrors() || strings.Join(keys, ",") != want {
			t.Errorf("%q: instances = %v, %v; want %s", extra, keys, d, want)
		}
	}
}

func TestStepRunOnceInALoopingStep(t *testing.T) {
	mod, diags := loadCircuitModule(t, map[string]string{"main.circuit.hcl": onceCircuit("", `step "seed" {
    for_each = ["users", "orders"]
    run_once = true
    on       = "db1"
    command {
      command = "seed ${item.value}"
    }
  }`)})
	if diags.HasErrors() {
		t.Fatal(diags.Error())
	}
	keys, d := instanceKeys(t, mod.ManagedResources["conn3x_command.app__seed"].ForEach, nil)
	if d.HasErrors() || strings.Join(keys, ",") != "db1/orders,db1/users" {
		t.Fatalf("instances = %v, %v", keys, d)
	}
}

func TestStepRunOnceErrors(t *testing.T) {
	for want, step := range map[string]string{
		"run_once with when":         `run_once = true` + "\n    " + `when = true`,
		"on without run_once":        `on = "db1"`,
		"Invalid run_once in step":   `run_once = "yes"`,
		"isn't one of the circuit's": `run_once = true` + "\n    " + `on = "db9"`,
	} {
		mod, diags := loadCircuitModule(t, map[string]string{"main.circuit.hcl": onceCircuit("", `step "s" {
    `+step+`
    command {
      command = "true"
    }
  }`)})
		if diags.HasErrors() {
			if !strings.Contains(diags.Error(), want) {
				t.Errorf("%s: load: %s", want, diags.Error())
			}
			continue
		}
		_, d := instanceKeys(t, mod.ManagedResources["conn3x_command.app__s"].ForEach, nil)
		if !d.HasErrors() || !strings.Contains(d.Error(), want) {
			t.Errorf("%s: diags = %v", want, d)
		}
	}
}

func TestStepRunOnceImportOnAnotherHost(t *testing.T) {
	mod, diags := loadCircuitModule(t, map[string]string{"main.circuit.hcl": onceCircuit("", `step "conf" {
    run_once = true
    on       = "db1"
    import   = ["web1"]
    file {
      path    = "/etc/app.conf"
      content = "x"
    }
  }`)})
	if diags.HasErrors() {
		t.Fatal(diags.Error())
	}
	_, d := instanceKeys(t, mod.Import[0].ForEach, nil)
	if !d.HasErrors() || !strings.Contains(d.Error(), `import names "web1", but the step has run_once and runs on another host`) {
		t.Fatalf("diags = %v", d)
	}
}

// Under per_host a run_once step is a sync point: it waits for the step
// before it on every host, and the step after it waits for all of it rather
// than for its own host's instance, which only one host has.
func TestStepRunOnceWaitsOnEveryHost(t *testing.T) {
	mod, diags := loadCircuitModule(t, map[string]string{"main.circuit.hcl": onceCircuit(`  strategy = "per_host"`, `step "code" {
    command {
      command = "deploy"
    }
  }
  step "migrate" {
    run_once = true
    command {
      command = "migrate"
    }
  }
  step "restart" {
    notify = [handler.reload]
    command {
      command = "true"
    }
  }
  step "after" {
    command {
      command = "true"
    }
  }
  handler "reload" {
    service {
      name = "app"
    }
  }`)})
	if diags.HasErrors() {
		t.Fatal(diags.Error())
	}
	for addr, wantWhole := range map[string]map[string]bool{
		"conn3x_command.app__migrate": {"app__code": true},
		"conn3x_command.app__restart": {"app__migrate": true},
		"conn3x_command.app__after":   {"app__restart": false}, // and so, through restart, on migrate
	} {
		r := mod.ManagedResources[addr]
		got := map[string]bool{}
		for _, dep := range r.DependsOn {
			got[dep[1].(hcl.TraverseAttr).Name] = !Conn3xHostEdge(r, dep.SourceRange())
		}
		for n, whole := range wantWhole {
			if g, ok := got[n]; !ok || g != whole {
				t.Errorf("%s -> %s: whole-resource edge = %v (present %v), want %v", addr, n, g, ok, whole)
			}
		}
	}
}
