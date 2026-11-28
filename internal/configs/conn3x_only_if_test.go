// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package configs

import (
	"slices"
	"strings"
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"

	"github.com/opentofu/opentofu/internal/addrs"
)

const probeCircuit = `
circuit "web" {
  hosts = { web1 = "203.0.113.10", web2 = "203.0.113.11" }
  ssh {
    user = "root"
  }

  probe "first" {
    command = "true"
  }

  step "conf" {
    file {
      path    = "/etc/app.conf"
      content = "x\n"
    }
  }

  step "tools" {
    for_each = ["a", "b"]
    package {
      name = item.value
    }
  }

  probe "conf_there" {
    command = "test -f /etc/app.conf"
  }

  step "init" {
    only_if = data.conn3x_command.web__conf_there[each.key].exit_code == 0
    command {
      command = "touch /etc/app.init"
    }
  }

  step "per_item" {
    for_each = ["x"]
    only_if  = data.conn3x_command.web__conf_there[each.key].exit_code != 0 && item.value == "x"
    file {
      path    = "/etc/${item.value}"
      content = "y\n"
    }
  }
}
`

func dependsOn(r *Resource) []string {
	var out []string
	for _, d := range r.DependsOn {
		out = append(out, d.RootName()+"."+d[1].(hcl.TraverseAttr).Name)
	}
	return out
}

func TestProbeWaitsForEveryEarlierStep(t *testing.T) {
	mod, diags := loadCircuitModule(t, map[string]string{"main.tf": probeCircuit})
	if diags.HasErrors() {
		t.Fatal(diags.Error())
	}
	first := mod.DataResources["data.conn3x_command.web__first"]
	later := mod.DataResources["data.conn3x_command.web__conf_there"]
	if first == nil || later == nil {
		t.Fatalf("probes lowered to %v", mod.DataResources)
	}
	// No step before it: it reads at plan.
	if len(first.DependsOn) != 0 {
		t.Errorf("the first probe depends on %v", dependsOn(first))
	}
	// Every step before it, not only the last: depends_on isn't transitive.
	if got, want := dependsOn(later), []string{"conn3x_file.web__conf", "conn3x_package.web__tools"}; !slices.Equal(got, want) {
		t.Errorf("the second probe depends on %v, want %v", got, want)
	}
	if got := later.ForEach; got == nil {
		t.Error("the probe isn't repeated over the hosts")
	}
	attrs, _ := later.Config.JustAttributes()
	if _, ok := attrs["command"]; !ok {
		t.Errorf("probe config has %v", attrs)
	}
	if !Conn3xCircuitResource(later) {
		t.Error("a probe isn't a circuit resource, so per_host can't keep its edges to its host")
	}
	// The steps after it don't wait for it unless they read it.
	init := mod.ManagedResources["conn3x_command.web__init"]
	if slices.Contains(dependsOn(init), "conn3x_command.web__conf_there") {
		t.Error("a step waits for the probe through depends_on")
	}
}

func TestProbePerHostEdges(t *testing.T) {
	src := strings.Replace(probeCircuit, `hosts = {`, `strategy = "per_host"
  hosts = {`, 1)
	mod, diags := loadCircuitModule(t, map[string]string{"main.tf": src})
	if diags.HasErrors() {
		t.Fatal(diags.Error())
	}
	p := mod.DataResources["data.conn3x_command.web__conf_there"]
	for _, d := range p.DependsOn {
		if !Conn3xHostEdge(p, d.SourceRange()) {
			t.Errorf("per host, the probe's wait for %s isn't kept to its host", d.RootName())
		}
	}
}

func TestOnlyIfGoesToTheResource(t *testing.T) {
	mod, diags := loadCircuitModule(t, map[string]string{"main.tf": probeCircuit})
	if diags.HasErrors() {
		t.Fatal(diags.Error())
	}
	for _, name := range []string{"conn3x_command.web__init", "conn3x_file.web__per_item"} {
		r := mod.ManagedResources[name]
		attrs, _ := r.Config.JustAttributes()
		cond, ok := attrs["only_if"]
		if !ok {
			t.Fatalf("%s has no only_if", name)
		}
		// In a looping step, each and item are rewritten as in the module's arguments.
		for _, v := range cond.Expr.Variables() {
			if v.RootName() == "item" {
				t.Errorf("%s: only_if still reads item", name)
			}
		}
		// It decides nothing at plan: the step keeps every host.
		if _, filtered := r.ForEach.(*whenFilter); filtered {
			t.Errorf("%s: only_if filters for_each", name)
		}
	}
}

func TestOnlyIfErrors(t *testing.T) {
	for name, c := range map[string]struct{ step, want string }{
		"inside the module": {`step "a" {
    file {
      path    = "/etc/a"
      content = "a"
      only_if = true
    }
  }`, "only_if belongs on the step"},
		"network device": {`step "a" {
    only_if = true
    eos_vlan {
      vlan_id = 10
      name    = "a"
    }
  }`, "only_if on a network device step"},
		"duplicate probe": {`probe "a" {
    command = "true"
  }
  probe "a" {
    command = "true"
  }`, "Duplicate probe"},
		"probe with more than command": {`probe "a" {
    command = "true"
    when    = true
  }`, "A probe takes only command"},
	} {
		t.Run(name, func(t *testing.T) {
			src := "circuit \"web\" {\n  hosts = { web1 = \"203.0.113.10\" }\n  ssh {\n    user = \"root\"\n  }\n  " + c.step + "\n}\n"
			_, diags := loadCircuitModule(t, map[string]string{"main.tf": src})
			if !diags.HasErrors() || !strings.Contains(diags.Error(), c.want) {
				t.Fatalf("diags = %v, want %q", diags, c.want)
			}
		})
	}
}

// The probe lowers through the same decode as everything else in a
// circuit, so a file can hold both kinds and the parser sorts them.
func TestProbeIsADataResource(t *testing.T) {
	file, diags := hclsyntax.ParseConfig([]byte(probeCircuit), "main.circuit.hcl", hcl.InitialPos)
	if diags.HasErrors() {
		t.Fatal(diags.Error())
	}
	content, _ := file.Body.Content(&hcl.BodySchema{Blocks: []hcl.BlockHeaderSchema{{Type: "circuit", LabelNames: []string{"name"}}}})
	rs, _, d := decodeCircuitBlock(content.Blocks[0], map[string]hcl.Range{})
	if d.HasErrors() {
		t.Fatal(d.Error())
	}
	var probes []string
	for _, r := range rs {
		if r.Mode == addrs.DataResourceMode {
			probes = append(probes, r.Type+"."+r.Name)
		}
	}
	if want := []string{"conn3x_command.web__first", "conn3x_command.web__conf_there"}; !slices.Equal(probes, want) {
		t.Fatalf("probes = %v, want %v", probes, want)
	}
}
