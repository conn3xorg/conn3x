// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package configs

import (
	"sort"
	"strings"
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/zclconf/go-cty/cty"
)

func whenCircuit(step string) string {
	return `circuit "web" {
  hosts = {
    web1 = { address = "203.0.113.10", os = "debian" }
    web2 = { address = "203.0.113.11", os = "redhat" }
  }
  ssh {
    user = "root"
  }
  ` + step + `
  handler "restart" {
    service {
      name = "nginx"
    }
  }
}`
}

func instanceKeys(t *testing.T, e hcl.Expression, ctx *hcl.EvalContext) ([]string, hcl.Diagnostics) {
	t.Helper()
	v, diags := e.Value(ctx)
	if diags.HasErrors() || !v.IsKnown() {
		return nil, diags
	}
	var keys []string
	for it := v.ElementIterator(); it.Next(); {
		k, _ := it.Element()
		keys = append(keys, k.AsString())
	}
	sort.Strings(keys)
	return keys, diags
}

func TestStepWhenPicksHosts(t *testing.T) {
	mod, diags := loadCircuitModule(t, map[string]string{"main.circuit.hcl": whenCircuit(`step "apt" {
    when = each.value.os == "debian"
    command {
      command = "apt-get update"
    }
  }`)})
	if diags.HasErrors() {
		t.Fatal(diags.Error())
	}
	keys, d := instanceKeys(t, mod.ManagedResources["conn3x_command.web__apt"].ForEach, nil)
	if d.HasErrors() || strings.Join(keys, ",") != "web1" {
		t.Fatalf("instances = %v, %v; want web1", keys, d)
	}
}

// In a looping step, each and item in when mean what they do in the
// module's arguments.
func TestStepWhenInALoopingStep(t *testing.T) {
	mod, diags := loadCircuitModule(t, map[string]string{"main.circuit.hcl": whenCircuit(`step "tools" {
    for_each = ["git", "jq"]
    when     = each.key == "web2" && item.key == "jq"
    package {
      name = item.value
    }
  }`)})
	if diags.HasErrors() {
		t.Fatal(diags.Error())
	}
	keys, d := instanceKeys(t, mod.ManagedResources["conn3x_package.web__tools"].ForEach, nil)
	if d.HasErrors() || strings.Join(keys, ",") != "web2/jq" {
		t.Fatalf("instances = %v, %v; want web2/jq", keys, d)
	}
}

func TestStepWhenErrors(t *testing.T) {
	for want, tc := range map[string]struct {
		when string
		ctx  *hcl.EvalContext
	}{
		"when must be true or false": {when: `"maybe"`},
		"when isn't known yet": {when: `var.debian`, ctx: &hcl.EvalContext{Variables: map[string]cty.Value{
			"var": cty.ObjectVal(map[string]cty.Value{"debian": cty.UnknownVal(cty.Bool)}),
		}}},
		"item.key and item.value only exist": {when: `item.key == "a"`},
	} {
		mod, diags := loadCircuitModule(t, map[string]string{"main.circuit.hcl": whenCircuit(`step "s" {
    when = ` + tc.when + `
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
		_, d := instanceKeys(t, mod.ManagedResources["conn3x_command.web__s"].ForEach, tc.ctx)
		if !d.HasErrors() || !strings.Contains(d.Error(), want) {
			t.Errorf("%s: diags = %v", want, d)
		}
	}
}

// each and item are set per host, so they aren't references OpenTofu
// should resolve for the for_each; anything else when reads is.
func TestStepWhenVariables(t *testing.T) {
	mod, diags := loadCircuitModule(t, map[string]string{"main.circuit.hcl": `variable "families" {
  type = map(string)
}
` + whenCircuit(`step "s" {
    when = var.families[each.key] == "debian"
    command {
      command = "true"
    }
  }`)})
	if diags.HasErrors() {
		t.Fatal(diags.Error())
	}
	var roots []string
	for _, tr := range mod.ManagedResources["conn3x_command.web__s"].ForEach.Variables() {
		roots = append(roots, tr.RootName())
	}
	if got := strings.Join(roots, ","); strings.Contains(got, "each") || !strings.Contains(got, "var") {
		t.Fatalf("roots = %s", got)
	}
}

func TestStepWhenImportOnASkippedHost(t *testing.T) {
	mod, diags := loadCircuitModule(t, map[string]string{"main.circuit.hcl": whenCircuit(`step "apt" {
    when   = each.value.os == "debian"
    import = ["web2"]
    file {
      path    = "/etc/apt/apt.conf.d/99local"
      content = "x"
    }
  }`)})
	if diags.HasErrors() {
		t.Fatal(diags.Error())
	}
	_, d := instanceKeys(t, mod.Import[0].ForEach, nil)
	if !d.HasErrors() || !strings.Contains(d.Error(), `import names "web2", but the step's when is false there`) {
		t.Fatalf("diags = %v", d)
	}
}

// A handler notified by a step with when watches it through a filter, so a
// host the step skipped doesn't index a missing instance.
func TestStepWhenHandlerTrigger(t *testing.T) {
	mod, diags := loadCircuitModule(t, map[string]string{"main.circuit.hcl": whenCircuit(`step "conf" {
    when   = each.value.os == "debian"
    notify = [handler.restart]
    file {
      path    = "/etc/nginx/nginx.conf"
      content = "x"
    }
  }`)})
	if diags.HasErrors() {
		t.Fatal(diags.Error())
	}
	h := mod.ManagedResources["conn3x_service_action.web__restart"]
	attrs, _ := h.Config.JustAttributes()
	steps := cty.ObjectVal(map[string]cty.Value{"web1": cty.ObjectVal(map[string]cty.Value{"revision": cty.StringVal("r1")})})
	for host, want := range map[string]int{"web1": 1, "web2": 0} {
		ctx := &hcl.EvalContext{Variables: map[string]cty.Value{
			"conn3x_file": cty.ObjectVal(map[string]cty.Value{"web__conf": steps}),
			"each":        cty.ObjectVal(map[string]cty.Value{"key": cty.StringVal(host)}),
		}}
		v, d := attrs["triggers"].Expr.Value(ctx)
		if d.HasErrors() {
			t.Fatalf("%s: %s", host, d.Error())
		}
		if n := v.Index(cty.NumberIntVal(0)).LengthInt(); n != want {
			t.Errorf("%s: trigger has %d entries, want %d", host, n, want)
		}
	}
}

// A provider function in hosts, for_each or when must still be found by
// OpenTofu, which reads the functions an expression calls to know which
// providers it needs.
func TestStepForEachPassesFunctionsOn(t *testing.T) {
	mod, diags := loadCircuitModule(t, map[string]string{"main.circuit.hcl": `circuit "app" {
  hosts = provider::conn3x::inventory("inv.ini", "web")
  ssh {
    user = "root"
  }
  step "first" {
    command {
      command = "true"
    }
  }
  step "s" {
    for_each = provider::a::items()
    when     = provider::b::ok(each.key)
    command {
      command = "true"
    }
  }
}`})
	if diags.HasErrors() {
		t.Fatal(diags.Error())
	}
	for addr, want := range map[string][]string{
		"conn3x_command.app__first": {"provider::conn3x::inventory"},
		"conn3x_command.app__s":     {"provider::conn3x::inventory", "provider::a::items", "provider::b::ok"},
	} {
		f, ok := mod.ManagedResources[addr].ForEach.(hcl.ExpressionWithFunctions)
		if !ok {
			t.Fatalf("%s: for_each doesn't list its functions", addr)
		}
		var got []string
		for _, tr := range f.Functions() {
			var parts []string
			for _, step := range tr {
				switch s := step.(type) {
				case hcl.TraverseRoot:
					parts = append(parts, s.Name)
				case hcl.TraverseAttr:
					parts = append(parts, s.Name)
				}
			}
			got = append(got, strings.Join(parts, "::"))
		}
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%s: functions = %v, want %v", addr, got, want)
		}
	}
}
