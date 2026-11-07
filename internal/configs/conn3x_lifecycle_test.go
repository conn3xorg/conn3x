// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package configs

import (
	"strings"
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/zclconf/go-cty/cty"
)

func lifecycleCircuit(module, lifecycle string) string {
	return `resource "terraform_data" "trigger" {
  input = "1"
}

circuit "web" {
  hosts = { web1 = "203.0.113.10" }
  ssh {
    user = "root"
  }
  step "s" {
    ` + module + `
    lifecycle {
      ` + lifecycle + `
    }
  }
}`
}

const fileModule = `file {
      path    = "/etc/motd"
      content = "hi"
    }`

// Every allowed lifecycle argument reaches the lowered resource. This also
// guards the synthetic decodeResourceBlock call against an upstream sync
// that changes how lifecycle is decoded.
func TestStepLifecycleReachesTheResource(t *testing.T) {
	mod, diags := loadCircuitModule(t, map[string]string{"main.circuit.hcl": lifecycleCircuit(`authorized_key {
      user = "deploy"
      key  = "ssh-ed25519 AAAA"
    }`, `prevent_destroy       = true
      create_before_destroy = true
      ignore_changes        = [user]
      replace_triggered_by  = [terraform_data.trigger]
      precondition {
        condition     = each.key == "web1"
        error_message = "only web1"
      }
      postcondition {
        condition     = self.user == "deploy"
        error_message = "wrong user"
      }`)})
	if diags.HasErrors() {
		t.Fatal(diags.Error())
	}
	r := mod.ManagedResources["conn3x_authorized_key.web__s"]
	if r == nil {
		t.Fatalf("no step resource; have %v", keys(mod.ManagedResources))
	}
	m := r.Managed
	if !m.CreateBeforeDestroy || !m.CreateBeforeDestroySet {
		t.Error("create_before_destroy not copied")
	}
	if v, _ := m.PreventDestroy.Value(nil); !v.RawEquals(cty.True) {
		t.Errorf("prevent_destroy = %#v", v)
	}
	if len(m.IgnoreChanges) != 1 || traversalString(m.IgnoreChanges[0]) != "user" {
		t.Errorf("ignore_changes = %v", m.IgnoreChanges)
	}
	if len(r.TriggersReplacement) != 1 {
		t.Errorf("replace_triggered_by = %v", r.TriggersReplacement)
	}
	if len(r.Preconditions) != 1 || len(r.Postconditions) != 1 {
		t.Errorf("conditions: %d pre, %d post", len(r.Preconditions), len(r.Postconditions))
	}
	if r.ForEach == nil || r.Config == nil {
		t.Error("lifecycle replaced the step's lowering")
	}
}

func TestStepLifecycleIgnoreAll(t *testing.T) {
	mod, diags := loadCircuitModule(t, map[string]string{"main.circuit.hcl": lifecycleCircuit(fileModule, `ignore_changes = all`)})
	if diags.HasErrors() {
		t.Fatal(diags.Error())
	}
	if !mod.ManagedResources["conn3x_file.web__s"].Managed.IgnoreAllChanges {
		t.Fatal("ignore_changes = all not copied")
	}
}

func TestStepLifecycleErrors(t *testing.T) {
	for name, tc := range map[string]struct{ module, lifecycle, want string }{
		"enabled":     {fileModule, `enabled = false`, "empty for_each"},
		"destroy":     {fileModule, `destroy = false`, `on_remove = "forget"`},
		"unknown":     {fileModule, `retries = 3`, `"retries"`},
		"cbd on file": {fileModule, `create_before_destroy = true`, "isn't available on a file step"},
		"item outside a loop": {fileModule, `precondition {
        condition     = item.value != ""
        error_message = "x"
      }`, "item outside a looping step"},
	} {
		t.Run(name, func(t *testing.T) {
			_, diags := loadCircuitModule(t, map[string]string{"main.circuit.hcl": lifecycleCircuit(tc.module, tc.lifecycle)})
			if !diags.HasErrors() {
				t.Fatal("no error")
			}
			if !strings.Contains(diags.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", diags.Error(), tc.want)
			}
		})
	}
}

func TestStepLifecycleCBDFalseAllowedAnywhere(t *testing.T) {
	_, diags := loadCircuitModule(t, map[string]string{"main.circuit.hcl": lifecycleCircuit(fileModule, `create_before_destroy = false`)})
	if diags.HasErrors() {
		t.Fatal(diags.Error())
	}
}

func TestStepLifecycleDuplicate(t *testing.T) {
	src := strings.Replace(lifecycleCircuit(fileModule, `prevent_destroy = true`), "    lifecycle {", "    lifecycle {\n    }\n    lifecycle {", 1)
	_, diags := loadCircuitModule(t, map[string]string{"main.circuit.hcl": src})
	if !diags.HasErrors() || !strings.Contains(diags.Error(), "Duplicate lifecycle block") {
		t.Fatalf("want a duplicate lifecycle error, got %v", diags)
	}
}

func TestTemplateStepIgnoreChangesUsesStepNames(t *testing.T) {
	mod, diags := loadCircuitModule(t, map[string]string{
		"main.circuit.hcl": lifecycleCircuit(`template {
      source      = "motd.tftpl"
      destination = "/etc/motd"
    }`, `ignore_changes = [source, vars, destination, mode]`),
	})
	if diags.HasErrors() {
		t.Fatal(diags.Error())
	}
	var got []string
	for _, tr := range mod.ManagedResources["conn3x_file.web__s"].Managed.IgnoreChanges {
		got = append(got, traversalString(tr))
	}
	if strings.Join(got, ",") != "content,content,path,mode" {
		t.Fatalf("ignore_changes = %v", got)
	}
}

// In a looping step, each and item inside a condition mean the host and the
// item, as they do in the module block.
func TestLoopingStepConditionRefsRewritten(t *testing.T) {
	src := `circuit "web" {
  hosts = { web1 = "203.0.113.10" }
  ssh {
    user = "root"
  }
  step "s" {
    for_each = ["a"]
    file {
      path    = "/tmp/${item.key}"
      content = "x"
    }
    lifecycle {
      precondition {
        condition     = each.key == "web1" && item.value == "a"
        error_message = "on ${each.key}"
      }
    }
  }
}`
	mod, diags := loadCircuitModule(t, map[string]string{"main.circuit.hcl": src})
	if diags.HasErrors() {
		t.Fatal(diags.Error())
	}
	r := mod.ManagedResources["conn3x_file.web__s"]
	inst := cty.ObjectVal(map[string]cty.Value{
		"host_key": cty.StringVal("web1"), "host": cty.StringVal("203.0.113.10"),
		"item_key": cty.StringVal("a"), "item": cty.StringVal("a"),
	})
	ctx := &hcl.EvalContext{Variables: map[string]cty.Value{
		"each": cty.ObjectVal(map[string]cty.Value{"key": cty.StringVal("web1/a"), "value": inst}),
	}}
	cond := r.Preconditions[0]
	if v, d := cond.Condition.Value(ctx); d.HasErrors() || !v.RawEquals(cty.True) {
		t.Fatalf("condition = %#v (%v)", v, d)
	}
	if v, d := cond.ErrorMessage.Value(ctx); d.HasErrors() || v.AsString() != "on web1" {
		t.Fatalf("error_message = %#v (%v)", v, d)
	}
}

func TestLoopingStepReplaceTriggeredByRejectsEach(t *testing.T) {
	src := `resource "terraform_data" "t" {
  for_each = { web1 = 1 }
  input    = 1
}
circuit "web" {
  hosts = { web1 = "203.0.113.10" }
  ssh {
    user = "root"
  }
  step "s" {
    for_each = ["a"]
    file {
      path    = "/tmp/${item.key}"
      content = "x"
    }
    lifecycle {
      replace_triggered_by = [terraform_data.t[each.key]]
    }
  }
}`
	_, diags := loadCircuitModule(t, map[string]string{"main.circuit.hcl": src})
	if !diags.HasErrors() || !strings.Contains(diags.Error(), "replace_triggered_by of a looping step") {
		t.Fatalf("want a looping replace_triggered_by error, got %v", diags)
	}
}
