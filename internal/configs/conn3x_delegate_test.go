// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package configs

import (
	"strings"
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/ext/tryfunc"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/function"
)

// on without run_once keeps a step per host, but reaches the host on names:
// its address and its overrides, not the instance's own.
func TestStepOnDelegates(t *testing.T) {
	mod, diags := loadCircuitModule(t, map[string]string{"main.circuit.hcl": `circuit "app" {
  hosts = { web1 = "203.0.113.11", lb = { address = "203.0.113.5", user = "admin" } }
  ssh {
    user = "root"
  }
  step "drain" {
    on = "lb"
    command {
      command = "drain ${each.key}"
    }
  }
}`})
	if diags.HasErrors() {
		t.Fatal(diags.Error())
	}
	r := mod.ManagedResources["conn3x_command.app__drain"]
	keys, d := instanceKeys(t, r.ForEach, nil)
	if d.HasErrors() || strings.Join(keys, ",") != "lb,web1" {
		t.Fatalf("instances = %v, %v; want one per host", keys, d)
	}
	ctx := &hcl.EvalContext{
		Variables: map[string]cty.Value{"each": cty.ObjectVal(map[string]cty.Value{"key": cty.StringVal("web1"), "value": cty.StringVal("203.0.113.11")})},
		Functions: map[string]function.Function{"try": tryfunc.TryFunc},
	}
	attrs, _ := r.Config.JustAttributes()
	if got, d := attrs["command"].Expr.Value(ctx); d.HasErrors() || got.AsString() != "drain web1" {
		t.Errorf("command = %#v (%v): each still means the host the step is for", got, d)
	}
	ssh, _, _ := r.Config.PartialContent(&hcl.BodySchema{Blocks: []hcl.BlockHeaderSchema{{Type: "ssh"}}})
	sshAttrs, _ := ssh.Blocks[0].Body.JustAttributes()
	for name, want := range map[string]string{"host": "203.0.113.5", "user": "admin"} {
		if got, d := sshAttrs[name].Expr.Value(ctx); d.HasErrors() || got.AsString() != want {
			t.Errorf("ssh %s = %#v (%v), want %s", name, got, d, want)
		}
	}
}

func TestStepOnErrors(t *testing.T) {
	for want, src := range map[string]string{
		"on with each in ssh": `circuit "app" {
  hosts = { web1 = "203.0.113.11", lb = "203.0.113.5" }
  ssh {
    user = each.key
  }
  step "drain" {
    on = "lb"
    command {
      command = "true"
    }
  }
}`,
	} {
		if _, diags := loadCircuitModule(t, map[string]string{"main.circuit.hcl": src}); !strings.Contains(diags.Error(), want) {
			t.Errorf("%s: diags = %s", want, diags.Error())
		}
	}
}

// on = "controller" runs a command step on the machine Conn3x runs on, with
// none of the circuit's ssh settings, become included.
func TestStepOnController(t *testing.T) {
	mod, diags := loadCircuitModule(t, map[string]string{"main.circuit.hcl": `circuit "app" {
  hosts = { web1 = "203.0.113.11" }
  ssh {
    user   = "root"
    become = true
  }
  step "notify" {
    on = "controller"
    command {
      command = "echo ${each.key} >> deployed.txt"
    }
  }
}`})
	if diags.HasErrors() {
		t.Fatal(diags.Error())
	}
	r := mod.ManagedResources["conn3x_command.app__notify"]
	ssh, _, _ := r.Config.PartialContent(&hcl.BodySchema{Blocks: []hcl.BlockHeaderSchema{{Type: "ssh"}}})
	attrs, _ := ssh.Blocks[0].Body.JustAttributes()
	if len(attrs) != 2 {
		t.Errorf("ssh has %d attributes, want host and controller only", len(attrs))
	}
	if v, _ := attrs["controller"].Expr.Value(nil); !v.True() {
		t.Errorf("controller = %#v", v)
	}

	_, diags = loadCircuitModule(t, map[string]string{"main.circuit.hcl": `circuit "app" {
  hosts = { web1 = "203.0.113.11" }
  ssh {
    user = "root"
  }
  step "f" {
    on = "controller"
    file {
      path    = "/tmp/x"
      content = "x"
    }
  }
}`})
	if !strings.Contains(diags.Error(), "Only command steps run on the controller") {
		t.Errorf("a file step on the controller: %v", diags)
	}

	_, diags = loadCircuitModule(t, map[string]string{"main.circuit.hcl": `circuit "app" {
  hosts = { web1 = "203.0.113.11" }
  ssh {
    user       = "root"
    controller = true
  }
}`})
	if !strings.Contains(diags.Error(), "Unexpected controller in a circuit's ssh block") {
		t.Errorf("controller in the circuit's ssh block: %v", diags)
	}
}
