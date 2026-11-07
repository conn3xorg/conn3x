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
	"github.com/zclconf/go-cty/cty/function/stdlib"
)

func importCircuit(step string) string {
	return `circuit "web" {
  hosts = { web1 = "203.0.113.10", web2 = { address = "203.0.113.11", port = 2222 } }
  ssh {
    user = "root"
  }
  ` + step + `
}`
}

var importFuncs = map[string]function.Function{"jsonencode": stdlib.JSONEncodeFunc, "try": tryfunc.TryFunc}

// importID evaluates an import's ID for one instance, as OpenTofu would.
func importIDFor(t *testing.T, imp *Import, key string, value cty.Value) string {
	t.Helper()
	ctx := &hcl.EvalContext{
		Variables: map[string]cty.Value{"each": cty.ObjectVal(map[string]cty.Value{"key": cty.StringVal(key), "value": value})},
		Functions: importFuncs,
	}
	v, diags := imp.ID.Value(ctx)
	if diags.HasErrors() {
		t.Fatal(diags.Error())
	}
	return v.AsString()
}

func TestStepImportLowersToAnImportBlock(t *testing.T) {
	mod, diags := loadCircuitModule(t, map[string]string{"main.circuit.hcl": importCircuit(`step "motd" {
    import = true
    file {
      path    = "/etc/motd"
      content = "hi"
      owner   = "root"
    }
  }`)})
	if diags.HasErrors() {
		t.Fatal(diags.Error())
	}
	if len(mod.Import) != 1 {
		t.Fatalf("got %d imports", len(mod.Import))
	}
	imp := mod.Import[0]
	if got := imp.StaticTo.String(); got != "conn3x_file.web__motd" {
		t.Fatalf("StaticTo = %s", got)
	}
	if got := imp.Provider.String(); got != "terraform.io/builtin/conn3x" {
		t.Fatalf("provider = %s", got)
	}
	if imp.ForEach != mod.ManagedResources["conn3x_file.web__motd"].ForEach {
		t.Fatal("import = true should repeat over the step's own for_each")
	}
	got := importIDFor(t, imp, "web2", cty.ObjectVal(map[string]cty.Value{"address": cty.StringVal("203.0.113.11"), "port": cty.NumberIntVal(2222)}))
	want := `{"args":{"owner":"root","path":"/etc/motd"},"key":"web2","ssh":{"host":"203.0.113.11","port":2222,"user":"root"},"v":1}`
	if got != want {
		t.Fatalf("ID =\n%s\nwant\n%s", got, want)
	}
}

func TestStepImportFalseImportsNothing(t *testing.T) {
	mod, diags := loadCircuitModule(t, map[string]string{"main.circuit.hcl": importCircuit(`step "nginx" {
    import = false
    package {
      name = "nginx"
    }
  }`)})
	if diags.HasErrors() {
		t.Fatal(diags.Error())
	}
	if len(mod.Import) != 0 {
		t.Fatalf("got %d imports", len(mod.Import))
	}
}

func TestStepImportListPicksHosts(t *testing.T) {
	mod, diags := loadCircuitModule(t, map[string]string{"main.circuit.hcl": importCircuit(`step "nginx" {
    import = ["web2"]
    package {
      name = "nginx"
    }
  }`)})
	if diags.HasErrors() {
		t.Fatal(diags.Error())
	}
	v, diags := mod.Import[0].ForEach.Value(nil)
	if diags.HasErrors() {
		t.Fatal(diags.Error())
	}
	if v.LengthInt() != 1 || !v.Type().HasAttribute("web2") {
		t.Fatalf("for_each = %#v, want web2 only", v)
	}
}

func TestStepImportListRejectsAnUnknownHost(t *testing.T) {
	mod, diags := loadCircuitModule(t, map[string]string{"main.circuit.hcl": importCircuit(`step "nginx" {
    import = ["web3"]
    package {
      name = "nginx"
    }
  }`)})
	if diags.HasErrors() {
		t.Fatal(diags.Error())
	}
	_, diags = mod.Import[0].ForEach.Value(nil)
	if !diags.HasErrors() || !strings.Contains(diags.Error(), `import names "web3", which isn't one of this step's hosts`) {
		t.Fatalf("diags = %v", diags)
	}
}

// In a looping step a host name stands for all its instances.
func TestStepImportListInLoopingStep(t *testing.T) {
	mod, diags := loadCircuitModule(t, map[string]string{"main.circuit.hcl": importCircuit(`step "tools" {
    for_each = ["tree", "jq"]
    import   = ["web1"]
    package {
      name = item.value
    }
  }`)})
	if diags.HasErrors() {
		t.Fatal(diags.Error())
	}
	v, diags := mod.Import[0].ForEach.Value(nil)
	if diags.HasErrors() {
		t.Fatal(diags.Error())
	}
	if v.LengthInt() != 2 || !v.Type().HasAttribute("web1/tree") || !v.Type().HasAttribute("web1/jq") {
		t.Fatalf("for_each = %#v", v)
	}
	got := importIDFor(t, mod.Import[0], "web1/jq", v.GetAttr("web1/jq"))
	if !strings.Contains(got, `"args":{"name":"jq"}`) || !strings.Contains(got, `"host":"203.0.113.10"`) {
		t.Fatalf("ID = %s", got)
	}
}

// A write-only file's import says so and never carries the content.
func TestStepImportWriteOnly(t *testing.T) {
	mod, diags := loadCircuitModule(t, map[string]string{
		"main.circuit.hcl": importCircuit(`step "token" {
    import = true
    template {
      source      = "token.tftpl"
      destination = "/etc/token"
      write_only  = true
    }
  }`),
	})
	if diags.HasErrors() {
		t.Fatal(diags.Error())
	}
	got := importIDFor(t, mod.Import[0], "web1", cty.StringVal("203.0.113.10"))
	if !strings.Contains(got, `"write_only":true`) || strings.Contains(got, "content") || strings.Contains(got, "token.tftpl") {
		t.Fatalf("ID = %s", got)
	}
}

func TestStepImportUnsupportedModule(t *testing.T) {
	_, diags := loadCircuitModule(t, map[string]string{"main.circuit.hcl": importCircuit(`step "run" {
    import = true
    command {
      command = "true"
    }
  }`)})
	if !diags.HasErrors() || !strings.Contains(diags.Error(), "import works on steps using") {
		t.Fatalf("diags = %v", diags)
	}
}
