// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package configs

import (
	"strings"
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/ext/tryfunc"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/function"

	"github.com/opentofu/opentofu/internal/configs/symlib"
)

func loadCircuitModule(t *testing.T, files map[string]string) (*Module, hcl.Diagnostics) {
	t.Helper()
	full := map[string]string{}
	for name, src := range files {
		full["mod/"+name] = src
	}
	mod, diags := testParser(full).LoadConfigDir("mod")
	if mod != nil {
		diags = diags.Extend(mod.Finalize(symlib.EmptyTable, RootModuleCallForTesting()))
	}
	return mod, diags
}

const webCircuit = `
resource "terraform_data" "box" {
  input = "203.0.113.10"
}

circuit "web" {
  hosts = { web1 = terraform_data.box.output }
  ssh {
    user             = "root"
    private_key_file = "~/.ssh/id_ed25519"
  }

  step "motd" {
    file {
      path    = "/etc/motd"
      content = "hello ${each.key}\n"
    }
  }

  step "issue" {
    depends_on = [terraform_data.box]
    file {
      path    = "/etc/issue"
      content = conn3x_file.web__motd[each.key].sha256
    }
  }
}
`

func TestCircuitLowersToResources(t *testing.T) {
	mod, diags := loadCircuitModule(t, map[string]string{"main.circuit.hcl": webCircuit})
	if diags.HasErrors() {
		t.Fatal(diags.Error())
	}
	motd, ok := mod.ManagedResources["conn3x_file.web__motd"]
	if !ok {
		t.Fatalf("no conn3x_file.web__motd; have %v", keys(mod.ManagedResources))
	}
	issue := mod.ManagedResources["conn3x_file.web__issue"]
	if issue == nil {
		t.Fatal("no conn3x_file.web__issue")
	}

	if motd.ForEach == nil || issue.ForEach == nil {
		t.Fatal("steps are not repeated over hosts")
	}
	if got := motd.Provider.String(); got != "terraform.io/builtin/conn3x" {
		t.Fatalf("provider = %s", got)
	}

	// The first step has no step dependencies; the second follows it and
	// keeps its own depends_on.
	if len(motd.DependsOn) != 0 {
		t.Fatalf("first step depends on %v", motd.DependsOn)
	}
	var deps []string
	for _, d := range issue.DependsOn {
		deps = append(deps, traversalString(d))
	}
	if strings.Join(deps, ",") != "terraform_data.box,conn3x_file.web__motd" {
		t.Fatalf("second step depends_on = %v", deps)
	}

	// The step body has the module arguments plus an ssh block whose host
	// comes from each.value.
	content, diags := motd.Config.Content(&hcl.BodySchema{
		Attributes: []hcl.AttributeSchema{{Name: "path"}, {Name: "content"}},
		Blocks:     []hcl.BlockHeaderSchema{{Type: "ssh"}},
	})
	if diags.HasErrors() {
		t.Fatal(diags.Error())
	}
	if len(content.Blocks) != 1 {
		t.Fatalf("got %d ssh blocks", len(content.Blocks))
	}
	ssh, diags := content.Blocks[0].Body.JustAttributes()
	if diags.HasErrors() {
		t.Fatal(diags.Error())
	}
	host, ok := ssh["host"]
	if !ok {
		t.Fatal("ssh block has no host")
	}
	// A host is an address, or an object with one and its own settings.
	ctx := func(v cty.Value) *hcl.EvalContext {
		return &hcl.EvalContext{
			Variables: map[string]cty.Value{"each": cty.ObjectVal(map[string]cty.Value{"key": cty.StringVal("web1"), "value": v})},
			Functions: map[string]function.Function{"try": tryfunc.TryFunc},
		}
	}
	for v, want := range map[*cty.Value]string{
		ptr(cty.StringVal("203.0.113.10")): "203.0.113.10",
		ptr(cty.ObjectVal(map[string]cty.Value{"address": cty.StringVal("10.0.0.5"), "port": cty.NumberIntVal(2222)})): "10.0.0.5",
	} {
		got, diags := host.Expr.Value(ctx(*v))
		if diags.HasErrors() || got.AsString() != want {
			t.Errorf("host for %#v = %#v, %s; want %s", *v, got, diags, want)
		}
	}
	port, diags := ssh["port"].Expr.Value(ctx(cty.ObjectVal(map[string]cty.Value{"address": cty.StringVal("10.0.0.5"), "port": cty.NumberIntVal(2222)})))
	if diags.HasErrors() || !port.RawEquals(cty.NumberIntVal(2222)) {
		t.Errorf("a host's own port = %#v, %s; want 2222", port, diags)
	}
	if _, ok := ssh["user"]; !ok {
		t.Fatal("circuit ssh settings not copied to the step")
	}
}

func TestCircuitInTfFile(t *testing.T) {
	_, diags := loadCircuitModule(t, map[string]string{"main.tf": webCircuit})
	if diags.HasErrors() {
		t.Fatal(diags.Error())
	}
}

func TestCircuitErrors(t *testing.T) {
	for name, tc := range map[string]struct{ src, want string }{
		"missing hosts": {`circuit "a" {
  ssh {
    user = "root"
  }
  step "s" {
    file {
      path    = "/x"
      content = "x"
    }
  }
}`, "hosts"},
		"host in circuit ssh": {`circuit "a" {
  hosts = { h = "1.2.3.4" }
  ssh {
    user = "root"
    host = "1.2.3.4"
  }
  step "s" {
    file {
      path    = "/x"
      content = "x"
    }
  }
}`, "comes from hosts"},
		"unknown module": {`circuit "a" {
  hosts = { h = "1.2.3.4" }
  ssh {
    user = "root"
  }
  step "s" {
    packge {
      name = "nginx"
    }
  }
}`, `Unknown module "packge"`},
		"two modules": {`circuit "a" {
  hosts = { h = "1.2.3.4" }
  ssh {
    user = "root"
  }
  step "s" {
    file {
      path = "/x"
      content = "x"
    }
    file {
      path = "/y"
      content = "y"
    }
  }
}`, "exactly one module"},
		"duplicate step": {`circuit "a" {
  hosts = { h = "1.2.3.4" }
  ssh {
    user = "root"
  }
  step "s" {
    file {
      path    = "/x"
      content = "x"
    }
  }
  step "s" {
    file {
      path    = "/y"
      content = "y"
    }
  }
}`, "Duplicate step"},
		"duplicate circuit": {`circuit "a" {
  hosts = { h = "1.2.3.4" }
  ssh {
    user = "root"
  }
  step "s" {
    file {
      path    = "/x"
      content = "x"
    }
  }
}
circuit "a" {
  hosts = { h = "1.2.3.4" }
  ssh {
    user = "root"
  }
  step "t" {
    file {
      path    = "/x"
      content = "x"
    }
  }
}`, "Duplicate circuit"},
		"double underscore": {`circuit "a__b" {
  hosts = { h = "1.2.3.4" }
  ssh {
    user = "root"
  }
  step "s" {
    file {
      path    = "/x"
      content = "x"
    }
  }
}`, "Invalid circuit name"},
	} {
		t.Run(name, func(t *testing.T) {
			_, diags := loadCircuitModule(t, map[string]string{"main.circuit.hcl": tc.src})
			if !diags.HasErrors() {
				t.Fatal("no error")
			}
			if !strings.Contains(diags.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", diags.Error(), tc.want)
			}
		})
	}
}

func keys(m map[string]*Resource) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func traversalString(tr hcl.Traversal) string {
	var parts []string
	for _, step := range tr {
		switch s := step.(type) {
		case hcl.TraverseRoot:
			parts = append(parts, s.Name)
		case hcl.TraverseAttr:
			parts = append(parts, s.Name)
		}
	}
	return strings.Join(parts, ".")
}

func TestTemplateStepLowersToFile(t *testing.T) {
	src := `
circuit "web" {
  hosts = { web1 = "203.0.113.10" }
  ssh {
    user = "root"
  }
  step "nginx_conf" {
    template {
      source      = "${path.module}/nginx.conf.tftpl"
      destination = "/etc/nginx/nginx.conf"
      vars        = { server_name = each.key }
      mode        = "0640"
    }
  }
  step "motd" {
    template {
      source      = "motd.tftpl"
      destination = "/etc/motd"
    }
  }
}
`
	mod, diags := loadCircuitModule(t, map[string]string{"main.circuit.hcl": src})
	if diags.HasErrors() {
		t.Fatal(diags.Error())
	}
	r, ok := mod.ManagedResources["conn3x_file.web__nginx_conf"]
	if !ok {
		t.Fatalf("no conn3x_file.web__nginx_conf; have %v", keys(mod.ManagedResources))
	}
	content, diags := r.Config.Content(&hcl.BodySchema{
		Attributes: []hcl.AttributeSchema{{Name: "path", Required: true}, {Name: "content", Required: true}, {Name: "mode"}},
		Blocks:     []hcl.BlockHeaderSchema{{Type: "ssh"}},
	})
	if diags.HasErrors() {
		t.Fatal(diags.Error())
	}
	call, ok := content.Attributes["content"].Expr.(*hclsyntax.FunctionCallExpr)
	if !ok || call.Name != "templatefile" || len(call.Args) != 2 {
		t.Fatalf("content is %T, want templatefile(source, vars)", content.Attributes["content"].Expr)
	}
	if _, ok := content.Attributes["mode"]; !ok {
		t.Fatal("mode not carried over")
	}

	motd := mod.ManagedResources["conn3x_file.web__motd"]
	mc, _ := motd.Config.Content(&hcl.BodySchema{
		Attributes: []hcl.AttributeSchema{{Name: "path"}, {Name: "content"}},
		Blocks:     []hcl.BlockHeaderSchema{{Type: "ssh"}},
	})
	if call, ok := mc.Attributes["content"].Expr.(*hclsyntax.FunctionCallExpr); !ok || len(call.Args) != 2 {
		t.Fatal("template without vars should still pass an empty vars object")
	}
}

func TestTemplateStepErrors(t *testing.T) {
	for name, tc := range map[string]struct{ body, want string }{
		"missing source": {`destination = "/etc/x"`, `"source" is required`},
		"missing dest":   {`source = "x.tftpl"`, `"destination" is required`},
		"content set":    {"source = \"x\"\n      destination = \"/x\"\n      content = \"y\"", `Unsupported argument`},
	} {
		t.Run(name, func(t *testing.T) {
			src := "circuit \"a\" {\n  hosts = { h = \"1.2.3.4\" }\n  ssh {\n    user = \"root\"\n  }\n  step \"s\" {\n    template {\n      " + tc.body + "\n    }\n  }\n}\n"
			_, diags := loadCircuitModule(t, map[string]string{"main.circuit.hcl": src})
			if !diags.HasErrors() || !strings.Contains(diags.Error(), tc.want) {
				t.Fatalf("diags = %v, want %q", diags.Error(), tc.want)
			}
		})
	}
}

const handlerCircuit = `
circuit "web" {
  hosts = { web1 = "203.0.113.10" }
  ssh {
    user = "root"
  }
  step "conf" {
    template {
      source      = "nginx.conf.tftpl"
      destination = "/etc/nginx/nginx.conf"
    }
    notify = [handler.restart_nginx]
  }
  step "site" {
    file {
      path    = "/srv/index.html"
      content = "hi"
    }
    notify = [handler.restart_nginx]
  }
  handler "restart_nginx" {
    service {
      name = "nginx"
    }
  }
}
`

func TestHandlerLowersToServiceAction(t *testing.T) {
	mod, diags := loadCircuitModule(t, map[string]string{"main.circuit.hcl": handlerCircuit})
	if diags.HasErrors() {
		t.Fatal(diags.Error())
	}
	h, ok := mod.ManagedResources["conn3x_service_action.web__restart_nginx"]
	if !ok {
		t.Fatalf("no handler resource; have %v", keys(mod.ManagedResources))
	}
	if h.ForEach == nil {
		t.Fatal("handler not repeated over hosts")
	}
	content, diags := h.Config.Content(&hcl.BodySchema{
		Attributes: []hcl.AttributeSchema{{Name: "name", Required: true}, {Name: "action"}, {Name: "triggers", Required: true}},
		Blocks:     []hcl.BlockHeaderSchema{{Type: "ssh"}},
	})
	if diags.HasErrors() {
		t.Fatal(diags.Error())
	}
	var refs []string
	for _, tr := range content.Attributes["triggers"].Expr.Variables() {
		refs = append(refs, traversalString(tr))
	}
	got := strings.Join(refs, ",")
	for _, want := range []string{"conn3x_file.web__conf", "conn3x_file.web__site", "each"} {
		if !strings.Contains(got, want) {
			t.Fatalf("triggers reference %q, missing %q", got, want)
		}
	}
	if len(h.DependsOn) != 1 || traversalString(h.DependsOn[0]) != "conn3x_file.web__site" {
		t.Fatalf("handler should wait for the circuit's last step, depends_on = %v", h.DependsOn)
	}
	// notify is consumed by the lowering, not passed to the step's resource.
	conf := mod.ManagedResources["conn3x_file.web__conf"]
	if attrs, _ := conf.Config.JustAttributes(); attrs["notify"] != nil {
		t.Fatal("notify leaked into the step's resource")
	}
}

func TestHandlerErrors(t *testing.T) {
	for name, tc := range map[string]struct{ src, want string }{
		"unknown handler": {strings.Replace(handlerCircuit, "handler.restart_nginx]\n  }\n  step \"site\"", "handler.restart_apache]\n  }\n  step \"site\"", 1), `No handler "restart_apache"`},
		"bad reference":   {strings.Replace(handlerCircuit, "notify = [handler.restart_nginx]\n  }\n  step \"site\"", "notify = [step.site]\n  }\n  step \"site\"", 1), "handler.<name>"},
		"handler module":  {strings.Replace(handlerCircuit, "service {\n      name = \"nginx\"", "file {\n      name = \"nginx\"", 1), "service block"},
	} {
		t.Run(name, func(t *testing.T) {
			_, diags := loadCircuitModule(t, map[string]string{"main.circuit.hcl": tc.src})
			if !diags.HasErrors() || !strings.Contains(diags.Error(), tc.want) {
				t.Fatalf("diags = %v, want %q", diags.Error(), tc.want)
			}
		})
	}
}

func TestUnusedHandlerIsAWarning(t *testing.T) {
	src := strings.ReplaceAll(handlerCircuit, "    notify = [handler.restart_nginx]\n", "")
	_, diags := loadCircuitModule(t, map[string]string{"main.circuit.hcl": src})
	if diags.HasErrors() {
		t.Fatal(diags.Error())
	}
	found := false
	for _, d := range diags {
		if d.Severity == hcl.DiagWarning && strings.Contains(d.Summary, "Unused handler") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no unused-handler warning: %v", diags)
	}
}

func TestWarnsWhenAFileStepAndAnEditShareAPath(t *testing.T) {
	src := `
circuit "a" {
  hosts = { h = "1.2.3.4" }
  ssh {
    user = "root"
  }
  step "whole" {
    file {
      path    = "/etc/app.conf"
      content = "x = 1\n"
    }
  }
  step "part" {
    line {
      path = "/etc/app.conf"
      line = "y = 2"
    }
  }
}
`
	_, diags := loadCircuitModule(t, map[string]string{"main.circuit.hcl": src})
	if diags.HasErrors() {
		t.Fatal(diags.Error())
	}
	for _, d := range diags {
		if d.Severity == hcl.DiagWarning && strings.Contains(d.Summary, "edited and written whole") {
			return
		}
	}
	t.Fatalf("no warning: %v", diags)
}

func ptr(v cty.Value) *cty.Value { return &v }
