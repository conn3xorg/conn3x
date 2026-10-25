// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package configs

import (
	"fmt"
	"sort"
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

func TestTemplateWriteOnlyLowersToContentWO(t *testing.T) {
	src := `
circuit "db" {
  hosts = { db1 = "203.0.113.10" }
  ssh {
    user = "root"
  }
  step "secret" {
    template {
      source      = "pgpass.tftpl"
      destination = "/root/.pgpass"
      write_only  = true
    }
  }
  step "plain" {
    template {
      source      = "motd.tftpl"
      destination = "/etc/motd"
      write_only  = false
    }
  }
}
`
	mod, diags := loadCircuitModule(t, map[string]string{"main.circuit.hcl": src})
	if diags.HasErrors() {
		t.Fatal(diags.Error())
	}
	attrs := func(name string) hcl.Attributes {
		c, _, _ := mod.ManagedResources[name].Config.PartialContent(&hcl.BodySchema{
			Attributes: []hcl.AttributeSchema{{Name: "content"}, {Name: "content_wo"}, {Name: "write_only"}},
		})
		return c.Attributes
	}
	secret := attrs("conn3x_file.db__secret")
	if _, ok := secret["content_wo"]; !ok {
		t.Fatal("write_only = true should lower to content_wo")
	}
	if _, ok := secret["content"]; ok {
		t.Fatal("write_only = true must not also set content")
	}
	if _, ok := secret["write_only"]; ok {
		t.Fatal("write_only must not reach conn3x_file")
	}
	plain := attrs("conn3x_file.db__plain")
	if _, ok := plain["content"]; !ok {
		t.Fatal("write_only = false should lower to content")
	}
}

func TestTemplateWriteOnlyMustBeLiteral(t *testing.T) {
	src := `
variable "wo" {
  default = true
}
circuit "db" {
  hosts = { db1 = "203.0.113.10" }
  ssh {
    user = "root"
  }
  step "secret" {
    template {
      source      = "pgpass.tftpl"
      destination = "/root/.pgpass"
      write_only  = var.wo
    }
  }
}
`
	_, diags := loadCircuitModule(t, map[string]string{"main.circuit.hcl": src})
	if !diags.HasErrors() || !strings.Contains(diags.Error(), "true or false") {
		t.Fatalf("want an error asking for true or false, got %v", diags)
	}
}

const loopingCircuit = `
circuit "app" {
  hosts = { a = "10.0.0.1", b = { address = "10.0.0.2", port = 2222 } }
  ssh {
    user = "root"
  }
  step "tools" {
    for_each = ["git", "jq"]
    package {
      name = item.value
    }
  }
  step "conf" {
    for_each = { motd = "hi", issue = "ho" }
    file {
      path    = "/etc/${item.key}"
      content = "${each.key}: ${item.value}"
    }
  }
  step "plain" {
    file {
      path    = "/etc/plain"
      content = each.key
    }
  }
}
`

func TestLoopingStepLowersToHostItemProduct(t *testing.T) {
	mod, diags := loadCircuitModule(t, map[string]string{"main.circuit.hcl": loopingCircuit})
	if diags.HasErrors() {
		t.Fatal(diags.Error())
	}
	v, vDiags := mod.ManagedResources["conn3x_package.app__tools"].ForEach.Value(nil)
	if vDiags.HasErrors() {
		t.Fatal(vDiags.Error())
	}
	got := map[string]string{}
	for k, inst := range v.AsValueMap() {
		got[k] = inst.GetAttr("host_key").AsString() + "|" + inst.GetAttr("item_key").AsString() + "|" + inst.GetAttr("item").AsString()
	}
	want := map[string]string{"a/git": "a|git|git", "a/jq": "a|jq|jq", "b/git": "b|git|git", "b/jq": "b|jq|jq"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("for_each = %v, want %v", got, want)
	}
	if host := v.GetAttr("b/jq").GetAttr("host"); host.GetAttr("port").AsBigFloat().String() != "2222" {
		t.Fatalf("host object not carried: %#v", host)
	}
}

func TestLoopingStepRewritesReferences(t *testing.T) {
	mod, diags := loadCircuitModule(t, map[string]string{"main.circuit.hcl": loopingCircuit})
	if diags.HasErrors() {
		t.Fatal(diags.Error())
	}
	r := mod.ManagedResources["conn3x_file.app__conf"]
	inst := cty.ObjectVal(map[string]cty.Value{
		"host_key": cty.StringVal("b"), "host": cty.ObjectVal(map[string]cty.Value{"address": cty.StringVal("10.0.0.2"), "port": cty.NumberIntVal(2222)}),
		"item_key": cty.StringVal("motd"), "item": cty.StringVal("hi"),
	})
	ctx := &hcl.EvalContext{
		Variables: map[string]cty.Value{"each": cty.ObjectVal(map[string]cty.Value{"key": cty.StringVal("b/motd"), "value": inst})},
		Functions: map[string]function.Function{"try": tryfunc.TryFunc},
	}
	attrs, _ := r.Config.JustAttributes()
	for name, want := range map[string]string{"path": "/etc/motd", "content": "b: hi"} {
		got, d := attrs[name].Expr.Value(ctx)
		if d.HasErrors() || got.AsString() != want {
			t.Errorf("%s = %#v (%v), want %q", name, got, d, want)
		}
	}
	ssh, _, _ := r.Config.PartialContent(&hcl.BodySchema{Blocks: []hcl.BlockHeaderSchema{{Type: "ssh"}}})
	sshAttrs, _ := ssh.Blocks[0].Body.JustAttributes()
	for name, want := range map[string]string{"host": "10.0.0.2", "port": "2222"} {
		got, d := sshAttrs[name].Expr.Value(ctx)
		if d.HasErrors() {
			t.Fatalf("ssh %s: %v", name, d)
		}
		s := ""
		if got.Type() == cty.Number {
			s = got.AsBigFloat().String()
		} else {
			s = got.AsString()
		}
		if s != want {
			t.Errorf("ssh %s = %s, want %s", name, s, want)
		}
	}
}

func TestStepWithoutForEachUnchanged(t *testing.T) {
	mod, diags := loadCircuitModule(t, map[string]string{"main.circuit.hcl": loopingCircuit})
	if diags.HasErrors() {
		t.Fatal(diags.Error())
	}
	if _, ok := mod.ManagedResources["conn3x_file.app__plain"].ForEach.(*hclsyntax.ObjectConsExpr); !ok {
		t.Fatalf("a step without for_each should keep hosts as its for_each, got %T", mod.ManagedResources["conn3x_file.app__plain"].ForEach)
	}
}

func TestItemOutsideLoopIsAnError(t *testing.T) {
	src := `
circuit "app" {
  hosts = { a = "10.0.0.1" }
  ssh {
    user = "root"
  }
  step "plain" {
    file {
      path    = "/etc/x"
      content = item.value
    }
  }
}
`
	_, diags := loadCircuitModule(t, map[string]string{"main.circuit.hcl": src})
	if !diags.HasErrors() || !strings.Contains(diags.Error(), "for_each") {
		t.Fatalf("want an error pointing at for_each, got %v", diags)
	}
}

func TestHandlerTriggersFromLoopingStep(t *testing.T) {
	src := `
circuit "app" {
  hosts = { a = "10.0.0.1", b = "10.0.0.2" }
  ssh {
    user = "root"
  }
  step "conf" {
    for_each = ["one", "two"]
    file {
      path    = "/etc/${item.value}"
      content = "x"
    }
    notify = [handler.reload]
  }
  handler "reload" {
    service {
      name   = "nginx"
      action = "reload"
    }
  }
}
`
	mod, diags := loadCircuitModule(t, map[string]string{"main.circuit.hcl": src})
	if diags.HasErrors() {
		t.Fatal(diags.Error())
	}
	h := mod.ManagedResources["conn3x_service_action.app__reload"]
	attrs, _ := h.Config.JustAttributes()
	startswith := function.New(&function.Spec{
		Params: []function.Parameter{{Name: "s", Type: cty.String}, {Name: "p", Type: cty.String}},
		Type:   function.StaticReturnType(cty.Bool),
		Impl: func(args []cty.Value, _ cty.Type) (cty.Value, error) {
			return cty.BoolVal(strings.HasPrefix(args[0].AsString(), args[1].AsString())), nil
		},
	})
	inst := func(sum string) cty.Value { return cty.ObjectVal(map[string]cty.Value{"sha256": cty.StringVal(sum)}) }
	ctx := &hcl.EvalContext{
		Variables: map[string]cty.Value{
			"each": cty.ObjectVal(map[string]cty.Value{"key": cty.StringVal("a")}),
			"conn3x_file": cty.ObjectVal(map[string]cty.Value{"app__conf": cty.ObjectVal(map[string]cty.Value{
				"a/one": inst("1"), "a/two": inst("2"), "b/one": inst("3"), "b/two": inst("4"),
			})}),
		},
		Functions: map[string]function.Function{"startswith": startswith},
	}
	got, d := attrs["triggers"].Expr.Value(ctx)
	if d.HasErrors() {
		t.Fatal(d.Error())
	}
	keys := []string{}
	for k := range got.Index(cty.NumberIntVal(0)).AsValueMap() {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if fmt.Sprint(keys) != "[a/one a/two]" {
		t.Fatalf("host a's handler watches %v, want only host a's instances", keys)
	}
}
