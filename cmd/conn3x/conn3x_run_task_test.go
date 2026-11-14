// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zclconf/go-cty/cty"
)

func TestLoadTask(t *testing.T) {
	write := func(body string) string {
		p := filepath.Join(t.TempDir(), "t.task.hcl")
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	task, err := loadTask(write(`task "deploy" {
  description = "Ships it."
  param "version" {}
  param "port" { default = 8080 }
  step "pkg" {
    package { name = "app-${param.version}" }
  }
  step "svc" {
    service {
      name  = upper(host.name)
      state = "started"
    }
  }
}`))
	if err != nil {
		t.Fatal(err)
	}
	if task.name != "deploy" || len(task.steps) != 2 || task.steps[0].module != "package" || task.steps[1].typ != "conn3x_service" {
		t.Fatalf("task = %+v", task)
	}
	params, err := task.paramValues(map[string]string{"version": "1.2"})
	if err != nil {
		t.Fatal(err)
	}
	if !params.GetAttr("port").RawEquals(cty.NumberIntVal(8080)) {
		t.Errorf("port default = %#v", params.GetAttr("port"))
	}
	host := cty.ObjectVal(map[string]cty.Value{"name": cty.StringVal("web1"), "vars": cty.MapValEmpty(cty.String)})
	args, err := task.steps[0].args(context.Background(), params, host)
	if err != nil || args["name"].AsString() != "app-1.2" {
		t.Errorf("pkg args = %v, %v", args, err)
	}
	args, err = task.steps[1].args(context.Background(), params, host)
	if err != nil || args["name"].AsString() != "WEB1" {
		t.Errorf("svc args = %v, %v", args, err)
	}
	if _, err := task.paramValues(nil); err == nil || !strings.Contains(err.Error(), "needs param version") {
		t.Errorf("missing param: %v", err)
	}

	cmd := func(name string) string {
		return "  step \"" + name + "\" {\n    command {\n      command = \"true\"\n    }\n  }\n"
	}
	for body, want := range map[string]string{
		"task \"a\" {\n}\n":                      "has no steps",
		"task \"a\" {\n  step \"x\" {\n  }\n}\n": "holds one module block",
		"task \"a\" {\n  step \"x\" {\n    eos_vlan {\n      vlan_id = 1\n    }\n  }\n}\n": "isn't a module a task can run",
		"task \"a\" {\n" + cmd("x") + cmd("x") + "}\n":                                     "two steps named x",
		"task \"a\" {\n" + cmd("x") + "}\ntask \"b\" {\n" + cmd("x") + "}\n":               "one task block",
	} {
		if _, err := loadTask(write(body)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err = %v, want %q", body, err, want)
		}
	}
}
