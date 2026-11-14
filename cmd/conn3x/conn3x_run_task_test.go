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
  step "cron" {
    crontab {
      user = "root"
      job {
        name     = "backup"
        schedule = "@daily"
        command  = "backup ${param.version}"
      }
    }
  }
}`))
	if err != nil {
		t.Fatal(err)
	}
	if task.name != "deploy" || len(task.steps) != 3 || task.steps[0].module != "package" || task.steps[1].typ != "conn3x_service" {
		t.Fatalf("task = %+v", task)
	}
	params, err := paramValues("task deploy", task.params, map[string]cty.Value{"version": cty.StringVal("1.2")})
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
	args, err = task.steps[2].args(context.Background(), params, host)
	if err != nil || args["job"].LengthInt() != 1 || args["job"].Index(cty.NumberIntVal(0)).GetAttr("command").AsString() != "backup 1.2" {
		t.Errorf("cron args = %v, %v", args, err)
	}
	bad, err := loadTask(write("task \"a\" {\n  step \"x\" {\n    file {\n      path = \"/x\"\n      id   = \"y\"\n    }\n  }\n}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bad.steps[0].args(context.Background(), params, host); err == nil || !strings.Contains(err.Error(), `no argument "id"`) {
		t.Errorf("a computed argument: %v", err)
	}
	bad, err = loadTask(write("task \"a\" {\n  step \"x\" {\n    file {\n      path = \"/x\"\n      ssh {\n        host = \"h\"\n      }\n    }\n  }\n}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bad.steps[0].args(context.Background(), params, host); err == nil || !strings.Contains(err.Error(), "ssh") {
		t.Errorf("an ssh block in a step: %v", err)
	}
	if _, err := paramValues("task deploy", task.params, nil); err == nil || !strings.Contains(err.Error(), "needs param version") {
		t.Errorf("missing param: %v", err)
	}

	cmd := func(name string) string {
		return "  step \"" + name + "\" {\n    command {\n      command = \"true\"\n    }\n  }\n"
	}
	for body, want := range map[string]string{
		"task \"a\" {\n}\n":                      "has no steps",
		"task \"a\" {\n  step \"x\" {\n  }\n}\n": "holds one module block",
		"task \"a\" {\n  step \"x\" {\n    eos_vlan {\n      vlan_id = 1\n    }\n  }\n}\n": "only runs in a circuit",
		"task \"a\" {\n" + cmd("x") + cmd("x") + "}\n":                                     "two steps named x",
		"task \"a\" {\n" + cmd("x") + "}\ntask \"b\" {\n" + cmd("x") + "}\n":               "one task block",
	} {
		if _, err := loadTask(write(body)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err = %v, want %q", body, err, want)
		}
	}
	// Junos and VyOS steps commit on their own outside a circuit.
	for _, mod := range []string{"junos_vlan", "vyos_hostname"} {
		if _, err := loadTask(write("task \"a\" {\n  step \"x\" {\n    " + mod + " {\n    }\n  }\n}\n")); err != nil {
			t.Errorf("%s: %v", mod, err)
		}
	}
}
