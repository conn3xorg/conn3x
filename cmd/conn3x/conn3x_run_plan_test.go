// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadPlan(t *testing.T) {
	dir := t.TempDir()
	task := "task \"t\" {\n  param \"x\" {}\n  step \"s\" {\n    command {\n      command = \"true\"\n    }\n  }\n}\n"
	if err := os.WriteFile(filepath.Join(dir, "t.task.hcl"), []byte(task), 0o644); err != nil {
		t.Fatal(err)
	}
	write := func(body string) string {
		p := filepath.Join(dir, "p.plan.hcl")
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	run := func(name, task string) string {
		return "  run \"" + name + "\" {\n    task  = \"" + task + "\"\n    hosts = \"all\"\n  }\n"
	}
	p, err := loadPlan(write("plan \"p\" {\n  param \"v\" {\n    default = \"1\"\n  }\n" + run("a", "t.task.hcl") + run("b", "t.task.hcl") + "}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if p.name != "p" || len(p.runs) != 2 || p.runs[1].name != "b" || p.runs[0].task.name != "t" || p.params["v"] == nil {
		t.Fatalf("plan = %+v", p)
	}
	for body, want := range map[string]string{
		"plan \"p\" {\n}\n": "has no runs",
		"plan \"p\" {\n" + run("a", "t.task.hcl") + run("a", "t.task.hcl") + "}\n": "two runs named a",
		"plan \"p\" {\n" + run("a", "missing.task.hcl") + "}\n":                    "run a:",
		"plan \"p\" {\n  run \"a\" {\n    task = \"t.task.hcl\"\n  }\n}\n":         "hosts",
	} {
		if _, err := loadPlan(write(body)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: err = %v, want %q", body, err, want)
		}
	}
}
