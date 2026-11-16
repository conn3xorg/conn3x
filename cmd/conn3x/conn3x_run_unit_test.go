// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Each mistake on the command line is refused with exit 1, before any host
// is reached.
func TestRunRefusesBeforeAnyHost(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	inv := write("inventory.ini", "[web]\nweb1 ansible_host=127.0.0.1\n")
	badInv := write("bad.ini", "[web]\nweb1 ansible_ssh_common_args='-o ProxyCommand=\"nc %h | tee\"'\n")
	task := write("t.task.hcl", "task \"t\" {\n  param \"v\" {}\n  step \"s\" {\n    command {\n      command = \"true\"\n    }\n  }\n}\n")
	plan := write("p.plan.hcl", "plan \"p\" {\n  param \"v\" {}\n  run \"a\" {\n    task  = \"t.task.hcl\"\n    hosts = \"all\"\n  }\n}\n")
	notDir := write("file", "")
	for want, o := range map[string]runOptions{
		"-i or -circuits is required":        {args: "uptime", pattern: "all"},
		"give -i or -circuits, not both":     {inventory: inv, circuits: dir, args: "uptime", pattern: "all"},
		"give -a with a command":             {inventory: inv, pattern: "all"},
		"give one of -m, -task and -plan":    {inventory: inv, module: "service", task: task, pattern: "all"},
		"-batch-size \"0\"":                  {inventory: inv, args: "uptime", batchSize: "0", pattern: "all"},
		"-max-failures can't be negative":    {inventory: inv, args: "uptime", maxFailures: -1, pattern: "all"},
		"plan p needs param v":               {inventory: inv, plan: plan, pattern: "all"},
		"-a: \"v\" isn't NAME=VALUE":         {inventory: inv, plan: plan, args: "v", pattern: "all"},
		"missing.plan.hcl":                   {inventory: inv, plan: filepath.Join(dir, "missing.plan.hcl"), pattern: "all"},
		"task t needs param v":               {inventory: inv, task: task, pattern: "all"},
		"-a: \"x\" isn't NAME=VALUE":         {inventory: inv, task: task, args: "x", pattern: "all"},
		"missing.task.hcl":                   {inventory: inv, task: filepath.Join(dir, "missing.task.hcl"), pattern: "all"},
		"\"nope\" isn't a module":            {inventory: inv, module: "nope", args: "x=1", pattern: "all"},
		"only runs in a circuit":             {inventory: inv, module: "eos_vlan", args: "vlan_id=10", pattern: "all"},
		"service has no argument":            {inventory: inv, module: "service", args: "colour=red", pattern: "all"},
		"isn't a directory":                  {circuits: notDir, args: "uptime", pattern: "all"},
		"missing.ini":                        {inventory: filepath.Join(dir, "missing.ini"), args: "uptime", pattern: "all"},
		"host web1: ansible_ssh_common_args": {inventory: badInv, args: "uptime", pattern: "all"},
		"\"db\" matches no host":             {inventory: inv, args: "uptime", pattern: "db"},
	} {
		var out, errOut bytes.Buffer
		if code := runRun(context.Background(), o, &out, &errOut); code != 1 || !strings.Contains(errOut.String(), want) {
			t.Errorf("%+v: exit %d, %q, want %q", o, code, errOut.String(), want)
		}
	}
}

// A host that fails, here before it is dialed, for want of its known_hosts
// file, gets its own line, and the run exits 2.
func TestRunReportsAFailedHost(t *testing.T) {
	inv := filepath.Join(t.TempDir(), "inventory.ini")
	if err := os.WriteFile(inv, []byte("web1 ansible_host=127.0.0.1 ansible_port=1 conn3x_ssh_become=true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, asJSON := range []bool{false, true} {
		var out, errOut bytes.Buffer
		o := runOptions{inventory: inv, args: "uptime", pattern: "all", forks: 1, json: asJSON, user: "u", knownHosts: filepath.Join(t.TempDir(), "known_hosts")}
		if code := runRun(context.Background(), o, &out, &errOut); code != 2 {
			t.Fatalf("json %v: exit %d, out %q, err %q", asJSON, code, out.String(), errOut.String())
		}
		if !asJSON {
			if !strings.HasPrefix(out.String(), "web1 | failed: ") {
				t.Errorf("out %q", out.String())
			}
			continue
		}
		var line map[string]any
		if err := json.Unmarshal(out.Bytes(), &line); err != nil || line["host"] != "web1" || line["status"] != "failed" || line["error"] == "" {
			t.Errorf("json line %q: %v", out.String(), err)
		}
	}
}

// A mistake in any run stops a plan before its first run starts.
func TestRunPlanRefusesBeforeAnyRun(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	inv := write("inventory.ini", "web1 ansible_host=127.0.0.1\n")
	write("t.task.hcl", "task \"t\" {\n  param \"v\" {}\n  step \"s\" {\n    command {\n      command = \"true\"\n    }\n  }\n}\n")
	ok := "  run \"a\" {\n    task   = \"t.task.hcl\"\n    hosts  = \"all\"\n    params = { v = \"1\" }\n  }\n"
	for want, run := range map[string]string{
		"run b: hosts:":                       "  run \"b\" {\n    task  = \"t.task.hcl\"\n    hosts = nope.x\n  }\n",
		"run b: hosts must be a host pattern": "  run \"b\" {\n    task  = \"t.task.hcl\"\n    hosts = run.a\n  }\n",
		"run b: params:":                      "  run \"b\" {\n    task   = \"t.task.hcl\"\n    hosts  = \"all\"\n    params = nope.x\n  }\n",
		"run b: params must be an object":     "  run \"b\" {\n    task   = \"t.task.hcl\"\n    hosts  = \"all\"\n    params = \"v=1\"\n  }\n",
		"run b: task t needs param v":         "  run \"b\" {\n    task  = \"t.task.hcl\"\n    hosts = \"all\"\n  }\n",
	} {
		plan := write("p.plan.hcl", "plan \"p\" {\n"+ok+run+"}\n")
		var out, errOut bytes.Buffer
		if code := runRun(context.Background(), runOptions{inventory: inv, plan: plan, pattern: "all"}, &out, &errOut); code != 1 || !strings.Contains(errOut.String(), want) || out.Len() != 0 {
			t.Errorf("%s: exit %d, out %q, err %q", want, code, out.String(), errOut.String())
		}
	}
	for want, body := range map[string]string{
		"must hold one plan block, not 2":     "plan \"p\" {\n" + ok + "}\nplan \"q\" {\n" + ok + "}\n",
		"run a: task must be the task file's": "plan \"p\" {\n  run \"a\" {\n    task  = 1 + nope\n    hosts = \"all\"\n  }\n}\n",
		"Unclosed configuration block":        "plan \"p\" {\n",
		"Unsupported argument":                "colour = \"red\"\n",
		"An argument named \"colour\"":        "plan \"p\" {\n  colour = \"red\"\n" + ok + "}\n",
		"Variables not allowed":               "plan \"p\" {\n  param \"v\" {\n    default = nope.x\n  }\n" + ok + "}\n",
		"An argument named \"size\"":          "plan \"p\" {\n  run \"a\" {\n    task   = \"t.task.hcl\"\n    hosts  = \"all\"\n    size   = 1\n  }\n}\n",
	} {
		if _, err := loadPlan(write("p.plan.hcl", body)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v", want, err)
		}
	}
}

// A run with a failed host stops the plan: the runs after it are skipped,
// and say so, and the plan exits 2.
func TestRunPlanStopsAtAFailedRun(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	inv := write("inventory.ini", "web1 ansible_host=127.0.0.1 ansible_port=1\n")
	write("t.task.hcl", "task \"t\" {\n  step \"s\" {\n    command {\n      command = \"true\"\n    }\n  }\n}\n")
	plan := write("p.plan.hcl", "plan \"p\" {\n  run \"a\" {\n    task  = \"t.task.hcl\"\n    hosts = \"all\"\n  }\n  run \"b\" {\n    task  = \"t.task.hcl\"\n    hosts = \"all\"\n  }\n}\n")
	known := filepath.Join(dir, "known_hosts") // not there, so the host fails before it's dialed
	var out, errOut bytes.Buffer
	if code := runRun(context.Background(), runOptions{inventory: inv, plan: plan, pattern: "all", json: true, forks: 1, knownHosts: known}, &out, &errOut); code != 2 {
		t.Fatalf("exit %d, out %q, err %q", code, out.String(), errOut.String())
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	var first, last map[string]any
	if len(lines) != 2 || json.Unmarshal([]byte(lines[0]), &first) != nil || json.Unmarshal([]byte(lines[1]), &last) != nil {
		t.Fatalf("out %q", out.String())
	}
	if first["run"] != "a" || first["status"] != "failed" || last["run"] != "b" || last["status"] != "skipped" {
		t.Errorf("lines %v, %v", first, last)
	}
}
