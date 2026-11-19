// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// -list-hosts prints what a pattern matches and connects to nothing: the
// hosts below have no address that answers.
func TestRunListHosts(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	inv := write("inventory.ini", "[web]\nweb1 ansible_host=192.0.2.1\nweb2 ansible_host=192.0.2.2\nweb3 ansible_host=192.0.2.3\n[db]\ndb1 ansible_host=192.0.2.9\n")
	write("t.task.hcl", "task \"t\" {\n  step \"s\" {\n    command {\n      command = \"true\"\n    }\n  }\n}\n")
	plan := write("p.plan.hcl", "plan \"p\" {\n  run \"app\" {\n    task  = \"t.task.hcl\"\n    hosts = \"web*:!web3\"\n  }\n  run \"data\" {\n    task  = \"t.task.hcl\"\n    hosts = \"db\"\n  }\n}\n")
	circuits := filepath.Join(dir, "circuits")
	if err := os.Mkdir(circuits, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(circuits, "web.circuit.hcl"), []byte("circuit \"web\" {\n  hosts = { w1 = \"192.0.2.1\", w2 = \"192.0.2.2\" }\n  ssh {\n    user = \"root\"\n  }\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	for _, c := range []struct {
		name string
		o    runOptions
		want string
	}{
		{"pattern", runOptions{inventory: inv, pattern: "web*:!web3"}, "  hosts (2):\n    web1\n    web2\n"},
		{"no match", runOptions{inventory: inv, pattern: "cache"}, "  hosts (0):\n"},
		{"json", runOptions{inventory: inv, pattern: "web*:!web3", json: true}, `["web1","web2"]` + "\n"},
		{"json, no match", runOptions{inventory: inv, pattern: "cache", json: true}, "[]\n"},
		{"circuits", runOptions{circuits: circuits, pattern: "web"}, "  hosts (2):\n    w1\n    w2\n"},
		{"plan", runOptions{inventory: inv, plan: plan, pattern: "all"}, "run app, task t:\n  hosts (2):\n    web1\n    web2\nrun data, task t:\n  hosts (1):\n    db1\n"},
		{"-a is ignored", runOptions{inventory: inv, pattern: "db", args: "uptime"}, "  hosts (1):\n    db1\n"},
	} {
		c.o.listHosts = true
		var out, errOut bytes.Buffer
		if code := runRun(context.Background(), c.o, &out, &errOut); code != 0 || out.String() != c.want {
			t.Errorf("%s: exit %d, stdout:\n%s\nstderr: %s\nwant:\n%s", c.name, code, out.String(), errOut.String(), c.want)
		}
	}

	var out, errOut bytes.Buffer
	if code := runRun(context.Background(), runOptions{inventory: inv, plan: plan, pattern: "all", json: true, listHosts: true}, &out, &errOut); code != 0 {
		t.Fatalf("plan, json: exit %d: %s", code, errOut.String())
	}
	var runs []struct {
		Run   string   `json:"run"`
		Hosts []string `json:"hosts"`
	}
	if err := json.Unmarshal(out.Bytes(), &runs); err != nil || len(runs) != 2 || runs[0].Run != "app" || len(runs[0].Hosts) != 2 || runs[1].Hosts[0] != "db1" {
		t.Errorf("plan, json: %v %+v:\n%s", err, runs, out.String())
	}
}
