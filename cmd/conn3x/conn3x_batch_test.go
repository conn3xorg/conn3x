// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"slices"
	"strings"
	"testing"

	"github.com/opentofu/opentofu/internal/configs"
)

func TestBatchPlanHosts(t *testing.T) {
	p, err := readBatchPlan([]byte(`{"resource_changes": [
		{"address": "conn3x_command.web__a[\"web10\"]", "mode": "managed", "name": "web__a", "index": "web10", "change": {"actions": ["create"]}},
		{"address": "conn3x_command.web__a[\"web2\"]", "mode": "managed", "name": "web__a", "index": "web2", "change": {"actions": ["no-op"]}},
		{"address": "conn3x_file.web__b[\"web2/x\"]", "mode": "managed", "name": "web__b", "index": "web2/x", "change": {"actions": ["update"]}},
		{"address": "conn3x_command.web__a[\"a/b\"]", "mode": "managed", "name": "web__a", "index": "a/b", "change": {"actions": ["no-op"]}},
		{"address": "conn3x_file.web__b[\"a/b/x\"]", "mode": "managed", "name": "web__b", "index": "a/b/x", "change": {"actions": ["create"]}},
		{"address": "conn3x_command.db__a[\"db1\"]", "mode": "managed", "name": "db__a", "index": "db1", "change": {"actions": ["create"]}},
		{"address": "data.conn3x_facts.web__f[\"web3\"]", "mode": "data", "name": "web__f", "index": "web3", "change": {"actions": ["read"]}}
	]}`))
	if err != nil {
		t.Fatal(err)
	}
	// web__a doesn't loop, and web__b does.
	of := func(typ, name, key string) []string {
		if name != "web__b" {
			return []string{key}
		}
		var hs []string
		for i := range len(key) {
			if key[i] == '/' {
				hs = append(hs, key[:i])
			}
		}
		return hs
	}
	hosts, others := p.circuitHosts("web", of)
	if strings.Join(hosts, ",") != "a/b,web2,web10" {
		t.Errorf("hosts = %v", hosts)
	}
	if strings.Join(others, ",") != `conn3x_command.db__a["db1"]` {
		t.Errorf("others = %v", others)
	}
	// Without the configuration, a looping key's shortest reading.
	if hosts, _ := p.circuitHosts("web", nil); strings.Join(hosts, ",") != "a,web2,web10" {
		t.Errorf("hosts without the configuration = %v", hosts)
	}

	approved, _ := readBatchPlan([]byte(`{"resource_changes": [
		{"address": "a", "mode": "managed", "change": {"actions": ["update"]}},
		{"address": "b", "mode": "managed", "change": {"actions": ["create"]}}
	]}`))
	batch, _ := readBatchPlan([]byte(`{"resource_changes": [
		{"address": "a", "mode": "managed", "change": {"actions": ["update"]}},
		{"address": "b", "mode": "managed", "change": {"actions": ["delete", "create"]}},
		{"address": "c", "mode": "managed", "change": {"actions": ["create"]}},
		{"address": "d", "mode": "managed", "change": {"actions": ["no-op"]}}
	]}`))
	if extra := batch.notIn(approved); strings.Join(extra, ",") != "b,c" {
		t.Errorf("notIn = %v", extra)
	}
}

func TestBatchArgs(t *testing.T) {
	r := &batchRun{tmp: "/t", args: []string{"-chdir=x", "apply", "-auto-approve", "-var=a=1", "-batch-size", "2", "--max-failures=1", "-parallelism=5", "-no-color"}}
	if got := strings.Join(r.planArgs([]string{"web1", "web2"}, "p"), " "); got != "-chdir=x plan -detailed-exitcode -out=p -limit=web1,web2 -var=a=1 -parallelism=5 -no-color" {
		t.Errorf("planArgs = %s", got)
	}
	if got := strings.Join(r.applyArgs("p"), " "); got != "-chdir=x apply -parallelism=5 -no-color p" {
		t.Errorf("applyArgs = %s", got)
	}
	if !r.approved() {
		t.Error("-auto-approve didn't approve")
	}
}

func TestBatchFor(t *testing.T) {
	one := []configs.Conn3xBatch{{Circuit: "web", Size: 5, MaxFailures: 1}}
	b, err := batchFor(one, "25%", 0)
	if err != nil || b != (configs.Conn3xBatch{Circuit: "web", Percent: 25}) {
		t.Errorf("got %+v, %v", b, err)
	}
	if b, _ := batchFor(one, "", -1); b != one[0] {
		t.Errorf("no flags changed it: %+v", b)
	}
	if _, err := batchFor(append(one, configs.Conn3xBatch{Circuit: "db", Size: 1}), "", -1); err == nil || !strings.Contains(err.Error(), "web, db") {
		t.Errorf("two batched circuits: %v", err)
	}
}

func TestNaturalCompare(t *testing.T) {
	got := []string{"web10", "web2", "db1", "web1", "web02x", "web"}
	slices.SortFunc(got, naturalCompare)
	if strings.Join(got, ",") != "db1,web,web1,web2,web02x,web10" {
		t.Errorf("got %v", got)
	}
}
