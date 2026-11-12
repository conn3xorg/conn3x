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
	r.args = append(r.args, "-limit", "web*")
	if got := strings.Join(r.planArgs(nil, "p"), " "); !strings.HasSuffix(got, "-limit web*") {
		t.Errorf("the approved plan should keep -limit: %s", got)
	}
	if got := strings.Join(r.planArgs([]string{"web1"}, "p"), " "); strings.Contains(got, "web*") || !strings.Contains(got, "-limit=web1") {
		t.Errorf("a batch's plan should limit to the batch alone: %s", got)
	}
	if !r.approved("") {
		t.Error("-auto-approve didn't approve")
	}
}

func TestBatchApproval(t *testing.T) {
	for in, want := range map[string]bool{"yes\n": true, "no\n": false, "": false} {
		var out strings.Builder
		r := &batchRun{args: []string{"apply"}, in: strings.NewReader(in), out: &out, errOut: &out}
		if got := r.approved(" in batches"); got != want || !strings.Contains(out.String(), "perform these actions in batches?") {
			t.Errorf("%q: approved = %v, said %q", in, got, out.String())
		}
	}
	var out strings.Builder
	r := &batchRun{args: []string{"apply", "-input=false"}, out: &out, errOut: &out}
	if r.approved("") || !strings.Contains(out.String(), "-input=false needs -auto-approve to apply.") {
		t.Errorf("-input=false: %q", out.String())
	}
}

func TestBatchesFor(t *testing.T) {
	two := []configs.Conn3xBatch{{Circuit: "web", Size: 5, MaxFailures: 1}, {Circuit: "db", Size: 1}}
	bs, err := batchesFor(two, "25%", 0)
	if err != nil || bs[0] != (configs.Conn3xBatch{Circuit: "web", Percent: 25}) || bs[1] != (configs.Conn3xBatch{Circuit: "db", Percent: 25}) {
		t.Errorf("got %+v, %v", bs, err)
	}
	if bs, _ := batchesFor(two, "", -1); !slices.Equal(bs, two) {
		t.Errorf("no flags changed them: %+v", bs)
	}
	if _, err := batchesFor(two, "0", -1); err == nil {
		t.Error("-batch-size=0 should be refused")
	}
}

func TestBatchOrder(t *testing.T) {
	// web's steps depend on db's through a cloud resource; cache depends on
	// nothing, and app on web.
	p, err := readBatchPlan([]byte(`{"configuration": {"root_module": {"resources": [
		{"address": "conn3x_command.app__a", "depends_on": ["conn3x_command.web__b"]},
		{"address": "conn3x_command.web__a", "expressions": {"command": {"references": ["aws_lb.x.dns_name", "aws_lb.x"]}}},
		{"address": "conn3x_command.web__b", "depends_on": ["conn3x_command.web__a"]},
		{"address": "aws_lb.x", "expressions": {"tags": {"references": ["conn3x_command.db__a[\"db1\"].id"]}}},
		{"address": "conn3x_command.db__a"},
		{"address": "conn3x_command.cache__a"}
	]}}}`))
	if err != nil {
		t.Fatal(err)
	}
	var bs []configs.Conn3xBatch
	for _, c := range []string{"app", "web", "cache", "db"} {
		bs = append(bs, configs.Conn3xBatch{Circuit: c})
	}
	got, err := p.ordered(bs)
	var names []string
	for _, b := range got {
		names = append(names, b.Circuit)
	}
	if err != nil || strings.Join(names, ",") != "cache,db,web,app" {
		t.Errorf("ordered = %v, %v", names, err)
	}

	p.deps["conn3x_command.db__a"] = []string{"conn3x_command.app__a"}
	if _, err := p.ordered(bs); err == nil || !strings.Contains(err.Error(), `"app", "web", "db" depend on each other`) {
		t.Errorf("a cycle: %v", err)
	}
}

func TestNaturalCompare(t *testing.T) {
	got := []string{"web10", "web2", "db1", "web1", "web02x", "web"}
	slices.SortFunc(got, naturalCompare)
	if strings.Join(got, ",") != "db1,web,web1,web2,web02x,web10" {
		t.Errorf("got %v", got)
	}
}
