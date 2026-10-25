// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"reflect"
	"strings"
	"testing"
)

func TestDriftIsACommand(t *testing.T) {
	if _, ok := findCommand(brandedRoot(t), "drift"); !ok {
		t.Fatal("conn3x has no drift command")
	}
}

func TestDriftPlanArgs(t *testing.T) {
	got := driftPlanArgs([]string{"-chdir=infra", "drift", "-var-file=prod.tfvars"})
	want := []string{"-chdir=infra", "plan", "-refresh-only", "-detailed-exitcode", "-json", "-var-file=prod.tfvars"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q", got)
	}
}

const driftJSON = `{"@level":"info","@message":"Conn3x 0.0.0","type":"version"}
{"@level":"info","@message":"digitalocean_droplet.web: Drift detected (update)","type":"resource_drift","change":{"resource":{"addr":"digitalocean_droplet.web","resource_type":"digitalocean_droplet"},"action":"update"}}
{"@level":"info","@message":"conn3x_file.web__page[\"web1\"]: Drift detected (update)","type":"resource_drift","change":{"resource":{"addr":"conn3x_file.web__page[\"web1\"]","resource_type":"conn3x_file"},"action":"update"}}
{"@level":"info","@message":"conn3x_user.web__app[\"web1\"]: Drift detected (delete)","type":"resource_drift","change":{"resource":{"addr":"conn3x_user.web__app[\"web1\"]","resource_type":"conn3x_user"},"action":"delete"}}
{"@level":"error","@message":"Error: boom","type":"diagnostic","diagnostic":{"severity":"error","summary":"boom","detail":"it broke"}}
`

func TestDriftReport(t *testing.T) {
	r, err := readDrift(strings.NewReader(driftJSON))
	if err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	r.write(&out)
	want := `Drift found in 3 resources.

Cloud
  ~ digitalocean_droplet.web  changed

Hosts
  ~ conn3x_file.web__page["web1"]  changed
  - conn3x_user.web__app["web1"]  gone

Error: boom
  it broke

Run conn3x plan to see what Conn3x would change to put them back.
`
	if out.String() != want {
		t.Fatalf("got:\n%s", out.String())
	}

	clean, _ := readDrift(strings.NewReader(`{"type":"version"}` + "\n"))
	out.Reset()
	clean.write(&out)
	if out.String() != "No drift: the cloud and the hosts match the last apply.\n" {
		t.Fatalf("got %q", out.String())
	}
}

// A refresh-only plan exits 2 for changed outputs too; that is drift, not
// an error.
func TestDriftExitCode(t *testing.T) {
	var none driftReport
	for _, c := range []struct {
		rep      driftReport
		planCode int
		want     int
	}{
		{none, 0, 0},
		{none, 2, 2},
		{driftReport{hosts: []string{"x"}}, 2, 2},
		{driftReport{errors: []string{"e"}}, 1, 1},
		{none, 1, 1},
	} {
		if got := driftExit(c.rep, c.planCode); got != c.want {
			t.Errorf("driftExit(%+v, %d) = %d, want %d", c.rep, c.planCode, got, c.want)
		}
	}
	var out strings.Builder
	driftReport{outputsOnly: true}.write(&out)
	if !strings.Contains(out.String(), "Only outputs changed") {
		t.Fatalf("got %q", out.String())
	}
}

func TestConvertIsACommand(t *testing.T) {
	c, ok := findCommand(brandedRoot(t), "convert")
	if !ok || len(c.Commands) != 1 || c.Commands[0].Name != "ansible" {
		t.Fatal("conn3x has no convert ansible command")
	}
}

func TestRunConvertExitCodes(t *testing.T) {
	var out, errOut strings.Builder
	if code := runConvert("../../internal/conn3x/convert/ansible/testdata/web/site.yml", "", &out, &errOut); code != 3 {
		t.Fatalf("exit %d, want 3:\n%s", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "Converted 9 of 11 tasks. 2 need you") || !strings.Contains(out.String(), `circuit "web_servers"`) {
		t.Fatalf("stdout:\n%s\nstderr:\n%s", out.String(), errOut.String())
	}
	if code := runConvert("nope.yml", "", &out, &errOut); code != 1 {
		t.Fatalf("missing playbook exited %d", code)
	}
}
