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
