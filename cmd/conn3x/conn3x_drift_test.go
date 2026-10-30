// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/opentofu/opentofu/internal/command"
	"github.com/opentofu/opentofu/internal/conn3x/provider"
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

// A host the refresh couldn't reach is a warning to plan, but drift can't
// call it unchanged, so it's an error there.
func TestDriftUnreachableHostIsAnError(t *testing.T) {
	line := `{"type":"diagnostic","diagnostic":{"severity":"warning","summary":"` + provider.UnreachableSummary + `","detail":"Nothing answered at 10.0.0.5:22."}}` + "\n"
	r, err := readDrift(strings.NewReader(line + line)) // two steps on one host
	if err != nil {
		t.Fatal(err)
	}
	if len(r.errors) != 1 {
		t.Fatalf("got %d errors for one host, want 1", len(r.errors))
	}
	if got := driftExit(r, 0); got != 1 {
		t.Fatalf("exit %d, want 1", got)
	}
	var out strings.Builder
	r.write(&out)
	if !strings.Contains(out.String(), "Error: "+provider.UnreachableSummary) {
		t.Fatalf("report doesn't name the host:\n%s", out.String())
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
	if code := runConvert("../../internal/conn3x/convert/ansible/testdata/web/site.yml", "", "", &out, &errOut); code != 3 {
		t.Fatalf("exit %d, want 3:\n%s", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "Converted 10 tasks. 1 thing needs you") || !strings.Contains(out.String(), `circuit "web_servers"`) {
		t.Fatalf("stdout:\n%s\nstderr:\n%s", out.String(), errOut.String())
	}
	if code := runConvert("nope.yml", "", "", &out, &errOut); code != 1 {
		t.Fatalf("missing playbook exited %d", code)
	}
}

func TestRunConvertWithInventory(t *testing.T) {
	var out, errOut strings.Builder
	runConvert("../../internal/conn3x/convert/ansible/testdata/web/site.yml", "../../internal/conn3x/convert/ansible/testdata/inv/hosts.ini", "", &out, &errOut)
	if !strings.Contains(out.String(), `web1 = "203.0.113.10"`) {
		t.Fatalf("inventory not used:\n%s\n%s", out.String(), errOut.String())
	}
	if code := runConvert("../../internal/conn3x/convert/ansible/testdata/web/site.yml", "missing.ini", "", &out, &errOut); code != 1 {
		t.Fatalf("missing inventory exited %d", code)
	}
}

// With -chdir, conn3x has already moved into that directory by the time
// drift runs, so the child plan has to start where conn3x was started.
func TestDriftConfirmPlanIsANormalPlan(t *testing.T) {
	p := driftConfirmPlan("/bin/conn3x", "/home/me", []string{"-chdir=x", "drift", "-var", "a=b"})
	want := []string{"/bin/conn3x", "-chdir=x", "plan", "-json", "-var", "a=b"}
	if !slices.Equal(p.Args, want) || p.Dir != "/home/me" {
		t.Fatalf("args %v in %q", p.Args, p.Dir)
	}
}

func TestDriftConfirmedKeepsOnlyWhatAPlanWouldChange(t *testing.T) {
	stream := `{"type":"resource_drift","change":{"resource":{"addr":"google_bigquery_table.events","resource_type":"google_bigquery_table"},"action":"update"}}
{"type":"resource_drift","change":{"resource":{"addr":"digitalocean_droplet.web","resource_type":"digitalocean_droplet"},"action":"update"}}
{"type":"resource_drift","change":{"resource":{"addr":"digitalocean_firewall.web","resource_type":"digitalocean_firewall"},"action":"delete"}}
{"type":"resource_drift","change":{"resource":{"addr":"conn3x_file.page","resource_type":"conn3x_file"},"action":"update"}}
`
	r, err := readDrift(strings.NewReader(stream))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := readDrift(strings.NewReader(`{"type":"planned_change","change":{"resource":{"addr":"digitalocean_droplet.web"},"action":"update"}}
{"type":"planned_change","change":{"resource":{"addr":"other.new"},"action":"create"}}
`))
	if err != nil {
		t.Fatal(err)
	}
	r, code := r.confirmed(plan.planned, 2)
	if code != 2 {
		t.Fatalf("code %d", code)
	}
	if len(r.cloud) != 2 || len(r.hosts) != 1 {
		t.Fatalf("cloud %v hosts %v", r.cloud, r.hosts)
	}
	if !slices.Equal(r.notes, []string{"  google_bigquery_table.events"}) {
		t.Fatalf("notes %v", r.notes)
	}
}

func TestDriftOnlyNotesIsClean(t *testing.T) {
	r := driftReport{cloud: []string{"  ~ a.b  changed"}, changedCloud: []string{"a.b"}}
	r, code := r.confirmed(nil, 2)
	var out strings.Builder
	if got := reportDrift(r, code, &out); got != 0 {
		t.Fatalf("exit %d", got)
	}
	if !strings.Contains(out.String(), "No drift") || !strings.Contains(out.String(), "a.b") {
		t.Fatalf("output %q", out.String())
	}
}

func TestDriftPlanStartsInOriginalDir(t *testing.T) {
	p := driftPlan("/bin/conn3x", "/home/me", []string{"-chdir=sub", "drift"})
	if p.Dir != "/home/me" {
		t.Fatalf("plan runs in %q", p.Dir)
	}
}

// A plan that failed before reporting anything is an error, not "no drift".
func TestDriftFailedPlanIsNotClean(t *testing.T) {
	var out strings.Builder
	if code := reportDrift(driftReport{}, 1, &out); code != 1 || out.Len() != 0 {
		t.Fatalf("exit %d, printed %q", code, out.String())
	}
}

func TestDriftRejectsJSON(t *testing.T) {
	d, _ := findCommand(brandedRoot(t), "drift")
	var errOut strings.Builder
	old := stderr
	stderr = &errOut
	t.Cleanup(func() { stderr = old })
	if code := command.RunCommand(d, testMeta(t), []string{"-json"}); code != 1 {
		t.Fatalf("drift -json exited %d", code)
	}
	if !strings.Contains(errOut.String(), "-json") {
		t.Fatalf("stderr: %q", errOut.String())
	}
}

func TestConvertNeedsPlaybook(t *testing.T) {
	c, _ := findCommand(brandedRoot(t), "convert")
	if diags := c.Commands[0].CommandLine.RemainCheck(nil); diags.HasErrors() {
		t.Fatalf("a missing playbook is a usage error: %s", diags.Err())
	}
	if u := commandUsage("convert ", c.Commands[0]); !strings.Contains(u, "ansible [options] <PLAYBOOK>") {
		t.Fatalf("usage:\n%s", u)
	}
	var out, errOut strings.Builder
	if code := runConvert("", "", "", &out, &errOut); code != 1 || !strings.Contains(errOut.String(), "playbook path is required") {
		t.Fatalf("exit %d: %q", code, errOut.String())
	}
}
