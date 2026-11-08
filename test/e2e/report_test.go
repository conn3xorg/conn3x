// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/opentofu/opentofu/internal/conn3x/report"
)

type reportVars struct {
	Ports           map[string]string
	Key, KnownHosts string
	Fail            string
}

// apply -report and drift -report write reports that match the published
// schema: a step that failed on one host, the next step there skipped with
// the reason, and the other host's steps fine; then a file changed by hand
// shows up as drift on its host.
func TestRunReport(t *testing.T) {
	a, b := startHost(t, "rocky10"), startHost(t, "rocky10")
	known := shareKey(t, a, b)
	w := newWorkdir(t, "report")
	vars := reportVars{Ports: map[string]string{"a": a.port, "b": b.port}, Key: a.keyFile, KnownHosts: known, Fail: "b"}
	w.writeAs("main.circuit.hcl", vars)
	w.mustConn3x("init", "-no-color")

	read := func(name string) report.Report {
		t.Helper()
		src, err := os.ReadFile(filepath.Join(w.dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := report.Validate(src); err != nil {
			t.Fatalf("%s doesn't match the schema: %v\n%s", name, err, src)
		}
		var r report.Report
		if err := json.Unmarshal(src, &r); err != nil {
			t.Fatal(err)
		}
		return r
	}

	out, code := w.conn3x("apply", "-auto-approve", "-no-color", "-report=run.json")
	if code == 0 {
		t.Fatalf("apply passed although b's first step fails:\n%s", out)
	}
	r := read("run.json")
	t.Logf("report: %+v", r)
	if r.Success || r.Command != "apply" || len(r.Errors) == 0 || !strings.Contains(out, strings.SplitN(r.Errors[0], "\n", 2)[0]) {
		t.Errorf("success %v, command %s, errors %q", r.Success, r.Command, r.Errors)
	}
	sa, sb := r.Hosts["a"].Steps, r.Hosts["b"].Steps
	if len(sa) != 2 || sa[0].Status != report.StatusOK || sa[1].Status != report.StatusOK || !sa[1].Changed {
		t.Errorf("a's steps = %+v", sa)
	}
	if len(sb) != 2 || sb[0].Status != report.StatusFailed || !strings.Contains(sb[0].Error, "command failed") {
		t.Errorf("b's first step = %+v", sb)
	}
	if len(sb) == 2 && (sb[1].Status != report.StatusSkipped || sb[1].Reason != report.ReasonEarlierFailed) {
		t.Errorf("b's second step = %+v", sb[1])
	}

	vars.Fail = ""
	w.writeAs("main.circuit.hcl", vars)
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	a.exec("changed by hand\n", "sh", "-c", "cat > /etc/report-second")
	if out, code := w.conn3x("drift", "-no-color", "-report=drift.json"); code != 2 {
		t.Fatalf("drift exited %d:\n%s", code, out)
	}
	d := read("drift.json")
	if d.Command != "drift" || !d.Success || len(d.Drift) != 1 || d.Drift[0].Host != "a" || d.Drift[0].Kind != "changed" || !strings.HasPrefix(d.Drift[0].Address, "conn3x_file.r__second") {
		t.Errorf("drift report = %+v", d)
	}
}
