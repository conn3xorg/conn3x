// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

type chainVars struct{ PortA, PortB, PortSlow, Key, KnownHosts string }

// Each host runs its own chain of steps: a and b finish step two while slow
// is still on step one, and every host still runs one before two.
func TestStepsChainPerHost(t *testing.T) {
	a, b, slow := startHost(t, "rocky10"), startHost(t, "rocky10"), startHost(t, "rocky10")
	knownFile := shareKey(t, a, b, slow)

	w := newWorkdir(t, "chain")
	w.writeAs("main.circuit.hcl", chainVars{a.port, b.port, slow.port, a.keyFile, knownFile})
	w.mustConn3x("init", "-no-color")
	w.mustConn3x("apply", "-auto-approve", "-no-color")

	at := func(h *host, file string) float64 { t.Helper(); return stamp(t, h.exec("", "cat", file)) }
	slowOne := at(slow, "/tmp/one")
	for name, h := range map[string]*host{"a": a, "b": b, "slow": slow} {
		if one, two := at(h, "/tmp/one"), at(h, "/tmp/two"); two < one {
			t.Errorf("%s ran step two before step one", name)
		}
	}
	for name, h := range map[string]*host{"a": a, "b": b} {
		two := at(h, "/tmp/two")
		t.Logf("%s finished step two %.1fs before slow finished step one", name, slowOne-two)
		if two >= slowOne {
			t.Errorf("%s waited for slow: step two at %.3f, slow's step one at %.3f", name, two, slowOne)
		}
	}
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
		t.Fatalf("plan after apply:\n%s", out)
	}
}

// shareKey lets the first host's key log in to every host, so one circuit
// can reach them all, and returns a known_hosts file listing them all.
func shareKey(t *testing.T, hosts ...*host) string {
	t.Helper()
	pub := strings.TrimSpace(run(t, "ssh-keygen", "-y", "-f", hosts[0].keyFile))
	var known []byte
	for _, h := range hosts {
		h.exec(pub+"\n", "sh", "-c", "cat > /root/.ssh/authorized_keys")
		data, err := os.ReadFile(h.knownHosts)
		if err != nil {
			t.Fatal(err)
		}
		known = append(known, data...)
	}
	knownFile := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(knownFile, known, 0o600); err != nil {
		t.Fatal(err)
	}
	return knownFile
}

// stamp parses a `date +%s.%N` timestamp.
func stamp(t *testing.T, s string) float64 {
	t.Helper()
	v, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// A step with on runs once per host, over the connection of the host on
// names: lb ends up with a file for each host, and web1 with none.
func TestStepOnAnotherHost(t *testing.T) {
	web, lb := startHost(t, "rocky10"), startHost(t, "rocky10")
	knownFile := shareKey(t, web, lb)
	w := newWorkdir(t, "step_on")
	w.writeAs("main.circuit.hcl", chainVars{PortA: web.port, PortB: lb.port, Key: web.keyFile, KnownHosts: knownFile})
	w.mustConn3x("init", "-no-color")
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	files := func(h *host) string {
		return strings.TrimSpace(h.exec("", "sh", "-c", "ls /tmp | grep '^drained-' | sort | tr '\\n' ' '"))
	}
	if got := files(lb); got != "drained-lb drained-web1" {
		t.Errorf("lb has %q, want a file for each host", got)
	}
	if got := files(web); got != "" {
		t.Errorf("web1 has %q, want none: its step ran on lb", got)
	}
	if out := w.mustConn3x("plan", "-no-color", "-detailed-exitcode"); !strings.Contains(out, "No changes") {
		t.Errorf("a second plan should find both files on lb:\n%s", out)
	}
}

// on = "controller" runs each host's step on the machine Conn3x runs on, in
// its working directory, and never on the host.
func TestStepOnController(t *testing.T) {
	web1, web2 := startHost(t, "rocky10"), startHost(t, "rocky10")
	knownFile := shareKey(t, web1, web2)
	w := newWorkdir(t, "on_controller")
	w.writeAs("main.circuit.hcl", chainVars{PortA: web1.port, PortB: web2.port, Key: web1.keyFile, KnownHosts: knownFile})
	w.mustConn3x("init", "-no-color")
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	raw, err := os.ReadFile(filepath.Join(w.dir, "announced.txt"))
	lines := strings.Fields(string(raw))
	slices.Sort(lines)
	if err != nil || strings.Join(lines, " ") != "web1 web2" {
		t.Errorf("announced.txt = %q, %v; want a line for each host", raw, err)
	}
	for _, h := range []*host{web1, web2} {
		if got := strings.TrimSpace(h.exec("", "sh", "-c", "ls ~/announced.txt / 2>/dev/null | grep -c announced || true")); got != "0" {
			t.Errorf("a host has announced.txt: the step ran there")
		}
	}
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes") {
		t.Errorf("a second plan should have nothing to do:\n%s", out)
	}
}

// -limit runs a circuit on some hosts only, and leaves the others as they
// are until a run without it.
func TestLimitHosts(t *testing.T) {
	web, db := startHost(t, "rocky10"), startHost(t, "rocky10")
	knownFile := shareKey(t, web, db)
	w := newWorkdir(t, "limit_hosts")
	w.writeAs("main.circuit.hcl", chainVars{PortA: web.port, PortB: db.port, Key: web.keyFile, KnownHosts: knownFile})
	w.mustConn3x("init", "-no-color")
	motd := func(h *host) string {
		return strings.TrimSpace(h.exec("", "sh", "-c", "cat /etc/motd 2>/dev/null || true"))
	}

	out := w.mustConn3x("apply", "-auto-approve", "-no-color", "-var=motd=one", "-limit=web*")
	if !strings.Contains(out, "Limited to some hosts") || strings.Contains(out, "Resource targeting is in effect") {
		t.Errorf("a limited apply should say so, in its own words:\n%s", out)
	}
	if motd(web) != "one" || motd(db) != "" {
		t.Fatalf("after -limit=web*: web1 has %q and db1 %q, want one and nothing", motd(web), motd(db))
	}

	w.mustConn3x("apply", "-auto-approve", "-no-color", "-var=motd=one")
	w.mustConn3x("apply", "-auto-approve", "-no-color", "-var=motd=two", "-limit=all:!web1")
	if motd(web) != "one" || motd(db) != "two" {
		t.Fatalf("after -limit=all:!web1: web1 has %q and db1 %q, want one and two", motd(web), motd(db))
	}
	if out := w.mustConn3x("plan", "-no-color", "-var=motd=two"); !strings.Contains(out, "1 to change") || !strings.Contains(out, `["web1"]`) {
		t.Errorf("a plan without -limit should catch web1 up:\n%s", out)
	}
	if out, code := w.conn3x("plan", "-no-color", "-var=motd=two", "-limit=web9"); code != 0 || !strings.Contains(out, "-limit matched no host") {
		t.Errorf("a -limit that matches nothing should warn (exit %d):\n%s", code, out)
	}
	w.mustConn3x("plan", "-no-color", "-var=motd=two", "-limit=web1", "-out=web1.tfplan")
	if out, code := w.conn3x("apply", "-no-color", "-limit=web1", "web1.tfplan"); code == 0 || !strings.Contains(out, "saved plan") {
		t.Errorf("-limit on applying a saved plan should be refused (exit %d):\n%s", code, out)
	}
}

// A circuit with batch_size rolls out one batch at a time, in host name
// order, and stops starting batches once more hosts fail than max_failures
// allows.
func TestBatchApply(t *testing.T) {
	web1, web2, web10 := startHost(t, "rocky10"), startHost(t, "rocky10"), startHost(t, "rocky10")
	knownFile := shareKey(t, web1, web2, web10)
	w := newWorkdir(t, "batch")
	w.writeAs("main.circuit.hcl", chainVars{PortA: web1.port, PortB: web2.port, PortSlow: web10.port, Key: web1.keyFile, KnownHosts: knownFile})
	w.mustConn3x("init", "-no-color")
	stamp := func(h *host, name string) float64 {
		v, err := strconv.ParseFloat(strings.TrimSpace(h.exec("", "cat", "/tmp/"+name)), 64)
		if err != nil {
			t.Fatalf("/tmp/%s: %v", name, err)
		}
		return v
	}

	out := w.mustConn3x("apply", "-auto-approve", "-no-color", "-var=run=1")
	for _, want := range []string{"changes 3 hosts, which roll out in 3 batches of up to 1", "Batch 1 of 3: web1", "Batch 2 of 3: web2", "Batch 3 of 3: web10", "All 3 batches applied"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
	if stamp(web1, "finish") > stamp(web2, "start") || stamp(web2, "finish") > stamp(web10, "start") {
		t.Errorf("a batch started before the one before it finished")
	}

	out, code := w.conn3x("apply", "-auto-approve", "-no-color", "-var=run=2", "-var=fail_on=web2", "-report=run.json")
	if code == 0 || !strings.Contains(out, "1 host failed, more than max_failures = 0") || !strings.Contains(out, "Failed: web2") || !strings.Contains(out, "Not reached: web10") {
		t.Errorf("a failure should stop the rollout (exit %d):\n%s", code, out)
	}
	var rep struct {
		Success bool
		Hosts   map[string]struct{ Steps []struct{ Status string } }
		Errors  []string
	}
	raw, err := os.ReadFile(filepath.Join(w.dir, "run.json"))
	if err != nil || json.Unmarshal(raw, &rep) != nil {
		t.Fatalf("report: %v\n%s", err, raw)
	}
	_, reached := rep.Hosts["web10"]
	if rep.Success || reached || len(rep.Hosts["web1"].Steps) != 2 || rep.Hosts["web2"].Steps[0].Status != "failed" || !strings.Contains(strings.Join(rep.Errors, "\n"), "Not reached: web10") {
		t.Errorf("the rollout's report should have web1 done, web2 failed and web10 not reached:\n%s", raw)
	}
	if out := w.mustConn3x("plan", "-no-color", "-var=run=2"); !strings.Contains(out, `web__start["web10"] must be replaced`) || strings.Contains(out, `["web1"] must`) || strings.Contains(out, `["web1"] will`) {
		t.Errorf("web1 should be done and web10 untouched:\n%s", out)
	}

	out, code = w.conn3x("apply", "-auto-approve", "-no-color", "-var=run=3", "-var=fail_on=web1", "-batch-size=2", "-max-failures=1")
	if code == 0 || !strings.Contains(out, "every batch ran, and 1 host failed, within max_failures = 1") || !strings.Contains(out, "Batch 2 of 2: web10") {
		t.Errorf("-max-failures=1 should let the rollout finish and still fail (exit %d):\n%s", code, out)
	}

	out = w.mustConn3x("apply", "-auto-approve", "-no-color", "-var=run=4", "-limit=web1,web10")
	if !strings.Contains(out, "changes 2 hosts, which roll out in 2 batches") || !strings.Contains(out, "Batch 2 of 2: web10") {
		t.Errorf("-limit should batch only the hosts it matches:\n%s", out)
	}
	// 34% of the 3 hosts that change is 1, rounded down.
	out, code = w.conn3x("apply", "-auto-approve", "-no-color", "-var=run=5", "-var=fail_on=web2", "-max-failures=34%")
	if code == 0 || !strings.Contains(out, "within max_failures = 34% (1 of 3 hosts)") || !strings.Contains(out, "Batch 3 of 3: web10") {
		t.Errorf("-max-failures=34%% should let one of three hosts fail (exit %d):\n%s", code, out)
	}
}

func TestBatchTwoCircuits(t *testing.T) {
	web1, web2 := startHost(t, "rocky10"), startHost(t, "rocky10")
	knownFile := shareKey(t, web1, web2)
	w := newWorkdir(t, "batch_circuits")
	w.writeAs("main.circuit.hcl", chainVars{PortA: web1.port, PortB: web2.port, Key: web1.keyFile, KnownHosts: knownFile})
	w.mustConn3x("init", "-no-color")

	out := w.mustConn3x("apply", "-auto-approve", "-no-color", "-var=run=1")
	db, web := strings.Index(out, `Circuit "db", batch 1 of 1: web1`), strings.Index(out, `Circuit "web", batch 1 of 2: web1`)
	if !strings.Contains(out, "First, 1 other change applies in one go:\n  terraform_data.before") {
		t.Errorf("the change outside the circuits should apply first:\n%s", out)
	}
	if db < 0 || web < db || !strings.Contains(out, `Circuit "web", batch 2 of 2: web2`) || !strings.Contains(out, "All 3 batches applied") {
		t.Errorf("db should roll out, then web, one batch at a time:\n%s", out)
	}
	if out := w.mustConn3x("plan", "-no-color", "-var=run=1"); !strings.Contains(out, "No changes") {
		t.Errorf("every circuit should be applied:\n%s", out)
	}

	out, code := w.conn3x("apply", "-auto-approve", "-no-color", "-var=run=2", "-var=after=true")
	if code == 0 || !strings.Contains(out, "need batched steps first") || !strings.Contains(out, `conn3x_command.web__start["web2"]`) || strings.Contains(out, "Batch") {
		t.Errorf("a change that needs batched steps should stop the apply before anything runs (exit %d):\n%s", code, out)
	}
}

// A rescue runs on the hosts where a step it watches failed, in a plan of
// its own after the apply, and leaves nothing in state behind it.
func TestRescue(t *testing.T) {
	web1, web2 := startHost(t, "rocky10"), startHost(t, "rocky10")
	knownFile := shareKey(t, web1, web2)
	w := newWorkdir(t, "rescue")
	w.writeAs("main.circuit.hcl", chainVars{PortA: web1.port, PortB: web2.port, Key: web1.keyFile, KnownHosts: knownFile})
	w.mustConn3x("init", "-no-color")
	file := func(h *host, name string) string {
		return strings.TrimSpace(h.exec("", "sh", "-c", "cat /tmp/"+name+" 2>/dev/null; true"))
	}

	out := w.mustConn3x("apply", "-auto-approve", "-no-color", "-var=run=1")
	if !strings.Contains(out, `If config fails on a host, rescue "restore" of circuit "app" runs there.`) || strings.Contains(out, "Rescuing") {
		t.Errorf("the plan should say when the rescue runs, and nothing failed:\n%s", out)
	}

	out, code := w.conn3x("apply", "-auto-approve", "-no-color", "-var=run=2", "-var=fail_on=web2", "-report=run.json")
	if code == 0 || !strings.Contains(out, "Rescuing web2:") || !strings.Contains(out, "Rescued web2. The apply still fails") {
		t.Errorf("web2's failure should be rescued, and the apply still fail (exit %d):\n%s", code, out)
	}
	if file(web2, "rescued") != "rescued 2" || file(web1, "rescued") != "" || file(web1, "config") != "2" {
		t.Errorf("only web2 should be rescued: web1 %q, web2 %q", file(web1, "rescued"), file(web2, "rescued"))
	}
	if file(web1, "never") != "" || file(web2, "never") != "" {
		t.Error("a rescue whose watched step didn't fail ran")
	}
	var rep struct {
		Hosts map[string]struct {
			Rescued bool
			Steps   []struct{ Step, Status string }
		}
	}
	raw, err := os.ReadFile(filepath.Join(w.dir, "run.json"))
	if err != nil || json.Unmarshal(raw, &rep) != nil {
		t.Fatalf("report: %v\n%s", err, raw)
	}
	if !rep.Hosts["web2"].Rescued || rep.Hosts["web1"].Rescued || !strings.Contains(string(raw), `"step": "app.restore"`) {
		t.Errorf("the report should mark web2 rescued and show the rescue:\n%s", raw)
	}

	if out := w.mustConn3x("state", "list"); strings.Contains(out, "restore") {
		t.Errorf("the rescue should be dropped from state:\n%s", out)
	}
	if out, code := w.conn3x("plan", "-no-color", "-detailed-exitcode", "-var=run=2", "-var=fail_on=web2"); code != 2 || !strings.Contains(out, `app__config["web2"] will be created`) || strings.Contains(out, "restore") || strings.Contains(out, `["web1"] must`) {
		t.Errorf("the next plan should catch web2 up and say nothing of the rescue (exit %d):\n%s", code, out)
	}
}
