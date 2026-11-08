// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// eosVars fill testdata/eos.
type eosVars struct {
	Host, Port, KeyFile, KnownHosts string
	ConfirmAfter                    string // empty: the default, 30s
	Lockout                         bool
}

// eosSwitch is a cEOS-lab container someone started by hand: the image can't
// be redistributed, so CI has none and this test skips there. Set
// CONN3X_EOS_E2E to host:port of its SSH, and CONN3X_EOS_KEY to a key the
// switch's admin user (privilege 15) takes.
func eosSwitch(t *testing.T) eosVars {
	t.Helper()
	addr, key := os.Getenv("CONN3X_EOS_E2E"), os.Getenv("CONN3X_EOS_KEY")
	if addr == "" || key == "" {
		t.Skip("set CONN3X_EOS_E2E=host:port and CONN3X_EOS_KEY to run against a cEOS-lab switch")
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	known := filepath.Join(t.TempDir(), "known_hosts")
	scan := run(t, "ssh-keyscan", "-p", port, "-t", "ed25519,rsa", host)
	if err := os.WriteFile(known, []byte(scan), 0o600); err != nil {
		t.Fatal(err)
	}
	return eosVars{Host: host, Port: port, KeyFile: key, KnownHosts: known}
}

// cli runs EOS CLI input on the switch, as a person would by hand.
func (v eosVars) cli(t *testing.T, input string) (string, error) {
	t.Helper()
	cmd := exec.Command("ssh", "-p", v.Port, "-i", v.KeyFile, "-o", "UserKnownHostsFile="+v.KnownHosts,
		"-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "admin@"+v.Host)
	cmd.Stdin = strings.NewReader(input)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (v eosVars) mustCLI(t *testing.T, input string) string {
	t.Helper()
	out, err := v.cli(t, input)
	if err != nil {
		t.Fatalf("switch CLI %q: %v\n%s", input, err, out)
	}
	return out
}

func TestEOSApplyDriftAndAbort(t *testing.T) {
	sw := eosSwitch(t)
	sw.ConfirmAfter = "5s" // the least allowed; nothing here cuts SSH
	w := newWorkdir(t, "eos")
	w.writeAs("main.circuit.hcl", sw)
	w.mustConn3x("init", "-no-color")
	w.mustConn3x("apply", "-auto-approve", "-no-color")

	running := sw.mustCLI(t, "show running-config\n")
	for _, want := range []string{"hostname c3x-leaf1", "vlan 10\n   name users", "vlan 20\n   name voice", "interface Loopback0\n   description managed by conn3x"} {
		if !strings.Contains(running, want) {
			t.Fatalf("running-config is missing %q:\n%s", want, running)
		}
	}
	if startup := sw.mustCLI(t, "show startup-config\n"); !strings.Contains(startup, "hostname c3x-leaf1") {
		t.Fatalf("the change wasn't saved to startup-config:\n%s", startup)
	}
	if out, code := w.conn3x("plan", "-detailed-exitcode", "-no-color"); code != 0 || !strings.Contains(out, "No changes.") {
		t.Fatalf("second plan exited %d:\n%s", code, out)
	}

	sw.mustCLI(t, "configure\nhostname by-hand\nend\n")
	out, code := w.conn3x("drift", "-no-color")
	if code != 2 || !strings.Contains(out, "conn3x_eos_hostname.eos__name") {
		t.Fatalf("drift after a hand change exited %d:\n%s", code, out)
	}
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if out, code := w.conn3x("plan", "-detailed-exitcode", "-no-color"); code != 0 {
		t.Fatalf("plan after re-apply exited %d:\n%s", code, out)
	}

	// A line the switch refuses aborts the whole session: nothing changes.
	if err := os.WriteFile(filepath.Join(w.dir, "bad.circuit.hcl"), []byte(`circuit "bad" {
  hosts = { leaf1 = "`+sw.Host+`" }
  ssh {
    port             = `+sw.Port+`
    user             = "admin"
    private_key_file = "`+sw.KeyFile+`"
    known_hosts_file = "`+sw.KnownHosts+`"
  }
  step "half" {
    eos_config {
      parents = ["interface Loopback1"]
      lines   = ["description half done", "this is not a command"]
    }
  }
}
`), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, code := w.conn3x("apply", "-auto-approve", "-no-color"); code == 0 || !strings.Contains(out, "Nothing was changed") {
		t.Fatalf("an apply with a refused line exited %d:\n%s", code, out)
	}
	if running := sw.mustCLI(t, "show running-config\n"); strings.Contains(running, "Loopback1") {
		t.Fatalf("a refused session left part of itself behind:\n%s", running)
	}
	os.Remove(filepath.Join(w.dir, "bad.circuit.hcl"))
	if sessions := sw.mustCLI(t, "show configuration sessions\n"); strings.Contains(sessions, "conn3x-") {
		t.Fatalf("a conn3x session was left pending:\n%s", sessions)
	}

	w.mustConn3x("destroy", "-auto-approve", "-no-color")
	if running := sw.mustCLI(t, "show running-config\n"); strings.Contains(running, "vlan 10") || strings.Contains(running, "vlan 20") {
		t.Fatalf("destroy left the VLANs, whose on_remove defaults to delete:\n%s", running)
	}
}

// TestEOSLockoutRollsBack applies a change that stops new SSH logins. It
// can't be confirmed, so the switch has to roll it back on its own when the
// revert timer runs out. It runs with the default confirm_after, 30s, since
// the lockout here takes 3 to 6 seconds to bite. The circuit's other steps
// share the session, so they roll back with it. Takes about seven minutes.
func TestEOSLockoutRollsBack(t *testing.T) {
	sw := eosSwitch(t)
	w := newWorkdir(t, "eos")
	// A change that stops new SSH logins can't be confirmed, so the switch
	// rolls it back on its own when the revert timer runs out.
	sw.Lockout = true
	w.writeAs("main.circuit.hcl", sw)
	w.mustConn3x("init", "-no-color")
	if out, code := w.conn3x("apply", "-auto-approve", "-no-color"); code == 0 || !strings.Contains(out, "roll the change back on its own") {
		t.Fatalf("the lockout apply exited %d:\n%s", code, out)
	}
	deadline := time.Now().Add(8 * time.Minute)
	for {
		out, err := sw.cli(t, "show running-config section management ssh\n")
		if err == nil && !strings.Contains(out, "   shutdown") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the switch never rolled back the lockout (last: %v)\n%s", err, out)
		}
		time.Sleep(15 * time.Second)
	}
	// The steps before it shared its session, so they rolled back with it:
	// the next plan makes them again, and then there's nothing left to do.
	sw.Lockout = false
	w.writeAs("main.circuit.hcl", sw)
	out, code := w.conn3x("plan", "-detailed-exitcode", "-no-color")
	t.Logf("plan after the rollback exited %d: %s", code, lastLine(out, "Plan:"))
	if code != 2 || !strings.Contains(out, "conn3x_eos_commit.eos__commit") {
		t.Fatalf("plan after the rollback should redo the steps and the commit, exited %d:\n%s", code, out)
	}
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if out, code := w.conn3x("plan", "-detailed-exitcode", "-no-color"); code != 0 {
		t.Fatalf("plan after re-applying exited %d:\n%s", code, out)
	}
	if running := sw.mustCLI(t, "show running-config\n"); !strings.Contains(running, "hostname c3x-leaf1") || strings.Contains(running, "management ssh\n   shutdown") {
		t.Fatalf("after re-applying:\n%s", running)
	}

}

// lastLine is the last line of out that starts with prefix, after spaces.
func lastLine(out, prefix string) string {
	found := ""
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), prefix) {
			found = strings.TrimSpace(line)
		}
	}
	return found
}

// tenVars fill testdata/eos10: a hostname, a step per VLAN and a loopback.
type tenVars struct {
	eosVars
	Hostname string
	VLANs    []int
	Bad      int // the VLAN whose step is a line the switch refuses
}

func vlanRange(from, to int) []int {
	var out []int
	for i := from; i <= to; i++ {
		out = append(out, i)
	}
	return out
}

// TestEOSTenStepsOneCommit applies ten changed steps to one switch. They
// share one config session, so the apply waits confirm_after once, where
// slice 1 waited once per step. Destroying the circuit waits once too.
func TestEOSTenStepsOneCommit(t *testing.T) {
	sw := eosSwitch(t)
	sw.ConfirmAfter = "10s"
	v := tenVars{eosVars: sw, Hostname: "c3x-ten", VLANs: vlanRange(101, 108)}
	w := newWorkdir(t, "eos10")
	w.writeAs("main.circuit.hcl", v)
	w.mustConn3x("init", "-no-color")
	t.Cleanup(func() { w.conn3x("destroy", "-auto-approve", "-no-color") })

	out := w.mustConn3x("plan", "-no-color")
	if !strings.Contains(out, `conn3x_eos_commit.ten__commit["leaf1"] will be created`) || !strings.Contains(out, "12 to add") {
		t.Fatalf("plan should add ten steps, the commit and the removals commit:\n%s", out)
	}
	start := time.Now()
	out = w.mustConn3x("apply", "-auto-approve", "-no-color")
	took := time.Since(start)
	t.Logf("ten steps applied in %s with confirm_after %s", took.Round(100*time.Millisecond), sw.ConfirmAfter)
	if took >= 30*time.Second { // one step per session would wait 100 s
		t.Errorf("ten steps took %s: more than one confirm wait", took)
	}
	running := sw.mustCLI(t, "show running-config\n")
	for _, want := range []string{"hostname c3x-ten", "vlan 101\n   name ten101", "vlan 108\n   name ten108", "interface Loopback2\n   description ten steps"} {
		if !strings.Contains(running, want) {
			t.Fatalf("running-config is missing %q:\n%s", want, running)
		}
	}
	if startup := sw.mustCLI(t, "show startup-config\n"); !strings.Contains(startup, "vlan 108") {
		t.Fatalf("not saved to startup-config:\n%s", startup)
	}
	if out, code := w.conn3x("plan", "-detailed-exitcode", "-no-color"); code != 0 {
		t.Fatalf("second plan exited %d:\n%s", code, out)
	}

	// A hand change is drift in the step, not in the commit; the plan
	// changes the step and so the commit, and nothing else.
	sw.mustCLI(t, "configure\nvlan 103\n   name by-hand\nend\n")
	out, code := w.conn3x("drift", "-no-color")
	if code != 2 || !strings.Contains(out, `conn3x_eos_vlan.ten__v103`) || strings.Contains(out, "conn3x_eos_commit") {
		t.Fatalf("drift after a hand change exited %d:\n%s", code, out)
	}
	out = w.mustConn3x("plan", "-no-color")
	if !strings.Contains(out, `conn3x_eos_commit.ten__commit["leaf1"] will be updated in-place`) || !strings.Contains(out, "0 to add, 2 to change, 0 to destroy") {
		t.Fatalf("plan after a hand change:\n%s", out)
	}

	// One step changed and another removed: the change commits with the
	// circuit's commit, the removal in its own session after it.
	v.Hostname, v.VLANs = "c3x-ten2", vlanRange(101, 107)
	w.writeAs("main.circuit.hcl", v)
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	running = sw.mustCLI(t, "show running-config\n")
	if !strings.Contains(running, "hostname c3x-ten2") || strings.Contains(running, "vlan 108") || !strings.Contains(running, "vlan 103\n   name ten103") {
		t.Fatalf("after renaming, removing vlan 108 and undoing the hand change:\n%s", running)
	}
	if out, code := w.conn3x("plan", "-detailed-exitcode", "-no-color"); code != 0 {
		t.Fatalf("plan after the second apply exited %d:\n%s", code, out)
	}

	// Seven VLAN steps remove their VLAN on destroy, in one session.
	start = time.Now()
	w.mustConn3x("destroy", "-auto-approve", "-no-color")
	took = time.Since(start)
	t.Logf("destroy took %s with confirm_after %s", took.Round(100*time.Millisecond), sw.ConfirmAfter)
	if took >= 30*time.Second { // a session per removal would wait 70 s
		t.Errorf("destroy took %s: more than one confirm wait", took)
	}
	running = sw.mustCLI(t, "show running-config\n")
	for _, gone := range []string{"vlan 101", "vlan 107"} {
		if strings.Contains(running, gone) {
			t.Errorf("%s still on the switch after destroy", gone)
		}
	}
	if startup := sw.mustCLI(t, "show startup-config\n"); strings.Contains(startup, "vlan 101") {
		t.Errorf("removal not saved to startup-config")
	}
	if pending := sw.mustCLI(t, "show configuration sessions\n"); strings.Contains(pending, "conn3x-") && strings.Contains(pending, "pending") {
		t.Errorf("a conn3x session is left pending:\n%s", pending)
	}
}

// TestEOSRefusedStepLeavesNothing has the switch refuse step 5 of ten. The
// four steps before it are already in the session, and are dropped with it.
func TestEOSRefusedStepLeavesNothing(t *testing.T) {
	sw := eosSwitch(t)
	sw.ConfirmAfter = "5s"
	before := sw.mustCLI(t, "show running-config\n")
	v := tenVars{eosVars: sw, Hostname: "c3x-refused", VLANs: vlanRange(201, 208), Bad: 204}
	w := newWorkdir(t, "eos10")
	w.writeAs("main.circuit.hcl", v)
	w.mustConn3x("init", "-no-color")
	out, code := w.conn3x("apply", "-auto-approve", "-no-color")
	if code == 0 || !strings.Contains(out, "the lines earlier steps added in this apply were dropped too") || !strings.Contains(out, "% Invalid input") {
		t.Fatalf("an apply with a refused line in step 5 exited %d:\n%s", code, out)
	}
	running := sw.mustCLI(t, "show running-config\n")
	for _, gone := range []string{"c3x-refused", "vlan 201", "vlan 203", "Loopback3"} {
		if strings.Contains(running, gone) {
			t.Errorf("running-config has %q after the refused apply", gone)
		}
	}
	if stripComments(running) != stripComments(before) {
		t.Errorf("running-config changed:\nbefore\n%s\nafter\n%s", before, running)
	}
	if sessions := sw.mustCLI(t, "show configuration sessions\n"); strings.Contains(sessions, "conn3x-") {
		t.Fatalf("a conn3x session was left pending:\n%s", sessions)
	}
	w.mustConn3x("destroy", "-auto-approve", "-no-color")
}

func stripComments(config string) string {
	var b strings.Builder
	for _, line := range strings.Split(config, "\n") {
		if !strings.HasPrefix(line, "!") {
			b.WriteString(line + "\n")
		}
	}
	return b.String()
}

// TestEOSCleansUpACrashedRun leaves a pending conn3x session on the switch,
// as a run killed before its commit does. The next apply aborts it.
func TestEOSCleansUpACrashedRun(t *testing.T) {
	sw := eosSwitch(t)
	sw.ConfirmAfter = "5s"
	sw.mustCLI(t, "configure session conn3x-0000dead0000\nvlan 999\nend\n")
	if sessions := sw.mustCLI(t, "show configuration sessions\n"); !strings.Contains(sessions, "conn3x-0000dead0000") {
		t.Fatalf("no leftover session to clean up:\n%s", sessions)
	}
	v := tenVars{eosVars: sw, Hostname: "c3x-crash", VLANs: vlanRange(301, 301)}
	w := newWorkdir(t, "eos10")
	w.writeAs("main.circuit.hcl", v)
	w.mustConn3x("init", "-no-color")
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if sessions := sw.mustCLI(t, "show configuration sessions\n"); strings.Contains(sessions, "conn3x-0000dead0000") {
		t.Fatalf("the leftover session is still there:\n%s", sessions)
	}
	if running := sw.mustCLI(t, "show running-config\n"); strings.Contains(running, "vlan 999") || !strings.Contains(running, "vlan 301") {
		t.Fatalf("after cleaning up:\n%s", running)
	}
	w.mustConn3x("destroy", "-auto-approve", "-no-color")
}
