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
// the lockout here takes 3 to 6 seconds to bite. Takes about seven minutes.
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
	sw.Lockout = false
	w.writeAs("main.circuit.hcl", sw)
	if out, code := w.conn3x("plan", "-detailed-exitcode", "-no-color"); code != 0 {
		t.Fatalf("plan after the rollback exited %d:\n%s", code, out)
	}

}
