// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type loopVars struct {
	PortA, PortB, Key, KnownHosts, SuffixA string
	Users                                  []string
}

// A step with for_each repeats on every host; handlers follow each host.
func TestStepLoops(t *testing.T) {
	a, b := startHost(t, "rocky10"), startHost(t, "rocky10")
	pub := strings.TrimSpace(run(t, "ssh-keygen", "-y", "-f", a.keyFile))
	b.exec(pub+"\n", "sh", "-c", "cat > /root/.ssh/authorized_keys")
	known := filepath.Join(t.TempDir(), "known_hosts")
	var lines []byte
	for _, h := range []*host{a, b} {
		data, err := os.ReadFile(h.knownHosts)
		if err != nil {
			t.Fatal(err)
		}
		lines = append(lines, data...)
	}
	if err := os.WriteFile(known, lines, 0o600); err != nil {
		t.Fatal(err)
	}
	vars := loopVars{a.port, b.port, a.keyFile, known, "", []string{"alice", "bob"}}

	w := newWorkdir(t, "loops")
	w.writeAs("main.circuit.hcl", vars)
	w.mustConn3x("init", "-no-color")
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	for name, h := range map[string]*host{"a": a, "b": b} {
		if got := h.exec("", "cat", "/etc/conn3x-issue"); got != name+": welcome\n" {
			t.Fatalf("host %s /etc/conn3x-issue = %q", name, got)
		}
		h.exec("", "id", "alice")
		h.exec("", "id", "bob")
	}
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
		t.Fatalf("second plan:\n%s", out)
	}

	// A change for host a only: only a's items and a's handler change.
	vars.SuffixA = "!"
	w.writeAs("main.circuit.hcl", vars)
	out := w.mustConn3x("plan", "-no-color")
	if !strings.Contains(out, `conn3x_file.app__conf["a/motd"] will be updated`) || strings.Contains(out, `conn3x_file.app__conf["b/motd"] will be`) {
		t.Fatalf("change for host a planned:\n%s", out)
	}
	if !strings.Contains(out, `conn3x_service_action.app__reload["a"] must be replaced`) || strings.Contains(out, `conn3x_service_action.app__reload["b"] must be`) {
		t.Fatalf("handler should follow host a only:\n%s", out)
	}
	w.mustConn3x("apply", "-auto-approve", "-no-color")

	// Dropping an item removes just that item, on every host.
	vars.Users = []string{"alice"}
	w.writeAs("main.circuit.hcl", vars)
	out = w.mustConn3x("plan", "-no-color")
	for _, want := range []string{`conn3x_user.app__users["a/bob"] will be destroyed`, `conn3x_user.app__users["b/bob"] will be destroyed`, "0 to add, 0 to change, 2 to destroy"} {
		if !strings.Contains(out, want) {
			t.Fatalf("dropping bob: missing %q in\n%s", want, out)
		}
	}
}

// In a looping step the circuit's ssh block still sees the host as each.
// Planning new steps doesn't connect, so no host is needed.
func TestLoopingStepSSHMeansTheHost(t *testing.T) {
	w := &workdir{t: t, dir: t.TempDir()}
	src := `circuit "app" {
  hosts = toset(["192.0.2.10"])
  ssh {
    user = "u-${each.key}"
  }
  step "conf" {
    for_each = ["x"]
    file {
      path    = "/etc/${item.value}"
      content = "x"
    }
  }
}
`
	if err := os.WriteFile(filepath.Join(w.dir, "main.tf"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	w.mustConn3x("init", "-no-color")
	out := w.mustConn3x("plan", "-no-color")
	if !strings.Contains(out, `user = "u-192.0.2.10"`) {
		t.Fatalf("want the host's key in ssh.user:\n%s", out)
	}
}
