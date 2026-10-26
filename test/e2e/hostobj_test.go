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

type hostObjVars struct{ PortA, PortB, KeyA, KnownHosts string }

// A host can be an object whose own settings override the circuit's ssh
// block: here b listens on another port.
func TestHostObjectsOverrideSSH(t *testing.T) {
	a, b := startHost(t, "rocky10"), startHost(t, "debian13")
	// b accepts a's key, so one private_key_file reaches both.
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

	w := newWorkdir(t, "hostobj")
	w.writeAs("main.circuit.hcl", hostObjVars{a.port, b.port, a.keyFile, known})
	w.mustConn3x("init", "-no-color")
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	for name, h := range map[string]*host{"a": a, "b": b} {
		if got := h.exec("", "cat", "/etc/conn3x-name"); got != name+"\n" {
			t.Fatalf("host %s has %q", name, got)
		}
	}
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
		t.Fatalf("plan after apply:\n%s", out)
	}
}

// An ssh setting only the ssh block takes, such as become, fails validate
// instead of silently doing nothing.
func TestHostObjectUnknownFieldFailsValidate(t *testing.T) {
	w := &workdir{t: t, dir: t.TempDir()}
	src := `circuit "app" {
  hosts = { web1 = { address = "192.0.2.10", become = true } }
  ssh {
    user = "root"
  }
  step "motd" {
    file {
      path    = "/etc/motd"
      content = "hi"
    }
  }
}
`
	if err := os.WriteFile(filepath.Join(w.dir, "main.tf"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	w.mustConn3x("init", "-no-color")
	out, code := w.conn3x("validate", "-no-color")
	if code == 0 || !strings.Contains(out, `"become"`) || strings.Count(out, "Unsupported field in host object") != 1 {
		t.Fatalf("want one error naming become, got exit %d:\n%s", code, out)
	}
}
