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
