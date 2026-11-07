// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"os"
	"path/filepath"
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
