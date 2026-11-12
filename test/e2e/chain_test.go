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
