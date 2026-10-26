// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type agentVars struct {
	Port, KeyFile, KnownHosts string
	Round                     int
}

// runner is the program that ran the agent step's command on h.
func (h *host) runner() string {
	h.t.Helper()
	return strings.TrimSpace(h.exec("", "cat", "/etc/conn3x-runner"))
}

func TestAgentNoexecFallback(t *testing.T) {
	// ~/.cache and /var/tmp won't run programs, so the agent goes to
	// ~/.conn3x, the next place it tries.
	h := startHostWith(t, "rocky10", "--tmpfs", "/root/.cache:rw,noexec", "--tmpfs", "/var/tmp:rw,noexec")
	w := newWorkdir(t, "agent")
	w.env = append(w.env, "CONN3X_AGENT=on")
	w.writeAs("main.circuit.hcl", agentVars{h.port, h.keyFile, h.knownHosts, 1})
	w.mustConn3x("init", "-no-color")
	w.mustConn3x("apply", "-auto-approve", "-no-color")

	if got := h.runner(); !strings.HasPrefix(got, "/root/.conn3x/agent-") {
		t.Fatalf("the command ran under %q, want the agent in /root/.conn3x", got)
	}
	if left := h.exec("", "find", "/root/.cache", "/var/tmp", "/root/.conn3x", "-name", ".canary.*", "-o", "-name", ".agent.*"); left != "" {
		t.Fatalf("left behind:\n%s", left)
	}
	if got := h.exec("", "sh", "-c", "ls -A /root/.cache/conn3x | grep -v '^.lock$' || true"); got != "" {
		t.Fatalf("the noexec cache holds %q", got)
	}
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
		t.Fatalf("plan after apply:\n%s", out)
	}
}

func TestAgentUpgradeSwitchesBinary(t *testing.T) {
	h := startHost(t, "debian13")
	w := newWorkdir(t, "agent")
	w.env = append(w.env, "CONN3X_AGENT=on")
	w.writeAs("main.circuit.hcl", agentVars{h.port, h.keyFile, h.knownHosts, 1})
	w.mustConn3x("init", "-no-color")
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	first := h.runner()
	if !strings.HasPrefix(first, "/root/.cache/conn3x/agent-") {
		t.Fatalf("the command ran under %q, want the cached agent", first)
	}

	// A newer conn3x brings its own agent, and the old one is kept.
	_, here, _, _ := runtime.Caller(0)
	w.bin = filepath.Join(t.TempDir(), "conn3x")
	build := exec.Command("bash", "scripts/build-conn3x.sh", w.bin, "-ldflags=-X github.com/opentofu/opentofu/internal/conn3x/version.Version=9.9.9")
	build.Dir = filepath.Join(filepath.Dir(here), "..", "..")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building the newer conn3x: %v\n%s", err, out)
	}
	w.writeAs("main.circuit.hcl", agentVars{h.port, h.keyFile, h.knownHosts, 2})
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	second := h.runner()
	if !strings.HasPrefix(second, "/root/.cache/conn3x/agent-9.9.9-") {
		t.Fatalf("after upgrading the command ran under %q, want the 9.9.9 agent", second)
	}
	cached := strings.Fields(h.exec("", "sh", "-c", "ls /root/.cache/conn3x"))
	want := []string{filepath.Base(first), filepath.Base(second)}
	if len(cached) != 2 || !strings.Contains(strings.Join(cached, " "), want[0]) || !strings.Contains(strings.Join(cached, " "), want[1]) {
		t.Fatalf("cache holds %q, want %q", cached, want)
	}
}
