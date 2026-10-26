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
	User                      string // logs in as this user with become; empty is root
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
	w.writeAs("main.circuit.hcl", agentVars{h.port, h.keyFile, h.knownHosts, 1, ""})
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
	w.writeAs("main.circuit.hcl", agentVars{h.port, h.keyFile, h.knownHosts, 1, ""})
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
	w.writeAs("main.circuit.hcl", agentVars{h.port, h.keyFile, h.knownHosts, 2, ""})
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

// addDeploy adds a deploy user with passwordless sudo, logging in with the
// test key, with extra sudoers defaults and sshd settings. sshd and sudo
// skip PAM's account checks, whose helper can't run in rootless CI
// containers; sudo itself is real.
func addDeploy(h *host, sudoDefaults, sshd string) {
	h.t.Helper()
	h.exec("", "sh", "-c", `useradd -m deploy && echo 'deploy:Deploy-Pass-123' | chpasswd &&
printf '%s\n' 'Defaults:deploy !pam_acct_mgmt, !pam_session`+sudoDefaults+`' 'deploy ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/deploy &&
chmod 440 /etc/sudoers.d/deploy && visudo -cq &&
mkdir -p -m 700 /home/deploy/.ssh && cp /root/.ssh/authorized_keys /home/deploy/.ssh/ &&
chown -R deploy:deploy /home/deploy/.ssh &&
printf '%s\n' 'UsePAM no' '`+sshd+`' > /etc/ssh/sshd_config.d/00-conn3x-test.conf && systemctl restart sshd`)
}

func TestAgentBecome(t *testing.T) {
	h := startHost(t, "rocky10")
	addDeploy(h, "", "")
	w := newWorkdir(t, "agent")
	w.env = append(w.env, "CONN3X_AGENT=require")
	w.writeAs("main.circuit.hcl", agentVars{h.port, h.keyFile, h.knownHosts, 1, "deploy"})
	w.mustConn3x("init", "-no-color")
	w.mustConn3x("apply", "-auto-approve", "-no-color")

	// The command ran as root under the agent, cached where only root can
	// change it, and nothing of root's landed in the login user's home.
	if got := h.runner(); !strings.HasPrefix(got, "/root/.cache/conn3x/agent-") {
		t.Fatalf("the command ran under %q, want the agent in root's cache", got)
	}
	if got := strings.TrimSpace(h.exec("", "stat", "-c", "%U %a", "/root/.cache/conn3x", "/etc/conn3x-runner")); got != "root 700\nroot 644" {
		t.Fatalf("cache and output: %q", got)
	}
	if got := h.exec("", "find", "/home/deploy", "-user", "root"); got != "" {
		t.Fatalf("root's files in the login user's home:\n%s", got)
	}
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
		t.Fatalf("plan after apply:\n%s", out)
	}
}

// When sudo keeps the login user's XDG_CACHE_HOME, and maybe their HOME,
// root writes nothing in their home. With their HOME it caches its agent
// in /var/tmp/conn3x-0.
func TestAgentBecomeKeepsOutOfUserHome(t *testing.T) {
	for _, tc := range []struct{ keep, cache string }{
		{"HOME XDG_CACHE_HOME", "/var/tmp/conn3x-0"},
		{"XDG_CACHE_HOME", "/root/.cache/conn3x"},
	} {
		t.Run(tc.keep, func(t *testing.T) {
			h := startHost(t, "rocky10")
			addDeploy(h, `, !always_set_home, env_keep += "`+tc.keep+`"`, "SetEnv XDG_CACHE_HOME=/home/deploy/.cache")
			w := newWorkdir(t, "agent")
			w.env = append(w.env, "CONN3X_AGENT=require")
			w.writeAs("main.circuit.hcl", agentVars{h.port, h.keyFile, h.knownHosts, 1, "deploy"})
			w.mustConn3x("init", "-no-color")
			w.mustConn3x("apply", "-auto-approve", "-no-color")

			if got := h.runner(); !strings.HasPrefix(got, tc.cache+"/agent-") {
				t.Fatalf("the command ran under %q, want the agent in %s", got, tc.cache)
			}
			if got := strings.TrimSpace(h.exec("", "stat", "-c", "%U %a", tc.cache)); got != "root 700" {
				t.Fatalf("cache: %q", got)
			}
			if got := h.exec("", "find", "/home/deploy", "-newer", "/home/deploy/.ssh/authorized_keys", "-o", "-user", "root", "-o", "-name", ".cache"); got != "" {
				t.Fatalf("written in the login user's home:\n%s", got)
			}
		})
	}
}
