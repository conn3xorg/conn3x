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

type fileVars struct {
	Content, OnRemove, Port, KeyFile, KnownHosts string
	User, PasswordFile                           string
}

func TestFileLifecycle(t *testing.T) {
	h := startHost(t, "rocky10")
	w := newWorkdir(t, "file")
	vars := fileVars{Content: `Welcome to a Conn3x host\n`, Port: h.port, KeyFile: h.keyFile, KnownHosts: h.knownHosts}
	w.write(vars)

	out := w.mustConn3x("init", "-no-color")
	if strings.Contains(out, "registry") && strings.Contains(out, "conn3x") {
		t.Fatalf("init looked up conn3x in a registry:\n%s", out)
	}

	out = w.mustConn3x("plan", "-no-color")
	for _, want := range []string{`+ resource "conn3x_file" "motd"`, "1 to add"} {
		if !strings.Contains(out, want) {
			t.Fatalf("plan missing %q:\n%s", want, out)
		}
	}

	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if got := h.exec("", "cat", "/etc/motd"); got != "Welcome to a Conn3x host\n" {
		t.Fatalf("/etc/motd = %q", got)
	}

	if out = w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
		t.Fatalf("second plan is not empty:\n%s", out)
	}

	h.exec("", "sh", "-c", "echo hacked > /etc/motd")
	out = w.mustConn3x("plan", "-no-color")
	for _, want := range []string{`~ resource "conn3x_file" "motd"`, "1 to change", "hacked"} {
		if !strings.Contains(out, want) {
			t.Fatalf("drift plan missing %q:\n%s", want, out)
		}
	}
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if got := h.exec("", "cat", "/etc/motd"); got != "Welcome to a Conn3x host\n" {
		t.Fatalf("drift not repaired: /etc/motd = %q", got)
	}

	// Removing the resource forgets the file and leaves it on the host.
	if err := writeEmpty(w); err != nil {
		t.Fatal(err)
	}
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if got := h.exec("", "cat", "/etc/motd"); got != "Welcome to a Conn3x host\n" {
		t.Fatalf("file changed after removing the resource: %q", got)
	}
}

func TestFileUnknownHostKeyFailsApply(t *testing.T) {
	h := startHost(t, "rocky10")
	w := newWorkdir(t, "file")
	empty := t.TempDir() + "/known_hosts"
	vars := fileVars{Content: "x", Port: h.port, KeyFile: h.keyFile, KnownHosts: empty}
	if err := touch(empty); err != nil {
		t.Fatal(err)
	}
	w.write(vars)
	w.mustConn3x("init", "-no-color")
	// Plan itself never contacts a host for a new resource, so apply is where
	// the unknown key must stop it.
	out, code := w.conn3x("apply", "-auto-approve", "-no-color")
	if code == 0 {
		t.Fatalf("apply succeeded against an unknown host key:\n%s", out)
	}
	if !strings.Contains(out, "127.0.0.1:"+h.port) || !strings.Contains(out, "known_hosts") {
		t.Fatalf("error does not name the host and known_hosts file:\n%s", out)
	}
	if got := h.exec("", "cat", "/etc/motd"); got == "x" {
		t.Fatal("file was written despite the host key failure")
	}
}

func TestFileWithSudoPassword(t *testing.T) {
	h := startHost(t, "rocky10")
	// A deploy user whose sudo needs a password, logging in with the test key.
	// sshd skips PAM so non-root logins work in rootless CI containers, where
	// PAM's account helper can't run; sudo still checks the password with PAM.
	h.exec("", "sh", "-c", `useradd -m deploy && echo 'deploy:Deploy-Pass-123' | chpasswd &&
echo 'deploy ALL=(ALL) ALL' > /etc/sudoers.d/deploy && chmod 440 /etc/sudoers.d/deploy &&
mkdir -p -m 700 /home/deploy/.ssh && cp /root/.ssh/authorized_keys /home/deploy/.ssh/ &&
chown -R deploy:deploy /home/deploy/.ssh &&
echo 'UsePAM no' > /etc/ssh/sshd_config.d/00-conn3x-test.conf && systemctl restart sshd`)
	pw := filepath.Join(t.TempDir(), "sudo-pass")
	if err := os.WriteFile(pw, []byte("Deploy-Pass-123\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	w := newWorkdir(t, "file")
	w.write(fileVars{Content: `managed through sudo\n`, Port: h.port, KeyFile: h.keyFile, KnownHosts: h.knownHosts, User: "deploy", PasswordFile: pw})
	w.mustConn3x("init", "-no-color")
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if got := h.exec("", "cat", "/etc/motd"); got != "managed through sudo\n" {
		t.Fatalf("/etc/motd = %q", got)
	}
	if owner := strings.TrimSpace(h.exec("", "stat", "-c", "%U", "/etc/motd")); owner != "root" {
		t.Fatalf("/etc/motd owner = %s, want root", owner)
	}
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
		t.Fatalf("plan through sudo is not empty:\n%s", out)
	}

	// The wrong password stops apply with a clear error.
	if err := os.WriteFile(pw, []byte("wrong\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	w.write(fileVars{Content: `changed\n`, Port: h.port, KeyFile: h.keyFile, KnownHosts: h.knownHosts, User: "deploy", PasswordFile: pw})
	out, code := w.conn3x("apply", "-auto-approve", "-no-color")
	if code == 0 || !strings.Contains(out, "incorrect password") {
		t.Fatalf("apply with a wrong sudo password: exit %d\n%s", code, out)
	}
}
