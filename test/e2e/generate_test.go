// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// conn3x generate step prints steps for what a host already has; pasted
// into a circuit, they import with nothing to change and the next plan is
// empty. Content that isn't text, and write-only content, stays out of the
// output, and an object the host doesn't have is an error.
func TestGenerateStep(t *testing.T) {
	h := startHost(t, "rocky10")
	h.exec("Welcome ${user}\n", "sh", "-c", "cat > /etc/motd && chmod 0640 /etc/motd && chgrp wheel /etc/motd")
	h.exec("", "sh", "-c", "head -c 64 /dev/urandom > /etc/blob")
	h.exec("s3cret-token\n", "sh", "-c", "cat > /etc/app-token && chmod 0600 /etc/app-token")
	h.exec("", "dnf", "-y", "-q", "install", "tree")
	h.exec("", "useradd", "-s", "/bin/sh", "deploy")

	w := newWorkdir(t, "generate")
	gen := func(args ...string) string {
		t.Helper()
		base := []string{"generate", "step", "-host", "127.0.0.1", "-port", h.port, "-user", "root",
			"-private-key-file", h.keyFile, "-known-hosts-file", h.knownHosts}
		out, code := w.conn3x(append(base, args...)...)
		if code != 0 {
			t.Fatalf("generate %v exited %d:\n%s", args, code, out)
		}
		t.Logf("generate %v:\n%s", args, out)
		return out
	}
	steps := gen("file", "path=/etc/motd") + gen("package", "name=tree") +
		gen("service", "name=sshd") + gen("user", "name=deploy")
	if !strings.Contains(steps, `step "etc_motd"`) || !strings.Contains(steps, `"wheel"`) || !strings.Contains(steps, "Welcome $${user}") {
		t.Fatalf("the file step doesn't say what the host has:\n%s", steps)
	}

	if out := gen("file", "path=/etc/blob"); !strings.Contains(out, "isn't UTF-8") || !strings.Contains(out, `content_wo = "REPLACE ME"`) {
		t.Fatalf("binary content should become a placeholder:\n%s", out)
	}
	if out := gen("-write-only", "-name", "token", "file", "path=/etc/app-token"); strings.Contains(out, "s3cret") || !strings.Contains(out, `content_wo = "REPLACE ME"`) {
		t.Fatalf("write-only content reached the output:\n%s", out)
	}
	out, code := w.conn3x("generate", "step", "-host", "127.0.0.1", "-port", h.port, "-user", "root",
		"-private-key-file", h.keyFile, "-known-hosts-file", h.knownHosts, "file", "path=/etc/not-here")
	if code != 1 || !strings.Contains(out, "127.0.0.1 doesn't have file /etc/not-here") {
		t.Fatalf("a missing file should be an error (exit %d):\n%s", code, out)
	}

	w.writeAs("main.circuit.hcl", struct{ Port, KeyFile, KnownHosts string }{h.port, h.keyFile, h.knownHosts})
	path := filepath.Join(w.dir, "main.circuit.hcl")
	circuit, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(strings.Replace(string(circuit), "# steps", steps, 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	w.mustConn3x("init", "-no-color")
	out = w.mustConn3x("plan", "-no-color")
	t.Logf("first plan:\n%s", out)
	// sysctl keeps a setting in its own file, so adopting one writes it.
	if !strings.Contains(out, "Plan: 4 to import, 0 to add, 1 to change, 0 to destroy.") || !strings.Contains(out, "conn3x_sysctl.box__net_ipv4_ip_forward[\"box\"] will be updated in-place") {
		t.Fatalf("the generated steps should import, with only the sysctl file to write:\n%s", out)
	}
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
		t.Fatalf("the plan after import isn't empty:\n%s", out)
	}
}

// A file on a host can carry terminal escape sequences. A terminal hides
// them and leaves them out of copied text, so generate must not print them:
// "$<escape>{" would paste as a live "${", and an "EOT" with one inside
// would end the heredoc early.
func TestGenerateStepKeepsEscapeSequencesOffTheTerminal(t *testing.T) {
	h := startHost(t, "ubuntu2404")
	h.exec("ok\n$\x1b[m{file(\"/etc/hostname\")}\n", "sh", "-c", "cat > /tmp/gen-interp")
	h.exec("ok\nEO\x1b[mT\nimport = false\n", "sh", "-c", "cat > /tmp/gen-eot")
	w := newWorkdir(t, "generate")
	sgr := regexp.MustCompile("\x1b\\[[0-9;]*m")
	for _, path := range []string{"/tmp/gen-interp", "/tmp/gen-eot"} {
		out, code := w.conn3x("generate", "step", "-host", "127.0.0.1", "-port", h.port, "-user", "root",
			"-private-key-file", h.keyFile, "-known-hosts-file", h.knownHosts, "file", "path="+path)
		if code != 0 {
			t.Fatalf("generate %s exited %d:\n%s", path, code, out)
		}
		if strings.Contains(out, "\x1b") {
			t.Errorf("generate %s printed an escape character:\n%q", path, out)
		}
		// What the operator would copy from the screen.
		if copied := sgr.ReplaceAllString(out, ""); strings.Contains(copied, "${file(") || strings.Contains(copied, "\nEOT\nimport = false") {
			t.Errorf("generate %s: the step copied from a terminal isn't the one printed:\n%s", path, copied)
		}
	}
}

// generate steps lists what a host has, and prints import steps for the
// objects that match, which plan as imports with nothing to change.
func TestGenerateSteps(t *testing.T) {
	h := startHost(t, "ubuntu2404")
	h.exec("", "sh", "-c", "useradd -m -u 1500 -s /bin/sh alice && useradd -m -u 1501 -s /bin/sh bob")
	w := newWorkdir(t, "generate")
	gen := func(args ...string) (string, int) {
		t.Helper()
		base := []string{"generate", "steps", "-host", "127.0.0.1", "-port", h.port, "-user", "root",
			"-private-key-file", h.keyFile, "-known-hosts-file", h.knownHosts}
		return w.conn3x(append(base, args...)...)
	}
	list, code := gen("users")
	if code != 0 || !strings.Contains(list, "alice\n") || !strings.Contains(list, "bob\n") || strings.Contains(list, "root\n") {
		t.Fatalf("users list (exit %d):\n%s", code, list)
	}
	if pkgs, code := gen("packages"); code != 0 || !strings.Contains(pkgs, "openssh-server\n") {
		t.Fatalf("packages list (exit %d):\n%s", code, pkgs)
	}
	steps, code := gen("-match", "alice,bob", "users")
	if code != 0 || !strings.Contains(steps, `step "alice"`) || !strings.Contains(steps, `step "bob"`) || strings.Count(steps, "import = true") != 2 {
		t.Fatalf("user steps (exit %d):\n%s", code, steps)
	}
	pkg, code := gen("-match", "openssh-server", "packages")
	if code != 0 {
		t.Fatalf("package step (exit %d):\n%s", code, pkg)
	}
	// A setting someone put in sysctl.d, at the value the kernel has.
	h.exec("", "sh", "-c", "echo \"net.ipv4.ip_forward = $(cat /proc/sys/net/ipv4/ip_forward)\" > /etc/sysctl.d/90-local.conf && echo '# kernel.x = 1' >> /etc/sysctl.d/90-local.conf")
	if list, code := gen("sysctl"); code != 0 || !strings.Contains(list, "net.ipv4.ip_forward = ") || strings.Contains(list, "kernel.x") {
		t.Fatalf("sysctl list (exit %d):\n%s", code, list)
	}
	sysctl, code := gen("-match", "net.ipv4.ip_forward", "sysctl")
	if code != 0 || !strings.Contains(sysctl, "sysctl {") || !strings.Contains(sysctl, `name  = "net.ipv4.ip_forward"`) {
		t.Fatalf("sysctl step (exit %d):\n%s", code, sysctl)
	}
	if out, code := gen("-match", "nothing-like-this-*", "packages"); code != 1 || !strings.Contains(out, "matches none") {
		t.Fatalf("a match for nothing (exit %d):\n%s", code, out)
	}

	w.writeAs("main.circuit.hcl", struct{ Port, KeyFile, KnownHosts string }{h.port, h.keyFile, h.knownHosts})
	path := filepath.Join(w.dir, "main.circuit.hcl")
	circuit, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(strings.Replace(string(circuit), "# steps", steps+"\n"+pkg+"\n"+sysctl, 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	w.mustConn3x("init", "-no-color")
	out := w.mustConn3x("plan", "-no-color")
	// sysctl keeps a setting in its own file, so adopting one writes it.
	if !strings.Contains(out, "Plan: 4 to import, 0 to add, 1 to change, 0 to destroy.") || !strings.Contains(out, "conn3x_sysctl.box__net_ipv4_ip_forward[\"box\"] will be updated in-place") {
		t.Fatalf("the generated steps should import, with only the sysctl file to write:\n%s", out)
	}
}
