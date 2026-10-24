// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

// Package e2e drives the real conn3x binary against managed hosts running in
// Podman containers. Run with: go test -tags e2e ./test/e2e/...
package e2e

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"text/template"
	"time"

	gossh "golang.org/x/crypto/ssh"
)

var conn3xBin string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "conn3x-e2e-bin")
	if err != nil {
		panic(err)
	}
	conn3xBin = filepath.Join(dir, "conn3x")
	_, here, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(here), "..", "..")
	build := exec.Command("bash", "scripts/build-conn3x.sh", conn3xBin)
	build.Dir = root
	build.Stdout, build.Stderr = os.Stdout, os.Stderr
	if err := build.Run(); err != nil {
		panic(fmt.Sprintf("building conn3x: %v", err))
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// host is a running container that accepts SSH as root with a test key.
type host struct {
	t          *testing.T
	container  string
	port       string
	keyFile    string
	knownHosts string
}

func startHost(t *testing.T, image string) *host {
	t.Helper()
	_, here, _, _ := runtime.Caller(0)
	imageDir := filepath.Join(filepath.Dir(here), "..", "images", image)
	tag := "localhost/conn3x-e2e-" + image
	run(t, "podman", "build", "-q", "-t", tag, imageDir)

	// Podman's default capabilities differ between versions. A real host's
	// root can read /etc/shadow (DAC_OVERRIDE) and write audit records, and
	// PAM needs both to let non-root users log in, so grant them explicitly.
	id := strings.TrimSpace(run(t, "podman", "run", "-d", "--rm", "--systemd=always",
		"--cap-add", "DAC_OVERRIDE,AUDIT_WRITE", "-p", "127.0.0.1::22", tag))
	t.Cleanup(func() {
		if t.Failed() {
			// Show what sshd and the rest of the host logged, to explain the failure.
			out, _ := exec.Command("podman", "exec", id, "journalctl", "--no-pager", "-n", "80").CombinedOutput()
			t.Logf("journal from %s:\n%s", image, out)
			diag, _ := exec.Command("podman", "exec", id, "sh", "-c",
				"ls -ln /etc/shadow /etc/passwd /usr/sbin/unix_chkpwd; grep -E '^Cap(Eff|Bnd)' /proc/self/status; cat /proc/self/uid_map").CombinedOutput()
			t.Logf("host details:\n%s", diag)
		}
		_ = exec.Command("podman", "rm", "-f", id).Run()
	})
	mapping := strings.TrimSpace(run(t, "podman", "port", id, "22/tcp"))
	h := &host{t: t, container: id, port: mapping[strings.LastIndex(mapping, ":")+1:]}

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	block, err := gossh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	h.keyFile = filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(h.keyFile, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	signer, _ := gossh.NewSignerFromKey(priv)
	h.exec(string(gossh.MarshalAuthorizedKey(signer.PublicKey())), "sh", "-c", "cat > /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys")

	// Let systemd finish booting first: services that start late can
	// restart sshd and drop a connection mid-handshake.
	_ = exec.Command("podman", "exec", id, "timeout", "60", "systemctl", "is-system-running", "--wait").Run()

	// Wait for sshd, then record its key the way an admin would.
	var keys string
	for deadline := time.Now().Add(60 * time.Second); time.Now().Before(deadline); time.Sleep(500 * time.Millisecond) {
		out, err := exec.Command("ssh-keyscan", "-t", "ed25519", "-p", h.port, "127.0.0.1").Output()
		if err == nil && len(bytes.TrimSpace(out)) > 0 {
			keys = string(out)
			break
		}
	}
	if keys == "" {
		t.Fatal("sshd did not come up within 60s")
	}
	h.knownHosts = filepath.Join(dir, "known_hosts")
	if err := os.WriteFile(h.knownHosts, []byte(keys), 0o600); err != nil {
		t.Fatal(err)
	}
	return h
}

func (h *host) exec(stdin string, args ...string) string {
	h.t.Helper()
	cmd := exec.Command("podman", append([]string{"exec", "-i", h.container}, args...)...)
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	if err != nil {
		h.t.Fatalf("podman exec %v: %v\n%s", args, err, out)
	}
	return string(out)
}

func run(t *testing.T, name string, args ...string) string {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
	return string(out)
}

// workdir renders a testdata template into a fresh working directory.
type workdir struct {
	t   *testing.T
	dir string
	tpl *template.Template
}

func newWorkdir(t *testing.T, name string) *workdir {
	t.Helper()
	_, here, _, _ := runtime.Caller(0)
	matches, _ := filepath.Glob(filepath.Join(filepath.Dir(here), "testdata", name, "*.tmpl"))
	if len(matches) != 1 {
		t.Fatalf("testdata/%s needs exactly one template, found %v", name, matches)
	}
	tpl := template.Must(template.ParseFiles(matches[0]))
	return &workdir{t: t, dir: t.TempDir(), tpl: tpl}
}

func (w *workdir) write(data any) {
	w.t.Helper()
	var b bytes.Buffer
	if err := w.tpl.Execute(&b, data); err != nil {
		w.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(w.dir, "main.tf"), b.Bytes(), 0o644); err != nil {
		w.t.Fatal(err)
	}
}

func (w *workdir) conn3x(args ...string) (string, int) {
	w.t.Helper()
	cmd := exec.Command(conn3xBin, args...)
	cmd.Dir = w.dir
	cmd.Env = append(os.Environ(), "TF_IN_AUTOMATION=1", "CHECKPOINT_DISABLE=1", "TF_CLI_CONFIG_FILE=")
	out, err := cmd.CombinedOutput()
	code := 0
	if exit, ok := err.(*exec.ExitError); ok {
		code = exit.ExitCode()
	} else if err != nil {
		w.t.Fatalf("running conn3x %v: %v", args, err)
	}
	return string(out), code
}

func (w *workdir) mustConn3x(args ...string) string {
	w.t.Helper()
	out, code := w.conn3x(args...)
	if code != 0 {
		w.t.Fatalf("conn3x %v exited %d:\n%s", args, code, out)
	}
	return out
}
