// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// becomeHost is a test host with the fake sudo in mode, and a file where
// the fake sudo logs every line it reads as a password.
func becomeHost(t *testing.T, mode string) (*testHost, string) {
	t.Helper()
	h := newTestHost(t)
	h.FakeSudo(t, mode)
	log := filepath.Join(t.TempDir(), "attempts")
	h.Env = append(h.Env, "FAKE_SUDO_LOG="+log)
	return h, log
}

// cachedAgent uploads the agent as the login user and returns what start
// needs to run it again.
func cachedAgent(t *testing.T, h *testHost) (dir, name, sum string) {
	t.Helper()
	if _, err := h.attach(t, Options{Upload: true, Version: testVersion, Payload: agentPayload(t)}); err != nil {
		t.Fatal(err)
	}
	raw, _ := testAgent()
	s := sha256.Sum256(raw)
	return h.cacheDir(), agentName(t), hex.EncodeToString(s[:])
}

// attempts are the lines the fake sudo read as passwords.
func attempts(t *testing.T, log string) []string {
	t.Helper()
	data, err := os.ReadFile(log)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
}

func startCommands(h *testHost) (out []string) {
	for _, c := range h.Commands() {
		if strings.HasPrefix(c, "exec sudo -S -p 'conn3x-sudo-") {
			out = append(out, c)
		}
	}
	return out
}

func TestBecomeAgentNoPassword(t *testing.T) {
	h, log := becomeHost(t, "nopasswd")
	c := dialServer(t, h.Server)
	// A password is set but sudo never asks, so it is never sent: a stray
	// line on the agent's stdin would break its first frame.
	b := &ssh.Become{Client: c, Password: []byte("s3cret")}
	a, err := Attach(ctx, c, Options{Upload: true, Version: testVersion, Payload: agentPayload(t), Become: b})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	res, err := a.Run(ctx, `printf '%s:' "$SUDO_USER"; cat`, []byte("payload"))
	if err != nil || string(res.Stdout) != "fake:payload" {
		t.Fatalf("got %q, %v (stderr %q)", res.Stdout, err, res.Stderr)
	}
	if got := startCommands(h); len(got) != 1 {
		t.Fatalf("started %d agents through sudo, want 1", len(got))
	}
	if got := attempts(t, log); len(got) != 0 {
		t.Fatalf("sudo was sent %d password lines", len(got))
	}
}

func TestBecomeAgentPassword(t *testing.T) {
	h, log := becomeHost(t, "password:s3cret")
	c := dialServer(t, h.Server)
	b := &ssh.Become{Client: c, Password: []byte("s3cret")}
	a, err := Attach(ctx, c, Options{Upload: true, Version: testVersion, Payload: agentPayload(t), Become: b})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	res, err := a.Run(ctx, `printf '%s:' "$SUDO_USER"; cat`, []byte("content\nwithout newline"))
	if err != nil || string(res.Stdout) != "fake:content\nwithout newline" {
		t.Fatalf("got %q, %v (stderr %q)", res.Stdout, err, res.Stderr)
	}
	if got := startCommands(h); len(got) != 1 {
		t.Fatalf("started %d agents through sudo, want 1", len(got))
	}
	// sudo read the password and nothing else, once per sudo it ran.
	for _, line := range attempts(t, log) {
		if line != "s3cret" {
			t.Fatalf("sudo read a line that is not the password")
		}
	}
}

func TestBecomeAgentWrongPassword(t *testing.T) {
	h, log := becomeHost(t, "nopasswd")
	dir, name, sum := cachedAgent(t, h)
	h.FakeSudo(t, "password:s3cret")
	c := dialServer(t, h.Server)

	begin := time.Now()
	_, err := start(ctx, c, dir, name, sum, &ssh.Become{Client: c, Password: []byte("wrong-pass")})
	if took := time.Since(begin); took > 5*time.Second {
		t.Fatalf("a wrong password took %v to fail", took)
	}
	if !errors.Is(err, ssh.ErrBecome) || !strings.Contains(err.Error(), "incorrect password") {
		t.Fatalf("err = %v, want ErrBecome for an incorrect password", err)
	}
	if strings.Contains(err.Error(), "wrong-pass") {
		t.Fatal("the error shows the password")
	}
	// Written once, never retried.
	if got := attempts(t, log); len(got) != 1 {
		t.Fatalf("sudo read %d password lines, want 1", len(got))
	}

	// Attach says the same as the shell would.
	_, err = Attach(ctx, c, Options{Version: testVersion, Payload: agentPayload(t), Become: &ssh.Become{Client: c, Password: []byte("wrong-pass")}})
	if !errors.Is(err, ssh.ErrBecome) || errors.Is(err, ErrUnavailable) || !strings.Contains(err.Error(), "incorrect password") {
		t.Fatalf("attach with a wrong password = %v, want ErrBecome and no fallback", err)
	}
}

func TestBecomeAgentPasswordNeededButMissing(t *testing.T) {
	h, log := becomeHost(t, "nopasswd")
	dir, name, sum := cachedAgent(t, h)
	h.FakeSudo(t, "password:s3cret")
	c := dialServer(t, h.Server)

	_, err := start(ctx, c, dir, name, sum, &ssh.Become{Client: c})
	if !errors.Is(err, ssh.ErrBecome) || !strings.Contains(err.Error(), "set become_password_file") {
		t.Fatalf("err = %v, want ErrBecome asking for become_password_file", err)
	}
	if got := attempts(t, log); len(got) != 0 {
		t.Fatalf("sudo was sent %d lines", len(got))
	}
	_, err = Attach(ctx, c, Options{Version: testVersion, Payload: agentPayload(t), Become: &ssh.Become{Client: c}})
	if !errors.Is(err, ssh.ErrBecome) || errors.Is(err, ErrUnavailable) || !strings.Contains(err.Error(), "become_password_file") {
		t.Fatalf("attach = %v, want ErrBecome and no fallback", err)
	}
}

func TestBecomeAgentRequiretty(t *testing.T) {
	h, _ := becomeHost(t, "nopasswd")
	dir, name, sum := cachedAgent(t, h)
	h.FakeSudo(t, "requiretty")
	c := dialServer(t, h.Server)

	_, shellErr := (&ssh.Become{Client: c}).Run(ctx, "true", nil)
	_, err := start(ctx, c, dir, name, sum, &ssh.Become{Client: c})
	if err == nil || shellErr == nil || err.Error() != shellErr.Error() {
		t.Fatalf("agent start = %v, want the shell's %v", err, shellErr)
	}
	_, err = Attach(ctx, c, Options{Version: testVersion, Payload: agentPayload(t), Become: &ssh.Become{Client: c}})
	if !errors.Is(err, ssh.ErrBecome) || errors.Is(err, ErrUnavailable) || !strings.Contains(err.Error(), shellErr.Error()) {
		t.Fatalf("attach = %v, want the shell's %v", err, shellErr)
	}
}

func TestBecomeMarkerSplitAcrossReads(t *testing.T) {
	h, log := becomeHost(t, "nopasswd")
	dir, name, sum := cachedAgent(t, h)
	h.FakeSudo(t, "password:s3cret")
	h.Env = append(h.Env, "FAKE_SUDO_SPLIT=1")
	c := dialServer(t, h.Server)

	a, err := start(ctx, c, dir, name, sum, &ssh.Become{Client: c, Password: []byte("s3cret")})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if got := mustRun(t, a, `echo "$SUDO_USER"`); got != "fake\n" {
		t.Fatalf("agent says SUDO_USER=%q", got)
	}
	if got := attempts(t, log); len(got) != 1 || got[0] != "s3cret" {
		t.Fatalf("sudo read %d lines, want the password once", len(got))
	}
}
