// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ssh

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh/sshtest"
)

func becomeServer(t *testing.T, mode string) (*sshtest.Server, Config) {
	t.Helper()
	s := sshtest.New(t)
	s.FakeSudo(t, mode)
	return s, testConfig(t, s)
}

func TestBecomeWithoutPassword(t *testing.T) {
	_, cfg := becomeServer(t, "nopasswd")
	b := &Become{Client: dial(t, cfg)}
	res, err := b.Run(context.Background(), `printf '%s:' "$SUDO_USER"; cat`, []byte("payload\nline2"))
	if err != nil {
		t.Fatal(err)
	}
	if string(res.Stdout) != "fake:payload\nline2" || res.ExitCode != 0 {
		t.Fatalf("got %q exit %d (stderr %q)", res.Stdout, res.ExitCode, res.Stderr)
	}
}

func TestBecomeWithPasswordKeepsStdinIntact(t *testing.T) {
	_, cfg := becomeServer(t, "password:s3cret")
	b := &Become{Client: dial(t, cfg), Password: []byte("s3cret")}
	for i := 0; i < 2; i++ {
		res, err := b.Run(context.Background(), `printf '%s:' "$SUDO_USER"; cat`, []byte("content without newline"))
		if err != nil {
			t.Fatal(err)
		}
		if string(res.Stdout) != "fake:content without newline" {
			t.Fatalf("run %d: got %q (stderr %q)", i, res.Stdout, res.Stderr)
		}
	}
}

func TestBecomeNeedsPasswordButNoneGiven(t *testing.T) {
	_, cfg := becomeServer(t, "password:s3cret")
	b := &Become{Client: dial(t, cfg)}
	_, err := b.Run(context.Background(), "true", nil)
	if err == nil || !strings.Contains(err.Error(), "become_password_file") {
		t.Fatalf("err = %v, want a hint about become_password_file", err)
	}
}

func TestBecomeWrongPassword(t *testing.T) {
	_, cfg := becomeServer(t, "password:s3cret")
	b := &Become{Client: dial(t, cfg), Password: []byte("nope")}
	_, err := b.Run(context.Background(), "true", nil)
	if err == nil || !strings.Contains(err.Error(), "incorrect") {
		t.Fatalf("err = %v, want an incorrect password error", err)
	}
}

func TestBecomeRequireTTY(t *testing.T) {
	_, cfg := becomeServer(t, "requiretty")
	b := &Become{Client: dial(t, cfg)}
	_, err := b.Run(context.Background(), "true", nil)
	if err == nil || !strings.Contains(err.Error(), "requiretty") {
		t.Fatalf("err = %v, want a requiretty explanation", err)
	}
}

func TestBecomeCommandFailureIsAResult(t *testing.T) {
	_, cfg := becomeServer(t, "nopasswd")
	b := &Become{Client: dial(t, cfg)}
	res, err := b.Run(context.Background(), "echo nope >&2; exit 4", nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 4 || !strings.Contains(string(res.Stderr), "nope") {
		t.Fatalf("got exit %d stderr %q", res.ExitCode, res.Stderr)
	}
}

func TestBecomeWrongPasswordNeverSeesCommandInput(t *testing.T) {
	s, cfg := becomeServer(t, "password:s3cret")
	// Record every line the fake sudo is handed as a password.
	log := s.Dir + "/attempts"
	s.Env = append(s.Env, "FAKE_SUDO_LOG="+log)
	b := &Become{Client: dial(t, cfg), Password: []byte("nope")}
	if _, err := b.Run(context.Background(), "cat > /dev/null", []byte("secret file content\n")); err == nil {
		t.Fatal("run with a wrong password succeeded")
	}
	if data, _ := os.ReadFile(log); strings.Contains(string(data), "secret file content") {
		t.Fatalf("command input reached sudo as a password attempt: %q", data)
	}
}

// Cached sudo credentials, shared across sessions as with
// timestamp_type=global, can't turn the password line into command input.
// The probe's "sudo -v" caches them, and a sudo that didn't prompt would
// hand the password to the command, writing it into a file step's file.
func TestBecomeCachedCredentialsKeepStdinIntact(t *testing.T) {
	s, cfg := becomeServer(t, "password:s3cret")
	s.Env = append(s.Env, "FAKE_SUDO_CACHE="+s.Dir+"/timestamp")
	b := &Become{Client: dial(t, cfg), Password: []byte("s3cret")}
	for i := 0; i < 2; i++ {
		res, err := b.Run(context.Background(), "cat", []byte("file content"))
		if err != nil {
			t.Fatal(err)
		}
		if string(res.Stdout) != "file content" {
			t.Fatalf("run %d: command read %q (stderr %q)", i, res.Stdout, res.Stderr)
		}
	}
}

// A probe cut short by its context is tried again by the next Run rather
// than failing every Run after it.
func TestBecomeProbeRetriesAfterCancel(t *testing.T) {
	_, cfg := becomeServer(t, "nopasswd")
	b := &Become{Client: dial(t, cfg)}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := b.Run(ctx, "true", nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled Run = %v, want context.Canceled", err)
	}
	if _, err := b.Run(context.Background(), "true", nil); err != nil {
		t.Fatalf("Run after a cancelled probe = %v", err)
	}
}
