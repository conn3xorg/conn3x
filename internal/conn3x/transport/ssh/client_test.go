// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"
)

func dial(t *testing.T, cfg Config) *Client {
	t.Helper()
	c, err := Dial(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func TestRunCapturesOutputAndExit(t *testing.T) {
	s := newTestServer(t)
	c := dial(t, s.config(t))
	res, err := c.Run(context.Background(), "printf hi; printf oops >&2; exit 3", nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(res.Stdout) != "hi" || string(res.Stderr) != "oops" || res.ExitCode != 3 {
		t.Fatalf("got stdout %q stderr %q exit %d", res.Stdout, res.Stderr, res.ExitCode)
	}
}

func TestRunSetsCLocale(t *testing.T) {
	s := newTestServer(t)
	c := dial(t, s.config(t))
	res, err := c.Run(context.Background(), `printf %s "$LC_ALL"`, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(res.Stdout) != "C" {
		t.Fatalf("LC_ALL = %q, want C", res.Stdout)
	}
}

func TestRunPassesStdin(t *testing.T) {
	s := newTestServer(t)
	c := dial(t, s.config(t))
	in := []byte("no trailing newline\x00\xff")
	res, err := c.Run(context.Background(), "cat", in)
	if err != nil {
		t.Fatal(err)
	}
	if string(res.Stdout) != string(in) {
		t.Fatalf("stdin round-trip: got %q", res.Stdout)
	}
}

func TestRunReusesOneConnection(t *testing.T) {
	s := newTestServer(t)
	c := dial(t, s.config(t))
	for i := 0; i < 5; i++ {
		if _, err := c.Run(context.Background(), "true", nil); err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
	}
}

func TestUnknownHostKeyFails(t *testing.T) {
	s := newTestServer(t)
	cfg := s.config(t)
	empty := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.KnownHostsFile = empty
	_, err := Dial(context.Background(), cfg)
	if !errors.Is(err, ErrHostKey) {
		t.Fatalf("err = %v, want ErrHostKey", err)
	}
	if !strings.Contains(err.Error(), cfg.Host) || !strings.Contains(err.Error(), empty) {
		t.Fatalf("error should name host and file: %v", err)
	}
}

func TestChangedHostKeyFails(t *testing.T) {
	s := newTestServer(t)
	cfg := s.config(t)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	other, _ := gossh.NewPublicKey(pub)
	path := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(path, []byte(knownHostsLine(s.Addr, other)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.KnownHostsFile = path
	_, err := Dial(context.Background(), cfg)
	if !errors.Is(err, ErrHostKey) || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("err = %v, want a changed-host-key ErrHostKey", err)
	}
}

func TestPinnedHostKey(t *testing.T) {
	s := newTestServer(t)
	cfg := s.config(t)
	cfg.KnownHostsFile = filepath.Join(t.TempDir(), "does-not-exist")
	cfg.HostKey = string(gossh.MarshalAuthorizedKey(s.HostKey))
	dial(t, cfg)

	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	other, _ := gossh.NewPublicKey(pub)
	cfg.HostKey = string(gossh.MarshalAuthorizedKey(other))
	if _, err := Dial(context.Background(), cfg); !errors.Is(err, ErrHostKey) {
		t.Fatalf("wrong pinned key: err = %v, want ErrHostKey", err)
	}
}

func TestUnreachableTimesOut(t *testing.T) {
	start := time.Now()
	_, err := Dial(context.Background(), Config{Host: "10.255.255.1", Port: 22, User: "x", PrivateKey: []byte("x"), Timeout: time.Second})
	if err == nil {
		t.Fatal("dial to a blackhole address succeeded")
	}
	if time.Since(start) > 3*time.Second {
		t.Fatalf("took %s, want about 1s", time.Since(start))
	}
	if !strings.Contains(err.Error(), "10.255.255.1:22") {
		t.Fatalf("error should name the address: %v", err)
	}
}

func TestCancelStopsRun(t *testing.T) {
	s := newTestServer(t)
	c := dial(t, s.config(t))
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := c.Run(ctx, "sleep 5", nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want deadline exceeded", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("run ignored cancellation, took %s", time.Since(start))
	}
}

func TestQuote(t *testing.T) {
	for _, s := range []string{"a b", "it's", "$(touch pwned)", "", "line\nbreak", `back\slash`, "`tick`", "*"} {
		out, err := exec.Command("sh", "-c", "printf %s "+Quote(s)).Output()
		if err != nil {
			t.Fatalf("Quote(%q): %v", s, err)
		}
		if string(out) != s {
			t.Errorf("Quote(%q) round-trips to %q", s, out)
		}
	}
	if _, err := os.Stat("pwned"); err == nil {
		t.Fatal("quoted command substitution executed")
	}
}
