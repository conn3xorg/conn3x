// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh/sshtest"
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
	s := sshtest.New(t)
	c := dial(t, testConfig(t, s))
	res, err := c.Run(context.Background(), "printf hi; printf oops >&2; exit 3", nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(res.Stdout) != "hi" || string(res.Stderr) != "oops" || res.ExitCode != 3 {
		t.Fatalf("got stdout %q stderr %q exit %d", res.Stdout, res.Stderr, res.ExitCode)
	}
}

func TestRunSetsCLocale(t *testing.T) {
	s := sshtest.New(t)
	c := dial(t, testConfig(t, s))
	res, err := c.Run(context.Background(), `printf %s "$LC_ALL"`, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(res.Stdout) != "C" {
		t.Fatalf("LC_ALL = %q, want C", res.Stdout)
	}
}

func TestRunPassesStdin(t *testing.T) {
	s := sshtest.New(t)
	c := dial(t, testConfig(t, s))
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
	s := sshtest.New(t)
	c := dial(t, testConfig(t, s))
	for i := 0; i < 5; i++ {
		if _, err := c.Run(context.Background(), "true", nil); err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
	}
}

func TestUnknownHostKeyFails(t *testing.T) {
	s := sshtest.New(t)
	cfg := testConfig(t, s)
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
	s := sshtest.New(t)
	cfg := testConfig(t, s)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	other, _ := gossh.NewPublicKey(pub)
	path := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(path, []byte(sshtest.KnownHostsLine(s.Addr, other)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.KnownHostsFile = path
	_, err := Dial(context.Background(), cfg)
	if !errors.Is(err, ErrHostKey) || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("err = %v, want a changed-host-key ErrHostKey", err)
	}
}

func TestPinnedHostKey(t *testing.T) {
	s := sshtest.New(t)
	cfg := testConfig(t, s)
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
	s := sshtest.New(t)
	c := dial(t, testConfig(t, s))
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

func TestStartStreamsWithoutPTY(t *testing.T) {
	s := sshtest.New(t)
	c := dial(t, testConfig(t, s))
	cmd := `head -c 5; [ -t 0 ] || echo no-tty >&2`
	p, err := c.Start(context.Background(), cmd)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if _, err := p.Write([]byte("hello, and more")); err != nil {
		t.Fatal(err)
	}
	out := make([]byte, 5)
	if _, err := io.ReadFull(p, out); err != nil || string(out) != "hello" {
		t.Fatalf("read %q, %v; want hello", out, err)
	}
	if err := p.Wait(); err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if string(p.Stderr()) != "no-tty\n" {
		t.Fatalf("stderr = %q, want no-tty", p.Stderr())
	}
	if got := s.Commands(); len(got) != 1 || got[0] != cmd {
		t.Fatalf("server ran %q, want exactly %q", got, cmd)
	}
}

func TestStartAfterCancel(t *testing.T) {
	s := sshtest.New(t)
	c := dial(t, testConfig(t, s))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Start(ctx, "true"); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

func TestLatencyDelaysEveryWrite(t *testing.T) {
	s := sshtest.New(t)
	c := dial(t, testConfig(t, s))
	s.Latency = 30 * time.Millisecond
	start := time.Now()
	if _, err := c.Run(context.Background(), "true", nil); err != nil {
		t.Fatal(err)
	}
	// A session takes several round trips: open, exec, exit status, close.
	if took := time.Since(start); took < 3*s.Latency {
		t.Fatalf("Run took %s with %s latency per write", took, s.Latency)
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

func testConfig(t *testing.T, s *sshtest.Server) Config {
	return Config{Host: s.Host, Port: s.Port, User: "test", PrivateKey: s.ClientKey, KnownHostsFile: s.KnownHosts(t)}
}

// runParallel runs n commands at once on c and fails on any error.
func runParallel(t *testing.T, c *Client, n int) {
	t.Helper()
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		go func() {
			res, err := c.Run(context.Background(), "sleep 0.1; echo ok", nil)
			if err == nil && strings.TrimSpace(string(res.Stdout)) != "ok" {
				err = errors.New("output " + string(res.Stdout))
			}
			errs <- err
		}()
	}
	for i := 0; i < n; i++ {
		if err := <-errs; err != nil {
			t.Error(err)
		}
	}
}

// sshd allows ten sessions per connection by default; more commands than
// that at once must queue, not fail.
func TestRunQueuesBeyondMaxSessions(t *testing.T) {
	s := sshtest.New(t)
	s.MaxSessions = 10
	runParallel(t, dial(t, testConfig(t, s)), 30)
	// The cap is below the server's limit, and a slot comes back only
	// once the server has freed its session, so nothing is ever refused.
	if got := s.Rejections(); got != 0 {
		t.Fatalf("server refused %d sessions under a cap below its limit", got)
	}
}

// A server allowing fewer sessions than the cap still runs everything, and
// each command exactly once. Five commands leave some of the cap's slots
// free when the server starts refusing; twenty fill it.
func TestRunAdaptsToLowerMaxSessions(t *testing.T) {
	for _, n := range []int{5, 20} {
		s := sshtest.New(t)
		s.MaxSessions = 3
		c := dial(t, testConfig(t, s))
		runParallel(t, c, n)
		if got := len(s.Commands()); got != n {
			t.Fatalf("server ran %d commands, want %d", got, n)
		}
		c.mu.Lock()
		limit := c.limit
		c.mu.Unlock()
		if limit != 3 {
			t.Errorf("%d commands: cap ended at %d, want 3", n, limit)
		}
		// Only the opens in flight when the cap was found are refused,
		// each once: past the cap of 8, the rest wait their turn.
		if got, most := s.Rejections(), int64(min(n, defaultMaxSessions)-3); got > most {
			t.Errorf("%d commands: server refused %d sessions, want at most %d", n, got, most)
		}
	}
}

// A session refused for any other reason fails at once, without retrying.
func TestRunRefusedSessionFailsAtOnce(t *testing.T) {
	s := sshtest.New(t)
	s.RejectSessions = gossh.Prohibited
	c := dial(t, testConfig(t, s))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := c.Run(ctx, "true", nil)
	var open *gossh.OpenChannelError
	if !errors.As(err, &open) || open.Reason != gossh.Prohibited {
		t.Fatalf("Run = %v, want the server's refusal", err)
	}
	if got := s.Rejections(); got != 1 {
		t.Fatalf("client tried %d times, want 1", got)
	}
}

// Sessions that end together are given back after one keepalive between
// them, not one each: keepalives that want a reply go out one at a time,
// so one each would free the slots a round trip apart.
func TestSessionsEndingTogetherShareAKeepalive(t *testing.T) {
	s := sshtest.New(t)
	s.SetDelay(20 * time.Millisecond)
	c := dial(t, testConfig(t, s))
	const n = 32
	runParallel(t, c, n)
	// One each would be n. How many share depends on timing: about 12
	// locally, 17 on a CI runner.
	if got := s.Keepalives(); got >= n*3/4 {
		t.Fatalf("%d commands sent %d keepalives, want fewer than %d", n, got, n*3/4)
	}
}

// A server that stops answering keepalives can't hold slots forever: the
// connection is closed, and commands waiting for a slot fail instead of
// hanging.
func TestUnansweredKeepaliveClosesConnection(t *testing.T) {
	t.Setenv("CONN3X_SSH_MAX_SESSIONS", "1")
	defer func(d time.Duration) { keepaliveTimeout = d }(keepaliveTimeout)
	keepaliveTimeout = 200 * time.Millisecond
	s := sshtest.New(t)
	s.IgnoreKeepalives = true
	c := dial(t, testConfig(t, s))
	if _, err := c.Run(context.Background(), "true", nil); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := c.Run(ctx, "true", nil); err == nil || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Run waiting for a slot = %v, want the connection's error", err)
	}
}

// BenchmarkQuickCommandsAtDelay runs 64 quick commands at once on a host
// 50 ms away, so the cap of 8 turns over many times.
func BenchmarkQuickCommandsAtDelay(b *testing.B) {
	s := sshtest.New(b)
	s.SetDelay(50 * time.Millisecond)
	c, err := Dial(context.Background(), Config{Host: s.Host, Port: s.Port, User: "test", PrivateKey: s.ClientKey, KnownHostsFile: s.KnownHosts(b)})
	if err != nil {
		b.Fatal(err)
	}
	defer c.Close()
	for b.Loop() {
		errs := make(chan error, 64)
		for range 64 {
			go func() { _, err := c.Run(context.Background(), "true", nil); errs <- err }()
		}
		for range 64 {
			if err := <-errs; err != nil {
				b.Fatal(err)
			}
		}
	}
}

func TestRunCancelledWhileWaitingForSession(t *testing.T) {
	t.Setenv("CONN3X_SSH_MAX_SESSIONS", "1")
	s := sshtest.New(t)
	c := dial(t, testConfig(t, s))

	holdCtx, release := context.WithCancel(context.Background())
	held := make(chan error, 1)
	go func() { _, err := c.Run(holdCtx, "sleep 30", nil); held <- err }()
	for len(s.Commands()) == 0 {
		time.Sleep(10 * time.Millisecond)
	}

	ctx, cancel := context.WithCancel(context.Background())
	waited := make(chan error, 1)
	go func() { _, err := c.Run(ctx, "echo never", nil); waited <- err }()
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case err := <-waited:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("waiting Run = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled Run is still waiting for a session")
	}

	// Cancelling the running command gives its slot back.
	release()
	if err := <-held; !errors.Is(err, context.Canceled) {
		t.Fatalf("held Run = %v", err)
	}
	if _, err := c.Run(context.Background(), "true", nil); err != nil {
		t.Fatal(err)
	}
	for _, cmd := range s.Commands() {
		if strings.Contains(cmd, "never") {
			t.Fatal("the cancelled command ran")
		}
	}
}

// A started process, such as the agent, holds its session until Close.
func TestStartHoldsSessionUntilClose(t *testing.T) {
	t.Setenv("CONN3X_SSH_MAX_SESSIONS", "1")
	s := sshtest.New(t)
	c := dial(t, testConfig(t, s))
	p, err := c.Start(context.Background(), "cat")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if _, err := c.Run(ctx, "true", nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Run while the process is open = %v, want a deadline", err)
	}
	p.Close()
	if _, err := c.Run(context.Background(), "true", nil); err != nil {
		t.Fatal(err)
	}
}
