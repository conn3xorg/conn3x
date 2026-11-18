// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ssh

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh/sshtest"
)

// shellClient dials with long-lived shells on, and runs one command so the
// connection has had a plain session and shells may start.
func shellClient(t *testing.T, s *sshtest.Server) *Client {
	t.Helper()
	t.Setenv("CONN3X_SSH_SHELL", "1")
	c := dial(t, testConfig(t, s))
	if _, err := c.Run(context.Background(), "true", nil); err != nil {
		t.Fatal(err)
	}
	return c
}

// Commands after the first share one shell, and each still sees only its
// own output, exit status and environment.
func TestShellRunsCommandsInOneSession(t *testing.T) {
	s := sshtest.New(t)
	c := shellClient(t, s)
	ctx := context.Background()
	for i, tc := range []struct {
		cmd            string
		stdout, stderr string
		code           int
	}{
		{"printf hi; printf oops >&2; exit 3", "hi", "oops", 3},
		{"X=1; cd /; echo $X", "1\n", "", 0},
		{`echo "${X:-unset}"; pwd`, "unset\n" + mustPwd(t, c) + "\n", "", 0},
		{`printf 'a\000b'`, "a\x00b", "", 0},
		{`printf '\n\001fake 0\n'; exit 7`, "\n\x01fake 0\n", "", 7},
		{"exit 0", "", "", 0},
		{"locale 2>/dev/null | grep -c . >/dev/null; echo $LC_ALL", "C\n", "", 0},
	} {
		res, err := c.Run(ctx, tc.cmd, nil)
		if err != nil {
			t.Fatalf("%d %q: %v", i, tc.cmd, err)
		}
		if string(res.Stdout) != tc.stdout || string(res.Stderr) != tc.stderr || res.ExitCode != tc.code {
			t.Errorf("%d %q: stdout %q stderr %q exit %d", i, tc.cmd, res.Stdout, res.Stderr, res.ExitCode)
		}
	}
	// Besides shellClient's first command and mustPwd's, everything went
	// to one shell.
	shells := 0
	for _, cmd := range s.Commands() {
		if strings.Contains(cmd, "/bin/sh -s") {
			shells++
		}
	}
	if got := s.Commands(); shells != 1 || len(got) != 3 {
		t.Errorf("server ran %q, want two plain commands and one shell", got)
	}
}

func mustPwd(t *testing.T, c *Client) string {
	t.Helper()
	t.Setenv("CONN3X_SSH_SHELL", "")
	res, err := c.Run(context.Background(), "pwd", nil)
	t.Setenv("CONN3X_SSH_SHELL", "1")
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(res.Stdout))
}

// A command with stdin takes a session of its own, so stdin never goes
// through a shell.
func TestShellLeavesStdinToSessions(t *testing.T) {
	s := sshtest.New(t)
	c := shellClient(t, s)
	res, err := c.Run(context.Background(), "cat", []byte("secret"))
	if err != nil || string(res.Stdout) != "secret" {
		t.Fatalf("stdout %q, err %v", res.Stdout, err)
	}
	if got := s.Commands(); len(got) != 2 || strings.Contains(got[1], "/bin/sh -s") {
		t.Errorf("server ran %q, want a session for the command with stdin", got)
	}
}

// A cancelled command and one that prints past the limit take their shell
// down, and the next command gets a fresh one.
func TestShellFailuresStartAFreshShell(t *testing.T) {
	saved := MaxOutput
	MaxOutput = 64 << 10
	defer func() { MaxOutput = saved }()
	s := sshtest.New(t)
	c := shellClient(t, s)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := c.Run(ctx, "sleep 5", nil); !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 2*time.Second {
		t.Fatalf("cancelled: err %v after %s", err, time.Since(start))
	}
	if _, err := c.Run(context.Background(), "head -c 4194304 /dev/zero", nil); err == nil || !strings.Contains(err.Error(), "printed more than") {
		t.Fatalf("a flood of output: err = %v, want the limit named", err)
	}
	res, err := c.Run(context.Background(), "head -c 65536 /dev/zero", nil)
	if err != nil || len(res.Stdout) != MaxOutput {
		t.Fatalf("output at the limit: %d bytes, err = %v", len(res.Stdout), err)
	}
	if res, err := c.Run(context.Background(), "echo ok", nil); err != nil || !bytes.Equal(res.Stdout, []byte("ok\n")) {
		t.Fatalf("after: %q, %v", res.Stdout, err)
	}
}

// Over a slow link a command in a shell waits on fewer replies than one in
// a new session. The test server delays every write it makes, not every
// round trip, so the gain here understates a real network's.
func TestShellSavesRoundTrips(t *testing.T) {
	s := sshtest.New(t)
	timed := func(c *Client) time.Duration {
		start := time.Now()
		for range 5 {
			if _, err := c.Run(context.Background(), "true", nil); err != nil {
				t.Fatal(err)
			}
		}
		return time.Since(start) / 5
	}
	sessions := dial(t, testConfig(t, s))
	c := shellClient(t, s)
	s.Latency = 30 * time.Millisecond
	perShell := timed(c)
	t.Setenv("CONN3X_SSH_SHELL", "")
	perSession := timed(sessions)
	if perShell*4 > perSession*3 {
		t.Fatalf("a command took %s in a shell and %s in a session, want at least a quarter less", perShell, perSession)
	}
}
