// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package sshtest

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// dial connects to s with key, checking the host key against its
// known_hosts file.
func dial(t *testing.T, s *Server, key []byte) (*gossh.Client, error) {
	t.Helper()
	signer, err := gossh.ParsePrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	hk, err := knownhosts.New(s.KnownHosts(t))
	if err != nil {
		t.Fatal(err)
	}
	c, err := gossh.Dial("tcp", s.Addr, &gossh.ClientConfig{
		User:            "test",
		Auth:            []gossh.AuthMethod{gossh.PublicKeys(signer)},
		HostKeyCallback: hk,
		Timeout:         5 * time.Second,
	})
	if err == nil {
		t.Cleanup(func() { c.Close() })
	}
	return c, err
}

func connect(t *testing.T, s *Server) *gossh.Client {
	t.Helper()
	c, err := dial(t, s, s.ClientKey)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// run runs cmd in a new session and returns stdout, stderr and the exit
// status.
func run(t *testing.T, c *gossh.Client, cmd, stdin string) (string, string, int) {
	t.Helper()
	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	var out, errb bytes.Buffer
	sess.Stdin, sess.Stdout, sess.Stderr = strings.NewReader(stdin), &out, &errb
	code := 0
	if err := sess.Run(cmd); err != nil {
		var exit *gossh.ExitError
		if !errors.As(err, &exit) {
			t.Fatalf("%s: %v", cmd, err)
		}
		code = exit.ExitStatus()
	}
	return out.String(), errb.String(), code
}

func TestExec(t *testing.T) {
	s := New(t)
	s.Env = append(s.Env, "CONN3X_TEST=set")
	c := connect(t, s)

	if out, errs, code := run(t, c, `printf "%s %s" "$CONN3X_TEST" "$(cat)"; echo oops >&2; exit 3`, "in"); out != "set in" || errs != "oops\n" || code != 3 {
		t.Errorf("got %q, %q, exit %d", out, errs, code)
	}
	if out, _, code := run(t, c, "pwd -P", ""); code != 0 {
		t.Errorf("pwd: exit %d", code)
	} else if want, _ := filepath.EvalSymlinks(s.Dir); strings.TrimSpace(out) != want {
		t.Errorf("ran in %q, want %q", out, want)
	}
	if _, _, code := run(t, c, "kill -9 $$", ""); code != 137 {
		t.Errorf("killed by a signal: exit %d, want 137", code)
	}
	if got := s.Commands(); len(got) != 3 || got[2] != "kill -9 $$" {
		t.Errorf("commands %q", got)
	}
}

func TestShell(t *testing.T) {
	s := New(t)
	sess, err := connect(t, s).NewSession()
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	sess.Stdin, sess.Stdout = strings.NewReader("echo from stdin\n"), &out
	if err := sess.Shell(); err != nil {
		t.Fatal(err)
	}
	if err := sess.Wait(); err != nil || out.String() != "from stdin\n" {
		t.Errorf("got %q, %v", out.String(), err)
	}
	// A request the server doesn't serve is refused, and the session lives on.
	sess, _ = connect(t, s).NewSession()
	defer sess.Close()
	if err := sess.Setenv("X", "y"); err == nil {
		t.Error("env request accepted")
	}
	if b, err := sess.Output("echo still"); err != nil || string(b) != "still\n" {
		t.Errorf("after a refused request: %q, %v", b, err)
	}
}

func TestSetExec(t *testing.T) {
	s := New(t)
	s.SetExec(func(cmd string, stdin []byte) (string, int) { return cmd + ":" + string(stdin), 7 })
	if out, _, code := run(t, connect(t, s), "show version", "x"); out != "show version:x" || code != 7 {
		t.Errorf("got %q, exit %d", out, code)
	}
}

func TestAuth(t *testing.T) {
	s := New(t)
	if _, err := dial(t, s, NewKeys(t).ClientKey); err == nil {
		t.Error("a key the server doesn't know got in")
	}
	// Keys created first serve a host whose key is known before it starts,
	// and Sharing makes it accept another set's client key.
	bastion, behind := NewKeys(t), NewKeys(t)
	h := StartWith(t, "127.0.0.1:0", behind.Sharing(bastion))
	if !bytes.Equal(h.HostKey.Marshal(), behind.Host.PublicKey().Marshal()) || !bytes.Equal(h.ClientKey, bastion.ClientKey) {
		t.Error("the server doesn't use the keys it was given")
	}
	connect(t, h)
	b, err := os.ReadFile(behind.KnownHosts(t, h.Addr))
	if err != nil || string(b) != KnownHostsLine(h.Addr, h.HostKey)+"\n" {
		t.Errorf("known_hosts %q, %v", b, err)
	}
	if b, err := os.ReadFile(s.KeyFile(t)); err != nil || !bytes.Equal(b, s.ClientKey) {
		t.Errorf("key file %q, %v", b, err)
	}
	if h, p, _ := net.SplitHostPort(s.Addr); h != s.Host || p == "0" || s.Port == 0 {
		t.Errorf("addr %s, host %s, port %d", s.Addr, s.Host, s.Port)
	}
	if s.Accepts() != 1 {
		t.Errorf("accepts %d, want 1", s.Accepts())
	}
}

func TestRejections(t *testing.T) {
	s := New(t)
	s.MaxSessions = 1
	c := connect(t, s)
	first, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	var open *gossh.OpenChannelError
	if _, err := c.NewSession(); !errors.As(err, &open) || open.Reason != gossh.ConnectionFailed || open.Message != "open failed" {
		t.Errorf("second session: %v", err)
	}
	first.Close()

	s.RejectSessions = gossh.Prohibited
	if _, err := c.NewSession(); !errors.As(err, &open) || open.Reason != gossh.Prohibited {
		t.Errorf("with RejectSessions: %v", err)
	}
	if _, _, err := c.OpenChannel("x11", nil); !errors.As(err, &open) || open.Reason != gossh.UnknownChannelType {
		t.Errorf("x11 channel: %v", err)
	}
	if s.Rejections() != 2 {
		t.Errorf("rejections %d, want 2", s.Rejections())
	}
}

func TestKeepalives(t *testing.T) {
	s := New(t)
	c := connect(t, s)
	// A keepalive after a session frees that session's place.
	s.MaxSessions = 1
	run(t, c, "true", "")
	if ok, _, err := c.SendRequest("keepalive@openssh.com", true, nil); err != nil || ok {
		t.Errorf("keepalive answered %v, %v; sshd answers with a failure", ok, err)
	}
	if ok, _, err := c.SendRequest("other", true, nil); err != nil || ok {
		t.Errorf("other request answered %v, %v", ok, err)
	}
	if _, _, err := c.SendRequest("other", false, nil); err != nil {
		t.Error(err)
	}
	if out, _, code := run(t, c, "echo again", ""); out != "again\n" || code != 0 || s.Rejections() != 0 {
		t.Errorf("after the keepalive: %q, exit %d, %d rejected", out, code, s.Rejections())
	}
	if s.Keepalives() != 1 {
		t.Errorf("keepalives %d, want 1", s.Keepalives())
	}

	s.IgnoreKeepalives = true
	c = connect(t, s)
	done := make(chan struct{})
	go func() { _, _, _ = c.SendRequest("keepalive@openssh.com", true, nil); close(done) }()
	select {
	case <-done:
		t.Error("an ignored keepalive got an answer")
	case <-time.After(100 * time.Millisecond):
	}
	c.Close()
	<-done
}

func TestForward(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		b, _ := io.ReadAll(conn) // until the client's half-close
		_, _ = conn.Write(append([]byte("echo:"), b...))
		conn.Close()
	}()

	s := New(t)
	s.SetForwardDelay(time.Millisecond)
	c := connect(t, s)
	conn, err := c.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = conn.Write([]byte("hi"))
	_ = conn.(interface{ CloseWrite() error }).CloseWrite()
	if b, err := io.ReadAll(conn); err != nil || string(b) != "echo:hi" {
		t.Errorf("got %q, %v", b, err)
	}
	if s.Forwards() != 1 {
		t.Errorf("forwards %d, want 1", s.Forwards())
	}

	// A target that refuses is a failed open, not a forward.
	dead, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := dead.Addr().String()
	dead.Close()
	if _, err := c.Dial("tcp", addr); err == nil {
		t.Error("forwarded to a closed port")
	}
	if _, _, err := c.OpenChannel("direct-tcpip", []byte("garbage")); err == nil {
		t.Error("accepted a malformed forward")
	}
	if s.Forwards() != 1 {
		t.Errorf("forwards %d, want 1", s.Forwards())
	}
}

func TestLatencyAndDelay(t *testing.T) {
	s := New(t)
	s.Latency = time.Millisecond
	s.SetDelay(time.Millisecond)
	if out, _, code := run(t, connect(t, s), "echo hi", ""); out != "hi\n" || code != 0 {
		t.Errorf("through a delayed link: %q, exit %d", out, code)
	}
}

func TestFakeSudo(t *testing.T) {
	for _, c := range []struct {
		mode, cmd, stdin, out, errs string
		code                        int
	}{
		{"nopasswd", "sudo -n -- sh -c 'echo $SUDO_USER'", "", "fake\n", "", 0},
		{"nopasswd", "sudo -v", "", "", "", 0},
		{"requiretty", "sudo -n -- true", "", "", "sudo: sorry, you must have a tty to run sudo\n", 1},
		{"password:s3cret", "sudo -n -- true", "", "", "sudo: a password is required\n", 1},
		{"password:s3cret", "sudo -S -p P: -- echo ok", "s3cret\n", "ok\n", "P:", 0},
		{"password:s3cret", "sudo -S -p P: -- echo ok", "a\nb\nc\n", "", "P:Sorry, try again.\nP:Sorry, try again.\nP:sudo: 3 incorrect password attempts\n", 1},
	} {
		t.Run(c.mode+" "+c.cmd, func(t *testing.T) {
			s := New(t)
			s.FakeSudo(t, c.mode)
			if out, errs, code := run(t, connect(t, s), c.cmd, c.stdin); out != c.out || errs != c.errs || code != c.code {
				t.Errorf("got %q, %q, exit %d", out, errs, code)
			}
		})
	}

	t.Run("cached credentials", func(t *testing.T) {
		s := New(t)
		s.FakeSudo(t, "password:s3cret")
		cache, log := filepath.Join(t.TempDir(), "cache"), filepath.Join(t.TempDir(), "log")
		s.Env = append(s.Env, "FAKE_SUDO_CACHE="+cache, "FAKE_SUDO_LOG="+log)
		c := connect(t, s)
		if _, _, code := run(t, c, "sudo -S -p P: -- true", "s3cret\n"); code != 0 {
			t.Fatalf("first sudo: exit %d", code)
		}
		if out, errs, code := run(t, c, "sudo -n -- echo cached", ""); out != "cached\n" || errs != "" || code != 0 {
			t.Errorf("cached: %q, %q, exit %d", out, errs, code)
		}
		if _, errs, code := run(t, c, "sudo -k -n -- true", ""); code != 1 || errs != "sudo: a password is required\n" {
			t.Errorf("-k: %q, exit %d", errs, code)
		}
		if b, _ := os.ReadFile(log); string(b) != "s3cret\n" {
			t.Errorf("password log %q", b)
		}
	})
}
