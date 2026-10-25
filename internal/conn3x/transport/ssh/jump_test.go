// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ssh

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh/sshtest"
)

// knownHostsFor trusts every server, as one known_hosts file.
func knownHostsFor(t *testing.T, servers ...*sshtest.Server) string {
	t.Helper()
	var lines []string
	for _, s := range servers {
		lines = append(lines, sshtest.KnownHostsLine(s.Addr, s.HostKey))
	}
	path := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// Every hop accepts the same client key, as a bastion and its hosts often do.
func sameKeys(t *testing.T, n int) []*sshtest.Server {
	keys := sshtest.NewKeys(t)
	var out []*sshtest.Server
	for i := 0; i < n; i++ {
		out = append(out, sshtest.StartWith(t, "127.0.0.1:0", sshtest.NewKeys(t).Sharing(keys)))
	}
	return out
}

func TestDialThroughJumpHosts(t *testing.T) {
	s := sameKeys(t, 3)
	target, first, second := s[0], s[1], s[2]
	cfg := Config{
		Host: target.Host, Port: target.Port, User: "test", PrivateKey: target.ClientKey,
		KnownHostsFile: knownHostsFor(t, target, first, second),
		Jumps:          []Jump{{Host: first.Host, Port: first.Port, User: "test"}, {Host: second.Host, Port: second.Port, User: "test"}},
	}
	c := dial(t, cfg)
	res, err := c.Run(context.Background(), "echo through", nil)
	if err != nil || strings.TrimSpace(string(res.Stdout)) != "through" {
		t.Fatalf("Run = %q, %v", res.Stdout, err)
	}
	if first.Forwards() != 1 || second.Forwards() != 1 {
		t.Fatalf("forwards: first %d, second %d; want 1 each", first.Forwards(), second.Forwards())
	}
	if target.Accepts() != 1 {
		t.Fatalf("target accepted %d connections", target.Accepts())
	}
	c.Close()
	if first.Accepts() != 1 {
		t.Fatalf("the jump host was dialled %d times", first.Accepts())
	}
}

// A jump host is verified like any other: an unknown key stops the dial.
func TestUnknownJumpHostKeyFails(t *testing.T) {
	s := sameKeys(t, 2)
	target, jump := s[0], s[1]
	_, err := Dial(context.Background(), Config{
		Host: target.Host, Port: target.Port, User: "test", PrivateKey: target.ClientKey,
		KnownHostsFile: knownHostsFor(t, target),
		Jumps:          []Jump{{Host: jump.Host, Port: jump.Port, User: "test"}},
	})
	if !errors.Is(err, ErrHostKey) || !strings.Contains(err.Error(), jump.Addr) {
		t.Fatalf("err = %v, want ErrHostKey naming %s", err, jump.Addr)
	}
}

func TestParseJump(t *testing.T) {
	for in, want := range map[string]Jump{
		"bastion.example.com":             {Host: "bastion.example.com", Port: 22},
		"deploy@bastion.example.com":      {Host: "bastion.example.com", Port: 22, User: "deploy"},
		"deploy@bastion.example.com:2222": {Host: "bastion.example.com", Port: 2222, User: "deploy"},
		"[2001:db8::1]:2200":              {Host: "2001:db8::1", Port: 2200},
	} {
		got, err := ParseJump(in)
		if err != nil || got != want {
			t.Errorf("ParseJump(%q) = %+v, %v; want %+v", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "user@", "host:0", "host:70000", "a b", "host:x"} {
		if _, err := ParseJump(bad); err == nil {
			t.Errorf("ParseJump(%q) accepted", bad)
		}
	}
}
