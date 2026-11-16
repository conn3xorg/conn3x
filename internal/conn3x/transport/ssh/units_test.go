// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ssh

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	gossh "golang.org/x/crypto/ssh"

	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh/sshtest"
)

func TestMaxSessionsFromEnv(t *testing.T) {
	for v, want := range map[string]int{"": defaultMaxSessions, "3": 3, "0": defaultMaxSessions, "1001": defaultMaxSessions, "many": defaultMaxSessions} {
		t.Setenv("CONN3X_SSH_MAX_SESSIONS", v)
		if got := maxSessions(); got != want {
			t.Errorf("%q: %d, want %d", v, got, want)
		}
	}
}

// KnownKeys answers from the pinned key first, then known_hosts.
func TestKnownKeys(t *testing.T) {
	keys := sshtest.NewKeys(t)
	pub := keys.Host.PublicKey()
	pinned := strings.TrimSpace(string(gossh.MarshalAuthorizedKey(pub)))
	got, err := KnownKeys(Config{Host: "h", HostKey: pinned})
	if err != nil || len(got) != 1 || !bytes.Equal(got[0].Marshal(), pub.Marshal()) {
		t.Errorf("pinned: %v, %v", got, err)
	}
	if _, err := KnownKeys(Config{Host: "h", HostKey: "not a key"}); err == nil {
		t.Error("a bad pinned key parsed")
	}
	// No port means 22, which known_hosts writes without brackets.
	file := keys.KnownHosts(t, "h:22")
	if got, err := KnownKeys(Config{Host: "h", KnownHostsFile: file}); err != nil || len(got) != 1 {
		t.Errorf("recorded at 22: %v, %v", got, err)
	}
	if got, err := KnownKeys(Config{Host: "other", KnownHostsFile: file}); err != nil || len(got) != 0 {
		t.Errorf("an address not recorded: %v, %v", got, err)
	}
	missing := filepath.Join(t.TempDir(), "none")
	if _, err := KnownKeys(Config{Host: "h", KnownHostsFile: missing}); !errors.Is(err, ErrHostKey) || !strings.Contains(err.Error(), "cannot read known_hosts file "+missing) {
		t.Errorf("missing file: %v", err)
	}
	t.Setenv("HOME", "")
	if _, err := KnownKeys(Config{Host: "h"}); !errors.Is(err, ErrHostKey) || !strings.Contains(err.Error(), "no home directory") {
		t.Errorf("no home: %v", err)
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "known_hosts"), []byte(sshtest.KnownHostsLine("h:22", pub)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := KnownKeys(Config{Host: "h"}); err != nil || len(got) != 1 {
		t.Errorf("the home known_hosts: %v, %v", got, err)
	}
}

// Captured output keeps what fits and drops the rest, without failing the
// writer.
func TestBoundedBuffers(t *testing.T) {
	l := &limitedWriter{w: &bytes.Buffer{}, n: 4}
	for _, s := range []string{"ab", "cdef", "gh"} {
		if n, err := l.Write([]byte(s)); n != len(s) || err != nil {
			t.Errorf("write %q: %d, %v", s, n, err)
		}
	}
	if l.w.String() != "abcd" {
		t.Errorf("kept %q", l.w.String())
	}
	var b syncBuffer
	big := bytes.Repeat([]byte("x"), maxProcessStderr+10)
	if n, _ := b.Write(big); n != len(big) || len(b.Bytes()) != maxProcessStderr {
		t.Errorf("wrote %d, kept %d", n, len(b.Bytes()))
	}
	if n, _ := b.Write([]byte("more")); n != 4 || len(b.Bytes()) != maxProcessStderr {
		t.Errorf("full buffer: wrote %d, kept %d", n, len(b.Bytes()))
	}
}

func TestSplitProxyCommandQuotes(t *testing.T) {
	got, err := SplitProxyCommand(`ssm  'a b'"c"	d`)
	if err != nil || strings.Join(got, "|") != "ssm|a bc|d" {
		t.Errorf("got %q, %v", got, err)
	}
	for _, bad := range []string{"", "  ", `nc 'x`, "nc $HOST"} {
		if _, err := SplitProxyCommand(bad); err == nil {
			t.Errorf("%q split", bad)
		}
	}
}
