// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build unix

package ssh

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh/sshtest"
)

// loginUmask gives the test server's commands the umask a hardened host's
// login session has: pam_umask applies UMASK 027 from /etc/login.defs, and
// sudo keeps it. The server's commands inherit this process's umask.
func loginUmask(t *testing.T) {
	old := syscall.Umask(0o027)
	t.Cleanup(func() { syscall.Umask(old) })
}

func perm(t *testing.T, path string) os.FileMode {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return st.Mode().Perm()
}

// Missing parents come out 0755 under a 027 login umask, and an explicit
// mode is still what it says, through Run and through Become.
func TestRunIgnoresLoginUmask(t *testing.T) {
	loginUmask(t)
	s := sshtest.New(t)
	s.FakeSudo(t, "nopasswd")
	c := dial(t, testConfig(t, s))
	runners := map[string]func(context.Context, string, []byte) (Result, error){
		"run":    c.Run,
		"become": (&Become{Client: c}).Run,
	}
	for name, run := range runners {
		dir := filepath.Join(t.TempDir(), name)
		cmd := `set -e; d=` + Quote(dir) + `
mkdir -p "$d/a/b"
mkdir -m 0700 "$d/private"
: > "$d/a/b/plain"
(umask 077; : > "$d/a/b/secret")
chmod 0640 "$d/a/b/plain"`
		if res, err := run(context.Background(), cmd, nil); err != nil || res.ExitCode != 0 {
			t.Fatalf("%s: %v, exit %d: %s", name, err, res.ExitCode, res.Stderr)
		}
		for path, want := range map[string]os.FileMode{
			dir:                 0o755,
			dir + "/a":          0o755,
			dir + "/a/b":        0o755,
			dir + "/private":    0o700,
			dir + "/a/b/plain":  0o640,
			dir + "/a/b/secret": 0o600,
		} {
			if got := perm(t, path); got != want {
				t.Errorf("%s: %s is %o, want %o", name, path, got, want)
			}
		}
	}
}
