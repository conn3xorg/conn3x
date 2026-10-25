// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package moduletest

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"

	"github.com/opentofu/opentofu/internal/conn3x/modules"
	"github.com/opentofu/opentofu/internal/conn3x/modules/file"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// RunnerConformance checks that the Runner from newRunner behaves like the
// shell on a host: every command here must give the same stdout, stderr
// and exit status as Local, and the file module must work through it.
// The Runner has to run commands on this machine.
func RunnerConformance(t *testing.T, newRunner func(t *testing.T) modules.Runner) {
	t.Helper()
	r := newRunner(t)
	ctx := context.Background()

	in := bytes.Repeat([]byte("conn3x\x00\xff\n"), 8<<20/9)
	for _, c := range []struct {
		name, cmd string
		stdin     []byte
	}{
		{"exit 0", "true", nil},
		{"exit 1", "false", nil},
		{"exit 42", "printf out; printf err >&2; exit 42", nil},
		{"exit 127", "conn3x-no-such-command", nil},
		{"stderr only", "echo oops >&2", nil},
		{"NUL stdin", "cat", []byte("a\x00b\x00\xff")},
		{"8 MiB in and out", "cat", in},
		{"32 MiB out", "head -c 33554432 /dev/zero", nil},
		{"C locale", `printf %s "$LC_ALL"`, nil},
		{"empty command", "", nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			want, err := Local{}.Run(ctx, c.cmd, c.stdin)
			if err != nil {
				t.Fatal(err)
			}
			got, err := r.Run(ctx, c.cmd, c.stdin)
			if err != nil {
				t.Fatal(err)
			}
			if !sameResult(got, want) {
				t.Errorf("got exit %d, stdout %q, stderr %q\nwant exit %d, stdout %q, stderr %q",
					got.ExitCode, clip(got.Stdout), clip(got.Stderr), want.ExitCode, clip(want.Stdout), clip(want.Stderr))
			}
		})
	}

	t.Run("file module", func(t *testing.T) {
		d := file.Desired{Path: filepath.Join(t.TempDir(), "it's a file"), Content: "two\n\nlines\x00", Mode: "0640"}
		if err := file.Apply(ctx, r, d); err != nil {
			t.Fatal(err)
		}
		got, err := file.Read(ctx, r, d.Path)
		if err != nil {
			t.Fatal(err)
		}
		want, err := file.Read(ctx, Local{}, d.Path)
		if err != nil {
			t.Fatal(err)
		}
		if got != want || !got.Exists || got.Content != d.Content || got.Mode != d.Mode {
			t.Errorf("read back %+v, the shell sees %+v", got, want)
		}
	})
}

// sameResult reports whether two results are equal, treating nil and empty
// output alike.
func sameResult(a, b ssh.Result) bool {
	return a.ExitCode == b.ExitCode && bytes.Equal(a.Stdout, b.Stdout) && bytes.Equal(a.Stderr, b.Stderr)
}

// clip shortens output for an error message.
func clip(b []byte) []byte {
	if len(b) > 200 {
		return append(b[:200:200], "..."...)
	}
	return b
}
