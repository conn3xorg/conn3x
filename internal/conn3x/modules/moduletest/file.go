// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package moduletest

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/opentofu/opentofu/internal/conn3x/modules"
	"github.com/opentofu/opentofu/internal/conn3x/modules/file"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// FileConformance checks file.Read through r against the shell runner sh
// on the same host. It makes each case with sh in a fresh directory, then
// both must give the same Actual, or the same error, and the shell's
// answer must be the one written here. When r is a modules.FileReader it
// must answer every case natively except a file whose owner has no name,
// which it must leave to the shell. Passing sh as r checks the shell
// alone. The unknown-owner case needs root and is skipped without it.
func FileConformance(t *testing.T, sh, r modules.Runner) {
	t.Helper()
	ctx := context.Background()
	dir := strings.TrimSpace(mustRun(t, sh, "mktemp -d"))
	t.Cleanup(func() { _, _ = sh.Run(ctx, "rm -rf -- "+ssh.Quote(dir), nil) })
	me := strings.TrimSpace(mustRun(t, sh, "id -un"))
	// Hosts are Linux. Elsewhere, such as a developer's Mac, the shell's
	// stat drops setuid and a link's mode follows the umask.
	linux := strings.TrimSpace(mustRun(t, sh, "uname -s")) == "Linux"
	big := strings.Repeat("conn3x\n", 4<<20/7+1)[:4<<20]

	for _, c := range []struct {
		name, setup string // setup runs in dir; the path is f
		want        file.Actual
		wantErr     bool // "f exists but is not a regular file"
		fallback    bool // a FileReader must leave it to the shell
		root        bool
		notRoot     bool // root can read anything
		unreadable  bool // "f exists but can't be read"
		linux       bool // only on Linux
	}{
		{name: "missing"},
		{name: "empty", setup: ": > f && chmod 0644 f", want: file.Actual{Exists: true, Mode: "0644", Owner: me}},
		{name: "NUL bytes", setup: `printf 'a\000b\000\377\n' > f && chmod 0640 f`, want: file.Actual{Exists: true, Content: "a\x00b\x00\xff\n", Mode: "0640", Owner: me}},
		{name: "4 MiB", setup: "yes conn3x | head -c 4194304 > f && chmod 0644 f", want: file.Actual{Exists: true, Content: big, Mode: "0644", Owner: me}},
		{name: "mode 0600", setup: "printf x > f && chmod 0600 f", want: file.Actual{Exists: true, Content: "x", Mode: "0600", Owner: me}},
		{name: "mode 0755", setup: "printf x > f && chmod 0755 f", want: file.Actual{Exists: true, Content: "x", Mode: "0755", Owner: me}},
		{name: "mode 4755", setup: "printf x > f && chmod 4755 f", want: file.Actual{Exists: true, Content: "x", Mode: "4755", Owner: me}, linux: true},
		// The mode and owner are the link's own, the content its target's.
		{name: "symlink", setup: "printf target > t && chmod 0640 t && ln -s t f", want: file.Actual{Exists: true, Content: "target", Mode: "0777", Owner: me}},
		// The owner is the link's too, not its target's.
		{name: "symlink owned by nobody", setup: "printf target > t && chmod 0640 t && ln -s t f && chown -h 65534:65534 f", want: file.Actual{Exists: true, Content: "target", Mode: "0777", Owner: "nobody"}, root: true, linux: true},
		{name: "dangling symlink", setup: "ln -s nowhere f", wantErr: true},
		{name: "directory", setup: "mkdir f", wantErr: true},
		// Unreadable is an error, never an empty file the plan would overwrite.
		{name: "unreadable", setup: "printf x > f && chmod 0000 f", unreadable: true, fallback: true, notRoot: true},
		{name: "unknown owner", setup: "printf x > f && chmod 0644 f && chown 4242:4242 f", want: file.Actual{Exists: true, Content: "x", Mode: "0644", Owner: "UNKNOWN", Group: "UNKNOWN"}, fallback: true, root: true},
	} {
		t.Run(c.name, func(t *testing.T) {
			if c.root && me != "root" {
				t.Skip("needs root to chown")
			}
			if c.notRoot && me == "root" {
				t.Skip("root can read any file")
			}
			if c.linux && !linux {
				t.Skip("needs Linux")
			}
			d := dir + "/" + strings.ReplaceAll(c.name, " ", "-")
			setup := "mkdir -- " + ssh.Quote(d)
			if c.setup != "" {
				setup += " && cd -- " + ssh.Quote(d) + " && " + c.setup
			}
			mustRun(t, sh, setup)
			p := d + "/f"

			want, wantErr := file.Read(ctx, sh, p)
			got, gotErr := file.Read(ctx, r, p)
			if errString(gotErr) != errString(wantErr) || got != want {
				t.Fatalf("got %s, %v\nthe shell gives %s, %v", show(got), gotErr, show(want), wantErr)
			}

			switch {
			case c.unreadable:
				if wantErr == nil || wantErr.Error() != p+" exists but can't be read by "+me {
					t.Fatalf("the shell gives %v, want can't be read", wantErr)
				}
			case c.wantErr:
				if wantErr == nil || wantErr.Error() != p+" exists but is not a regular file" {
					t.Fatalf("the shell gives %v, want not a regular file", wantErr)
				}
			case wantErr != nil:
				t.Fatal(wantErr)
			default:
				w := c.want
				if w.Group == "" {
					w.Group = want.Group // the directory's or the user's, by platform
				}
				if c.name == "symlink" && !linux {
					w.Mode = want.Mode
				}
				if want != w {
					t.Fatalf("the shell gives %s, want %s", show(want), show(w))
				}
			}

			if fr, ok := r.(modules.FileReader); ok {
				_, err := fr.ReadFile(ctx, p)
				if c.fallback && !errors.Is(err, errors.ErrUnsupported) {
					t.Fatalf("ReadFile answered %v; it must leave this to the shell", err)
				}
				if !c.fallback && err != nil {
					t.Fatalf("ReadFile: %v; it must answer this itself", err)
				}
			}
		})
	}
}

func mustRun(t *testing.T, r modules.Runner, cmd string) string {
	t.Helper()
	res, err := r.Run(context.Background(), cmd, nil)
	if err == nil && res.ExitCode != 0 {
		err = errors.New(strings.TrimSpace(string(res.Stderr)))
	}
	if err != nil {
		t.Fatalf("%s: %v", cmd, err)
	}
	return string(res.Stdout)
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// show prints an Actual with its content clipped.
func show(a file.Actual) string {
	return fmt.Sprintf("{exists=%v mode=%s owner=%s group=%s content=%q}", a.Exists, a.Mode, a.Owner, a.Group, clip([]byte(a.Content)))
}
