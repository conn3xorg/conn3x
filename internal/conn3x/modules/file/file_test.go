// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package file

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/opentofu/opentofu/internal/conn3x/modules"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// localRunner runs commands with the local sh, like a host would.
type localRunner struct{}

func (localRunner) Run(ctx context.Context, cmd string, stdin []byte) (ssh.Result, error) {
	c := exec.CommandContext(ctx, "sh", "-c", "export LC_ALL=C; "+cmd)
	c.Stdin = bytes.NewReader(stdin)
	var out, errb bytes.Buffer
	c.Stdout, c.Stderr = &out, &errb
	err := c.Run()
	res := ssh.Result{Stdout: out.Bytes(), Stderr: errb.Bytes()}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		res.ExitCode = exit.ExitCode()
		return res, nil
	}
	return res, err
}

var ctx = context.Background()

func TestReadMissing(t *testing.T) {
	a, err := Read(ctx, localRunner{}, filepath.Join(t.TempDir(), "nope"))
	if err != nil {
		t.Fatal(err)
	}
	if a.Exists {
		t.Fatal("missing file reported as existing")
	}
}

func TestApplyRoundTrip(t *testing.T) {
	dir := t.TempDir()
	for i, content := range []string{"a", "", "no newline", "line\n", "ünïcode\tx\n", "two\n\nblank\n"} {
		path := filepath.Join(dir, "f", "..", "f"+string(rune('a'+i)))
		d := Desired{Path: path, Content: content, Mode: "0644"}
		if err := Apply(ctx, localRunner{}, d); err != nil {
			t.Fatalf("Apply(%q): %v", content, err)
		}
		a, err := Read(ctx, localRunner{}, path)
		if err != nil {
			t.Fatal(err)
		}
		if !a.Exists || a.Content != content {
			t.Fatalf("round-trip %q: got exists=%v %q", content, a.Exists, a.Content)
		}
		if NeedsChange(d, a) {
			t.Fatalf("NeedsChange true right after Apply for %q", content)
		}
	}
}

func TestAwkwardPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "it's a $(file)")
	if err := Apply(ctx, localRunner{}, Desired{Path: path, Content: "x", Mode: "0644"}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "x" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestModeApplied(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	if err := Apply(ctx, localRunner{}, Desired{Path: path, Content: "s", Mode: "0600"}); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(path)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o, want 600", st.Mode().Perm())
	}
	a, _ := Read(ctx, localRunner{}, path)
	if a.Mode != "0600" {
		t.Fatalf("Read mode %q, want 0600", a.Mode)
	}
	if NeedsChange(Desired{Path: path, Content: "s", Mode: "0644"}, a) == false {
		t.Fatal("mode difference not detected")
	}
}

func TestDriftDetected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "motd")
	d := Desired{Path: path, Content: "hello\n", Mode: "0644"}
	if err := Apply(ctx, localRunner{}, d); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("hacked\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	a, _ := Read(ctx, localRunner{}, path)
	if !NeedsChange(d, a) || a.Content != "hacked\n" {
		t.Fatalf("drift not detected: %+v", a)
	}
}

func TestDelete(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gone")
	_ = os.WriteFile(path, []byte("x"), 0o644)
	if err := Delete(ctx, localRunner{}, path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("file still exists")
	}
	if err := Delete(ctx, localRunner{}, path); err != nil {
		t.Fatalf("deleting a missing file: %v", err)
	}
}

func TestFailedApplyLeavesNothingBehind(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f")
	err := Apply(ctx, localRunner{}, Desired{Path: path, Content: "x", Mode: "0644", Owner: "no-such-user-conn3x"})
	if err == nil {
		t.Fatal("chown to a missing user succeeded")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatalf("left behind: %v", entries)
	}
}

func TestReadRejectsDirectory(t *testing.T) {
	if _, err := Read(ctx, localRunner{}, t.TempDir()); err == nil {
		t.Fatal("reading a directory as a file succeeded")
	}
}

func TestValidate(t *testing.T) {
	for _, bad := range []Desired{
		{Path: "relative", Mode: "0644"},
		{Path: "/x", Mode: "644x"},
		{Path: "/x", Mode: "99999"},
		{Path: "", Mode: "0644"},
		{Path: "/x", Mode: "644"}, // plan would rewrite it, which OpenTofu rejects
		{Path: "/x", Mode: "00644"},
	} {
		if err := bad.Validate(); err == nil {
			t.Errorf("Validate(%+v) accepted", bad)
		}
	}
	if err := (Desired{Path: "/etc/motd", Mode: "0644"}).Validate(); err != nil {
		t.Errorf("valid desired rejected: %v", err)
	}
}

// recordRunner keeps the scripts it's given and runs them locally.
type recordRunner struct{ scripts []string }

func (r *recordRunner) Run(ctx context.Context, cmd string, stdin []byte) (ssh.Result, error) {
	r.scripts = append(r.scripts, cmd)
	return localRunner{}.Run(ctx, cmd, stdin)
}

// The new content must reach the disk before the rename, and the rename
// itself must reach it after, or a power cut can leave an empty file.
func TestApplySyncsBeforeAndAfterRename(t *testing.T) {
	r := &recordRunner{}
	p := filepath.Join(t.TempDir(), "motd")
	if err := Apply(context.Background(), r, Desired{Path: p, Content: "hi\n", Mode: "0644"}); err != nil {
		t.Fatal(err)
	}
	script := r.scripts[len(r.scripts)-1]
	syncTmp, rename, syncDir := strings.Index(script, `sync -- "$tmp"`), strings.Index(script, `mv -f -- "$tmp"`), strings.Index(script, `sync -- "$(dirname -- "$p")"`)
	if syncTmp < 0 || rename < 0 || syncDir < 0 || syncTmp > rename || rename > syncDir {
		t.Fatalf("want sync of the temp file, then the rename, then sync of the directory:\n%s", script)
	}
	if got, _ := os.ReadFile(p); string(got) != "hi\n" {
		t.Fatalf("content = %q", got)
	}
}

// fastRunner answers ReadFile with read, and runs commands locally.
type fastRunner struct {
	recordRunner
	read func(path string) (modules.FileStat, error)
}

func (r *fastRunner) ReadFile(_ context.Context, path string) (modules.FileStat, error) {
	return r.read(path)
}

func TestReadUsesFileReader(t *testing.T) {
	r := &fastRunner{read: func(string) (modules.FileStat, error) {
		return modules.FileStat{Exists: true, Regular: true, Mode: 0o4755, Owner: "root", Group: "wheel", Content: []byte("x\x00")}, nil
	}}
	a, err := Read(ctx, r, "/etc/motd")
	if err != nil {
		t.Fatal(err)
	}
	if want := (Actual{Exists: true, Content: "x\x00", Mode: "4755", Owner: "root", Group: "wheel"}); a != want {
		t.Fatalf("got %+v, want %+v", a, want)
	}
	if len(r.scripts) != 0 {
		t.Fatalf("ran %q as well", r.scripts)
	}

	r.read = func(string) (modules.FileStat, error) { return modules.FileStat{}, nil }
	if a, err := Read(ctx, r, "/nope"); err != nil || a != (Actual{}) {
		t.Fatalf("missing: got %+v, %v", a, err)
	}
	r.read = func(string) (modules.FileStat, error) { return modules.FileStat{Exists: true}, nil }
	if _, err := Read(ctx, r, "/etc"); err == nil || err.Error() != "/etc exists but is not a regular file" {
		t.Fatalf("not regular: %v", err)
	}
}

func TestReadFallsBackOnlyWhenUnsupported(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f")
	if err := os.WriteFile(p, []byte("hi"), 0o640); err != nil {
		t.Fatal(err)
	}
	r := &fastRunner{read: func(string) (modules.FileStat, error) {
		return modules.FileStat{}, fmt.Errorf("conn3x agent: no names: %w", errors.ErrUnsupported)
	}}
	a, err := Read(ctx, r, p)
	if err != nil || a.Content != "hi" || a.Mode != "0640" || len(r.scripts) != 1 {
		t.Fatalf("got %+v, %v after running %q; want the shell's answer", a, err, r.scripts)
	}

	// Anything else, such as the agent dying, is the answer: the shell
	// is never tried behind its back.
	gone := errors.New("the conn3x agent stopped")
	r = &fastRunner{read: func(string) (modules.FileStat, error) { return modules.FileStat{}, gone }}
	if _, err := Read(ctx, r, p); !errors.Is(err, gone) || len(r.scripts) != 0 {
		t.Fatalf("got %v after running %q; want the agent's error and no shell", err, r.scripts)
	}
}
