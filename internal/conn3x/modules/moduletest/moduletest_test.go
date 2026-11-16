// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package moduletest

import (
	"bytes"
	"context"
	"errors"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/opentofu/opentofu/internal/conn3x/modules"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// The shell must pass its own conformance checks, or they test nothing.
func TestLocalConforms(t *testing.T) {
	RunnerConformance(t, func(*testing.T) modules.Runner { return Local{} })
	FileConformance(t, Local{}, Local{})
}

func TestLocalExitStatus(t *testing.T) {
	ctx := context.Background()
	res, err := Local{}.Run(ctx, "printf out; printf err >&2; exit 3", nil)
	if err != nil || res.ExitCode != 3 || string(res.Stdout) != "out" || string(res.Stderr) != "err" {
		t.Fatalf("got %+v, %v", res, err)
	}
	if res, _ := (Local{}).Run(ctx, "kill -TERM $$", nil); res.ExitCode != 128+15 {
		t.Errorf("killed by TERM: exit %d, want 143", res.ExitCode)
	}
	// A context that is already done never starts the shell: the error
	// is Go's, not an exit status.
	done, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := (Local{}).Run(done, "true", nil); err == nil {
		t.Error("a cancelled context ran the command")
	}
}

func TestSh(t *testing.T) {
	dir := t.TempDir()
	if got := Sh(t, dir, "echo hi > f; cat f; echo"); got != "hi" {
		t.Errorf("got %q, want the output trimmed", got)
	}
	if _, err := os.Stat(dir + "/f"); err != nil {
		t.Errorf("the script didn't run in dir: %v", err)
	}
}

func TestRootDir(t *testing.T) {
	ran := false
	t.Run("root", func(t *testing.T) {
		dir := RootDir(t)
		ran = true
		if fi, err := os.Stat(dir); err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o755 || !strings.HasPrefix(dir, "/var/conn3x-route-test/") {
			t.Errorf("got %s, %v", dir, err)
		}
	})
	if want := runtime.GOOS == "linux" && os.Geteuid() == 0; ran != want {
		t.Errorf("ran as root on Linux = %v, want %v", ran, want)
	}
}

func TestHelpers(t *testing.T) {
	if !sameResult(ssh.Result{Stdout: nil}, ssh.Result{Stdout: []byte{}}) {
		t.Error("nil and empty output differ")
	}
	if sameResult(ssh.Result{ExitCode: 1}, ssh.Result{}) || sameResult(ssh.Result{Stderr: []byte("x")}, ssh.Result{}) {
		t.Error("different results are the same")
	}
	long := bytes.Repeat([]byte("a"), 300)
	if got := clip(long); len(got) != 203 || !bytes.HasSuffix(got, []byte("...")) || len(long) != 300 || long[200] != 'a' {
		t.Errorf("clip gave %d bytes and changed its input", len(got))
	}
	if got := clip([]byte("short")); string(got) != "short" {
		t.Errorf("clip(short) = %q", got)
	}
	if errString(nil) != "" || errString(errors.New("x")) != "x" {
		t.Error("errString")
	}
	if got := mustRun(t, Local{}, "echo hi"); got != "hi\n" {
		t.Errorf("mustRun = %q", got)
	}
}
