// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package server

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// What's at the path by the time it's opened may not be what was stat'ed.
// openRegular must refuse anything but that same regular file, and must
// not open it for reading to find out.
func TestOpenRegularRefusesWhatWasNotStated(t *testing.T) {
	dir := t.TempDir()
	reg, other, fifo := filepath.Join(dir, "reg"), filepath.Join(dir, "other"), filepath.Join(dir, "fifo")
	for _, p := range []string{reg, other} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Fatal(err)
	}
	stat := func(p string) *syscall.Stat_t {
		var st syscall.Stat_t
		if err := syscall.Stat(p, &st); err != nil {
			t.Fatal(err)
		}
		return &st
	}

	f, err := openRegular(reg, stat(reg))
	if err != nil {
		t.Fatalf("the file that was stat'ed: %v", err)
	}
	f.Close()
	if f, err := openRegular(other, stat(reg)); err == nil {
		f.Close()
		t.Fatal("opened a different file")
	}
	if f, err := openRegular(fifo, stat(fifo)); err == nil {
		f.Close()
		t.Fatal("opened a FIFO for reading")
	}
}

// A read as root leaves anything someone else could change to the shell.
func TestCheckRoute(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	base, err := os.MkdirTemp("/var", "conn3x-route-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	if err := os.Chmod(base, 0o755); err != nil {
		t.Fatal(err)
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.Mkdir(base+"/d", 0o755))
	must(os.WriteFile(base+"/d/f", []byte("x"), 0o600))
	must(os.Symlink("d/f", base+"/rootlink"))
	must(os.Symlink("../"+filepath.Base(base)+"/d/f", base+"/up"))
	must(os.Symlink(base+"/d/f", base+"/theirlink"))
	must(os.Lchown(base+"/theirlink", 65534, 65534))
	must(os.Mkdir(base+"/theirs", 0o755))
	must(os.Chown(base+"/theirs", 65534, 65534))
	must(os.Mkdir(base+"/open", 0o777))
	must(os.Chmod(base+"/open", 0o777))
	must(os.Mkdir(base+"/sticky", 0o755))
	must(os.Chmod(base+"/sticky", os.ModeSticky|0o777))

	for p, ok := range map[string]bool{
		"/d/f": true, "/missing/f": true, "/rootlink": true, "/up": true, "/theirs": true, "/sticky/f": true,
		"/theirlink": false, "/theirs/f": false, "/open/f": false, "/sticky/a/f": false,
	} {
		if err := checkRoute(base + p); (err == nil) != ok {
			t.Errorf("%s: %v, want ok=%v", p, err, ok)
		}
	}
}
