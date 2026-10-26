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
