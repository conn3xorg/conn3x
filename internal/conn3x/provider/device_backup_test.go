// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWriteDeviceBackup(t *testing.T) {
	backupNow = func() time.Time { return time.Date(2026, 11, 14, 10, 30, 0, 0, time.UTC) }
	t.Cleanup(func() { backupNow = time.Now })
	dir := filepath.Join(t.TempDir(), "backups")
	for i, want := range []string{"10.0.0.1-20261114T103000Z.cfg", "10.0.0.1-20261114T103000Z-2.cfg"} {
		if err := writeDeviceBackup(dir, "10.0.0.1", "hostname sw1\n"); err != nil {
			t.Fatal(err)
		}
		fi, err := os.Stat(filepath.Join(dir, want))
		if err != nil {
			t.Fatalf("backup %d: %v", i+1, err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("%s mode = %v, want 0600", want, fi.Mode().Perm())
		}
	}
	if di, _ := os.Stat(dir); di.Mode().Perm() != 0o700 {
		t.Errorf("dir mode = %v, want 0700", di.Mode().Perm())
	}
	// An IPv6 address or a host with a path separator stays one file name.
	if err := writeDeviceBackup(dir, "fd00::1", "x"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "fd00__1-20261114T103000Z.cfg")); err != nil {
		t.Error(err)
	}
}
