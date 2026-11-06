// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build unix

package file

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// Under a hardened login umask (UMASK 027, applied by pam_umask), a file
// step's missing parents come out 0755 and the file keeps its explicit
// mode, private ones included.
func TestApplyUnderLoginUmask027(t *testing.T) {
	old := syscall.Umask(0o027)
	t.Cleanup(func() { syscall.Umask(old) })
	root := t.TempDir()
	for _, mode := range []string{"0600", "0640", "0644", "0755"} {
		dir := filepath.Join(root, mode, "missing", "nested")
		path := filepath.Join(dir, "f")
		if err := Apply(ctx, localRunner{}, Desired{Path: path, Content: "x", Mode: mode}); err != nil {
			t.Fatal(err)
		}
		for _, p := range []string{filepath.Join(root, mode), filepath.Dir(dir), dir} {
			if st, err := os.Stat(p); err != nil || st.Mode().Perm() != 0o755 {
				t.Fatalf("parent %s: %v, %v; want 0755", p, st.Mode().Perm(), err)
			}
		}
		a, err := Read(ctx, localRunner{}, path)
		if err != nil || a.Mode != mode {
			t.Fatalf("file mode %q, %v; want %s", a.Mode, err, mode)
		}
	}
}
