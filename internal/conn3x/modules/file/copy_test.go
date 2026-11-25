// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package file

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func hash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// A copy of a file on the same host reads both files' hashes, never their
// content, and stops at a source that's missing or not a regular file
// before it writes anything (#1349).
func TestCopySource(t *testing.T) {
	dir := t.TempDir()
	src, dest := filepath.Join(dir, "app.conf.sample"), filepath.Join(dir, "etc", "app.conf")

	a, srcSum, err := ReadCopy(ctx, localRunner{}, dest, src)
	if err != nil || a.Exists || srcSum != "" {
		t.Fatalf("both missing: %+v %q %v", a, srcSum, err)
	}
	err = Apply(ctx, localRunner{}, Desired{Path: dest, Source: src, Mode: "0640"})
	if err == nil || !strings.Contains(err.Error(), "source_path "+src+" doesn't exist on the host") {
		t.Fatalf("missing source: %v", err)
	}
	if _, err := os.Stat(filepath.Dir(dest)); !os.IsNotExist(err) {
		t.Fatalf("a missing source still made %s: %v", filepath.Dir(dest), err)
	}

	if err := os.WriteFile(src, []byte("listen = 80\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Apply(ctx, localRunner{}, Desired{Path: dest, Source: src, Mode: "0640"}); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(dest); string(got) != "listen = 80\n" {
		t.Fatalf("dest = %q", got)
	}
	a, srcSum, err = ReadCopy(ctx, localRunner{}, dest, src)
	if err != nil || !a.Exists || a.Mode != "0640" || a.Content != "" || a.SHA256 != hash("listen = 80\n") || srcSum != a.SHA256 {
		t.Fatalf("after copy: %+v %q %v", a, srcSum, err)
	}
	if NeedsChange(Desired{Path: dest, Source: src, Mode: "0640"}, a) {
		t.Fatal("NeedsChange compared the empty content of a copy")
	}

	if err := os.WriteFile(dest, []byte("edited\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if a, srcSum, _ = ReadCopy(ctx, localRunner{}, dest, src); a.SHA256 == srcSum {
		t.Fatal("a hand edit read as in sync")
	}

	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{fifo, dir} {
		if _, _, err := ReadCopy(ctx, localRunner{}, dest, bad); err == nil || !strings.Contains(err.Error(), "is not a regular file") {
			t.Errorf("ReadCopy from %s: %v", bad, err)
		}
		if err := Apply(ctx, localRunner{}, Desired{Path: dest, Source: bad, Mode: "0640"}); err == nil || !strings.Contains(err.Error(), "is not a regular file") {
			t.Errorf("Apply from %s: %v", bad, err)
		}
	}
	if got, _ := os.ReadFile(dest); string(got) != "edited\n" {
		t.Fatalf("a refused copy changed dest: %q", got)
	}

	if err := (Desired{Path: dest, Source: "app.conf", Mode: "0644"}).Validate(); err == nil || !strings.Contains(err.Error(), "source_path") {
		t.Fatalf("relative source: %v", err)
	}
}

// A source path with a quote and spaces in it stays one argument.
func TestCopySourceQuoting(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, `it's a "file"; $(touch x)`)
	if err := os.WriteFile(src, []byte("q\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(dir, "out")
	if err := Apply(ctx, localRunner{}, Desired{Path: dest, Source: src, Mode: "0644"}); err != nil {
		t.Fatal(err)
	}
	if a, srcSum, err := ReadCopy(ctx, localRunner{}, dest, src); err != nil || a.SHA256 != srcSum {
		t.Fatalf("%+v %q %v", a, srcSum, err)
	}
	// The test runs in the package directory, where touch x would land.
	if _, err := os.Stat("x"); err == nil {
		t.Fatal("the source path ran as shell")
	}
}
