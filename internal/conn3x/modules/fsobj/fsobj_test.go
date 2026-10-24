// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package fsobj

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/opentofu/opentofu/internal/conn3x/modules/moduletest"
)

var ctx = context.Background()
var host = moduletest.Local{}

func TestDirectoryLifecycle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a", "b", "it's here")
	d := Directory{Path: path, Mode: "0750"}
	a, err := ReadDirectory(ctx, host, path)
	if err != nil || a.Exists {
		t.Fatalf("before: %+v %v", a, err)
	}
	if !DirectoryNeedsChange(d, a) {
		t.Fatal("missing directory not detected")
	}
	if err := ApplyDirectory(ctx, host, d); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil || !st.IsDir() || st.Mode().Perm() != 0o750 {
		t.Fatalf("created %v %v", st, err)
	}
	if a, _ = ReadDirectory(ctx, host, path); DirectoryNeedsChange(d, a) || a.Mode != "0750" {
		t.Fatalf("after apply still needs change: %+v", a)
	}
}

func TestDirectoryRejectsAFileInTheWay(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	_ = os.WriteFile(path, nil, 0o644)
	if _, err := ReadDirectory(ctx, host, path); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("err = %v", err)
	}
}

func TestDeleteDirectoryOnlyWhenEmpty(t *testing.T) {
	dir := t.TempDir()
	full := filepath.Join(dir, "full")
	_ = os.MkdirAll(full, 0o755)
	_ = os.WriteFile(filepath.Join(full, "keep"), nil, 0o644)
	if err := DeleteDirectory(ctx, host, full); err == nil || !strings.Contains(err.Error(), "not empty") {
		t.Fatalf("deleting a non-empty directory: %v", err)
	}
	if _, err := os.Stat(filepath.Join(full, "keep")); err != nil {
		t.Fatal("content was removed")
	}
	empty := filepath.Join(dir, "empty")
	_ = os.MkdirAll(empty, 0o755)
	if err := DeleteDirectory(ctx, host, empty); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(empty); !os.IsNotExist(err) {
		t.Fatal("empty directory still exists")
	}
}

func TestLinkLifecycle(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "current")
	l := Link{Path: path, Target: "releases/v1"}
	if a, _ := ReadLink(ctx, host, path); a.Exists || !LinkNeedsChange(l, a) {
		t.Fatalf("before: %+v", a)
	}
	if err := ApplyLink(ctx, host, l); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.Readlink(path); got != "releases/v1" {
		t.Fatalf("link -> %q", got)
	}
	l.Target = "releases/v2"
	a, _ := ReadLink(ctx, host, path)
	if !LinkNeedsChange(l, a) {
		t.Fatal("target change not detected")
	}
	if err := ApplyLink(ctx, host, l); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.Readlink(path); got != "releases/v2" {
		t.Fatalf("link -> %q after retarget", got)
	}
	if err := DeleteLink(ctx, host, path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("link still exists")
	}
}

func TestLinkRefusesToReplaceARealFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data")
	_ = os.WriteFile(path, []byte("precious"), 0o644)
	if err := ApplyLink(ctx, host, Link{Path: path, Target: "/etc/hosts"}); err == nil || !strings.Contains(err.Error(), "not a symlink") {
		t.Fatalf("err = %v", err)
	}
	if err := DeleteLink(ctx, host, path); err == nil {
		t.Fatal("deleting a real file as a link succeeded")
	}
	if got, _ := os.ReadFile(path); string(got) != "precious" {
		t.Fatal("real file was touched")
	}
}

func TestRetargetALinkThatPointsAtADirectory(t *testing.T) {
	dir := t.TempDir()
	for _, d := range []string{"releases/v1", "releases/v2"} {
		_ = os.MkdirAll(filepath.Join(dir, d), 0o755)
	}
	path := filepath.Join(dir, "current")
	if err := ApplyLink(ctx, host, Link{Path: path, Target: "releases/v1"}); err != nil {
		t.Fatal(err)
	}
	if err := ApplyLink(ctx, host, Link{Path: path, Target: "releases/v2"}); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.Readlink(path); got != "releases/v2" {
		t.Fatalf("link -> %q, want releases/v2", got)
	}
	if entries, _ := os.ReadDir(filepath.Join(dir, "releases", "v1")); len(entries) != 0 {
		t.Fatalf("something was moved into the old target: %v", entries)
	}
}
