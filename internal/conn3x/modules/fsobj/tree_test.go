// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package fsobj

import (
	"os"
	"path/filepath"
	"testing"
)

// A recursive mode counts and then changes every path under the directory,
// files and directories each as X says, and never what a link points at.
func TestTreeMode(t *testing.T) {
	top := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, nil, 0o666); err != nil || os.Chmod(outside, 0o666) != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"a/b"} {
		if err := os.MkdirAll(filepath.Join(top, p), 0o777); err != nil {
			t.Fatal(err)
		}
	}
	for name, mode := range map[string]os.FileMode{"a/data": 0o666, "a/b/run.sh": 0o777, "ok": 0o640} {
		if err := os.WriteFile(filepath.Join(top, name), nil, mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(filepath.Join(top, name), mode); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range []string{"a", "a/b"} {
		if err := os.Chmod(filepath.Join(top, p), 0o777); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(outside, filepath.Join(top, "a/link")); err != nil {
		t.Fatal(err)
	}
	d := Directory{Path: top, Mode: "u=rwX,g=rX,o=", Recurse: true}
	if err := d.Validate(); err != nil {
		t.Fatal(err)
	}
	owner := os.Getenv("USER")
	tree, err := ReadTree(ctx, host, d, owner)
	// a, a/b, a/data and a/b/run.sh change; ok is 0640 already; the link
	// isn't counted for a mode.
	if err != nil || tree.Changes != 4 || tree.Skipped != 0 {
		t.Fatalf("before: %+v %v", tree, err)
	}
	if err := ApplyTree(ctx, host, d); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]os.FileMode{"a": 0o750, "a/b": 0o750, "a/data": 0o640, "a/b/run.sh": 0o750, "ok": 0o640} {
		st, err := os.Stat(filepath.Join(top, name))
		if err != nil || st.Mode().Perm() != want {
			t.Errorf("%s: %v %v, want %v", name, st.Mode().Perm(), err, want)
		}
	}
	if st, _ := os.Stat(outside); st.Mode().Perm() != 0o666 {
		t.Errorf("the link's target is now %v", st.Mode().Perm())
	}
	if tree, err := ReadTree(ctx, host, d, owner); err != nil || tree.Changes != 0 {
		t.Fatalf("after: %+v %v", tree, err)
	}
}

// find refuses -execdir with a relative or empty entry in PATH, which
// Conn3x doesn't set, so the walk drops them.
func TestTreeWithARelativePath(t *testing.T) {
	top := t.TempDir()
	if err := os.WriteFile(filepath.Join(top, "f"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", ".:bin::"+os.Getenv("PATH")+":")
	if err := ApplyTree(ctx, host, Directory{Path: top, Mode: "g+r", Recurse: true}); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(filepath.Join(top, "f")); st.Mode().Perm() != 0o640 {
		t.Errorf("f is %v", st.Mode().Perm())
	}
}

// A directory that's in a step but not there yet has nothing under it.
func TestTreeOfAMissingDirectory(t *testing.T) {
	d := Directory{Path: filepath.Join(t.TempDir(), "none"), Mode: "a+X", Recurse: true}
	if tree, err := ReadTree(ctx, host, d, "root"); err != nil || tree != (Tree{}) {
		t.Fatalf("%+v %v", tree, err)
	}
	if err := ApplyTree(ctx, host, d); err != nil {
		t.Fatal(err)
	}
}

func TestTreeValidate(t *testing.T) {
	for _, d := range []Directory{
		{Path: "/srv/app", Mode: "u=rwX", Recurse: false},
		{Path: "/srv/app", Mode: "u+s", Recurse: true},
		{Path: "srv/app", Mode: "u=rwX", Recurse: true},
		{Path: "/", Owner: "deploy", Recurse: true},
		{Path: "//", Mode: "a+X", Recurse: true},
	} {
		if d.Validate() == nil {
			t.Errorf("%+v passed", d)
		}
	}
	// A numeric mode with recurse is the directory's own; the provider
	// refuses one written in the configuration.
	if err := (Directory{Path: "/srv/app", Mode: "0755", Recurse: true}).Validate(); err != nil {
		t.Error(err)
	}
}

// Multiply linked files that aren't the owner's are left and counted.
func TestTreeCount(t *testing.T) {
	d := Directory{Path: "/srv", Owner: "deploy", Recurse: true}
	got := d.count("deploy", []treeRecord{
		{n: 3, kind: "f", user: "root", links: 1},
		{n: 2, kind: "f", user: "root", links: 2},
		{n: 5, kind: "f", user: "deploy", links: 2},
		{n: 1, kind: "l", user: "root", links: 1},
	})
	if got != (Tree{Changes: 4, Skipped: 2}) {
		t.Errorf("%+v", got)
	}
}
