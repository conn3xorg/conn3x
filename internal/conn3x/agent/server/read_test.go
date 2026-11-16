// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package server

import (
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
)

// readFile gives what file.Read's shell command would: the path's own
// mode and owner, and the content of what it points to.
func TestReadFile(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "f")
	if err := os.WriteFile(f, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(f, 0o640); err != nil {
		t.Fatal(err)
	}
	me, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	got, err := readFile(f)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Exists || !got.Regular || string(got.Content) != "hello" || got.Mode != 0o640 || got.Owner != me.Username || got.Group == "" {
		t.Errorf("regular file: %+v", got)
	}

	link := filepath.Join(dir, "link")
	if err := os.Symlink("f", link); err != nil {
		t.Fatal(err)
	}
	if got, err := readFile(link); err != nil || !got.Regular || string(got.Content) != "hello" {
		t.Errorf("link to a file: %+v, %v", got, err)
	}

	dangling := filepath.Join(dir, "dangling")
	if err := os.Symlink("nowhere", dangling); err != nil {
		t.Fatal(err)
	}
	if got, err := readFile(dangling); err != nil || !got.Exists || got.Regular {
		t.Errorf("dangling link: %+v, %v", got, err)
	}

	for name, p := range map[string]string{"missing": filepath.Join(dir, "none"), "under a file": filepath.Join(f, "x")} {
		if got, err := readFile(p); err != nil || got.Exists {
			t.Errorf("%s: %+v, %v", name, got, err)
		}
	}
}

func TestReadFileTooBig(t *testing.T) {
	defer func(old int) { MaxOutput = old }(MaxOutput)
	MaxOutput = 4
	f := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(f, []byte("too long"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readFile(f); err == nil || !strings.Contains(err.Error(), "the most the agent returns") {
		t.Errorf("got %v", err)
	}
}

// An id /etc/passwd or /etc/group doesn't name is an error, which leaves
// the read to the shell.
func TestLookupNames(t *testing.T) {
	uid, gid := uint32(os.Getuid()), uint32(os.Getgid())
	owner, group, err := lookupNames(uid, gid)
	if me, _ := user.Current(); err != nil || owner != me.Username || group == "" {
		t.Errorf("own ids: %q %q %v", owner, group, err)
	}
	if _, _, err := lookupNames(4242424, gid); err == nil {
		t.Error("an unknown uid has a name")
	}
	if _, _, err := lookupNames(uid, 4242424); err == nil {
		t.Error("an unknown gid has a name")
	}
}
