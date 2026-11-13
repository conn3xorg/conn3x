// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package dircopy

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/opentofu/opentofu/internal/conn3x/modules/moduletest"
)

// gnu skips where find has no -printf, as on macOS: the hosts are Linux.
func gnu(t *testing.T) {
	t.Helper()
	if exec.Command("find", ".", "-maxdepth", "0", "-printf", "").Run() != nil {
		t.Skip("needs GNU find")
	}
}

func write(t *testing.T, p string, b []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestCopyRoundTrip(t *testing.T) {
	gnu(t)
	ctx, r := context.Background(), moduletest.Local{}
	src, dest := t.TempDir(), filepath.Join(t.TempDir(), "site")
	write(t, filepath.Join(src, "index.html"), []byte("<h1>hi</h1>\n"))
	write(t, filepath.Join(src, "img/logo.bin"), []byte{0, 1, 2, 255, '\n', 0})
	write(t, filepath.Join(src, "a dir/with space.txt"), []byte("spaced\n"))
	c := Copy{Source: src, Dest: dest, Mode: "0640", Delete: true}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}

	files, err := c.Local()
	if err != nil {
		t.Fatal(err)
	}
	sums := Sums(files)
	have, err := Read(ctx, r, dest)
	if err != nil || len(have) != 0 {
		t.Fatalf("missing destination: %v, %v", have, err)
	}
	plan := c.Diff(sums, have)
	if want := []string{"a dir/with space.txt", "img/logo.bin", "index.html"}; !slices.Equal(plan.Write, want) {
		t.Fatalf("first plan writes %q, want %q", plan.Write, want)
	}
	if err := c.Apply(ctx, r, files, plan); err != nil {
		t.Fatal(err)
	}
	have, err = Read(ctx, r, dest)
	if err != nil {
		t.Fatal(err)
	}
	if p := c.Diff(sums, have); !p.Empty() {
		t.Fatalf("after apply still plans %+v", p)
	}
	if got, _ := os.ReadFile(filepath.Join(dest, "img/logo.bin")); string(got) != string(files["img/logo.bin"]) {
		t.Errorf("binary file came out as %q", got)
	}

	// A hand edit and a stray file: the edit is written back, the stray removed.
	write(t, filepath.Join(dest, "index.html"), []byte("edited\n"))
	write(t, filepath.Join(dest, "stray.txt"), []byte("x"))
	have, _ = Read(ctx, r, dest)
	plan = c.Diff(sums, have)
	if !slices.Equal(plan.Write, []string{"index.html"}) || !slices.Equal(plan.Remove, []string{"stray.txt"}) {
		t.Fatalf("plan = %+v", plan)
	}
	if err := c.Apply(ctx, r, files, plan); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dest, "stray.txt")); !os.IsNotExist(err) {
		t.Error("stray file is still there")
	}

	// Without delete, files that aren't the step's stay.
	write(t, filepath.Join(dest, "theirs.txt"), []byte("x"))
	c.Delete = false
	have, _ = Read(ctx, r, dest)
	if p := c.Diff(sums, have); !p.Empty() {
		t.Errorf("without delete, plans %+v", p)
	}
}

func TestLocalRefusesLinks(t *testing.T) {
	src := t.TempDir()
	write(t, filepath.Join(src, "real"), []byte("x"))
	if err := os.Symlink("/etc/passwd", filepath.Join(src, "link")); err != nil {
		t.Skip(err)
	}
	_, err := Copy{Source: src}.Local()
	if err == nil || !strings.Contains(err.Error(), "link") {
		t.Fatalf("err = %v", err)
	}
}

func TestValidate(t *testing.T) {
	for _, c := range []Copy{
		{Source: "s", Dest: "relative", Mode: "0644"},
		{Source: "s", Dest: "/", Mode: "0644"},
		{Source: "s", Dest: "/srv/../etc", Mode: "0644"},
		{Source: "", Dest: "/srv/site", Mode: "0644"},
		{Source: "s", Dest: "/srv/site", Mode: "644"},
	} {
		if c.Validate() == nil {
			t.Errorf("%+v passed", c)
		}
	}
}
