// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package fsobj

import (
	"context"
	"strings"
	"testing"

	"github.com/opentofu/opentofu/internal/conn3x/modules/moduletest"
)

// A recursive owner goes to everything under the directory but a file with
// another link, and to a link itself, never to what it points at.
func TestApplyTreeOwner(t *testing.T) {
	dir := moduletest.RootDir(t)
	moduletest.Sh(t, dir, `mkdir -p app/a/b; echo x >app/a/b/f; echo s >secret; ln secret app/a/hard; ln -s ../../secret app/a/link`)
	d := Directory{Path: dir + "/app", Owner: "nobody", Mode: "u=rwX,g=rX,o=", Recurse: true}
	tree, err := ReadTree(context.Background(), moduletest.Local{}, d, "nobody")
	// a, a/b, a/b/f and the link change; the hard link is left.
	if err != nil || tree != (Tree{Changes: 4, Skipped: 1}) {
		t.Fatalf("before: %+v %v", tree, err)
	}
	if err := ApplyTree(context.Background(), moduletest.Local{}, d); err != nil {
		t.Fatal(err)
	}
	if got := moduletest.Sh(t, dir, "stat -c '%U %a' app/a app/a/b app/a/b/f secret; stat -c %U app/a/link"); got != "nobody 750\nnobody 750\nnobody 640\nroot 644\nnobody" {
		t.Fatalf("after:\n%s", got)
	}
	if tree, err := ReadTree(context.Background(), moduletest.Local{}, d, "nobody"); err != nil || tree != (Tree{Skipped: 1}) {
		t.Fatalf("after: %+v %v", tree, err)
	}
}

// Without an owner to set, root doesn't change modes in a directory someone
// else could change, and a walk that runs as the owner can't change what
// isn't theirs.
func TestApplyTreeModeOnly(t *testing.T) {
	dir := moduletest.RootDir(t)
	moduletest.Sh(t, dir, `mkdir -p root/theirs nobody/mine; touch root/theirs/x; chown nobody root/theirs root/theirs/x nobody nobody/mine
touch nobody/mine/f nobody/roots; chown nobody nobody/mine/f; chmod 644 nobody/mine/f nobody/roots`)
	err := ApplyTree(context.Background(), moduletest.Local{}, Directory{Path: dir + "/root", Mode: "go-w", Recurse: true})
	if err == nil || !strings.Contains(err.Error(), "as root") {
		t.Errorf("root changed modes in a directory of nobody's: %v", err)
	}
	err = ApplyTree(context.Background(), moduletest.Local{}, Directory{Path: dir + "/nobody", Mode: "o=", Recurse: true})
	if err == nil || !strings.Contains(err.Error(), "roots") {
		t.Errorf("nobody changed root's file: %v", err)
	}
	if got := moduletest.Sh(t, dir, "stat -c %a nobody/mine/f nobody/roots"); got != "640\n644" {
		t.Errorf("modes:\n%s", got)
	}
}
