// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package fsobj

import (
	"context"
	"encoding/binary"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

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

// A directory of root's with an ACL is refused as root's chmod walk goes
// in, and the error says it's the ACL.
func TestApplyTreeModeRefusesAnACL(t *testing.T) {
	dir := moduletest.RootDir(t)
	moduletest.Sh(t, dir, `mkdir -p -m 0755 app/conf; touch app/conf/x; chmod 0644 app/conf/x`)
	// What setfacl -m u:nobody:rwx writes, set directly since the test
	// images have no setfacl: version 2, then tag, permissions and id for
	// the owner, nobody, the group, the mask and others.
	acl := binary.LittleEndian.AppendUint32(nil, 2)
	for _, e := range [][3]uint32{{0x01, 7, ^uint32(0)}, {0x02, 7, 65534}, {0x04, 5, ^uint32(0)}, {0x10, 7, ^uint32(0)}, {0x20, 5, ^uint32(0)}} {
		acl = binary.LittleEndian.AppendUint16(acl, uint16(e[0]))
		acl = binary.LittleEndian.AppendUint16(acl, uint16(e[1]))
		acl = binary.LittleEndian.AppendUint32(acl, e[2])
	}
	if err := unix.Setxattr(dir+"/app/conf", "system.posix_acl_access", acl, 0); err != nil {
		t.Skipf("can't set an ACL here: %v", err)
	}
	if got := moduletest.Sh(t, dir, "ls -ld app/conf | cut -c1-11"); got != "drwxrwxr-x+" {
		t.Fatalf("the ACL didn't take: %s", got)
	}
	err := ApplyTree(context.Background(), moduletest.Local{}, Directory{Path: dir + "/app", Mode: "o=", Recurse: true})
	if err == nil || !strings.Contains(err.Error(), "app/conf as root: it has an ACL") {
		t.Errorf("root changed modes in a directory with an ACL: %v", err)
	}
	if got := moduletest.Sh(t, dir, "stat -c %a app/conf/x"); got != "644" {
		t.Errorf("x is now %s", got)
	}
}
