// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package fsobj

import (
	"context"
	"os/exec"
	"testing"

	"github.com/opentofu/opentofu/internal/conn3x/modules/moduletest"
)

// A filesystem mounted under the directory is left alone, its mount point
// too. Skipped where the test can't mount, as in an unprivileged container.
func TestApplyTreeLeavesMounts(t *testing.T) {
	dir := moduletest.RootDir(t)
	moduletest.Sh(t, dir, `mkdir -p app/data "app/it's [x]" other; echo x >other/f; chmod 0644 other/f`)
	// A bind from the same filesystem has the same device, so -xdev alone
	// would go in; mountinfo writes the space in the second as \040.
	for _, at := range []string{"app/data", "app/it's [x]"} {
		if out, err := exec.Command("mount", "--bind", dir+"/other", dir+"/"+at).CombinedOutput(); err != nil {
			t.Skipf("can't mount here: %v %s", err, out)
		}
		t.Cleanup(func() { _ = exec.Command("umount", dir+"/"+at).Run() })
	}
	d := Directory{Path: dir + "/app", Owner: "nobody", Mode: "u=rwX,g=rX,o=", Recurse: true}
	if tree, err := ReadTree(context.Background(), moduletest.Local{}, d, "nobody"); err != nil || tree != (Tree{}) {
		t.Fatalf("counted across the mount: %+v %v", tree, err)
	}
	if err := ApplyTree(context.Background(), moduletest.Local{}, d); err != nil {
		t.Fatal(err)
	}
	if got := moduletest.Sh(t, dir, "stat -c '%U %a' other other/f"); got != "root 755\nroot 644" {
		t.Fatalf("the mount was changed:\n%s", got)
	}
}
