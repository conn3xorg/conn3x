// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package modules_test

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"

	"github.com/opentofu/opentofu/internal/conn3x/modules"
	"github.com/opentofu/opentofu/internal/conn3x/modules/moduletest"
)

const who = "id -un"

func runGuard(t *testing.T, script string, routes ...modules.Route) (string, int, string) {
	t.Helper()
	res, err := moduletest.Local{}.Run(context.Background(), modules.Guard(script, routes...), nil)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(res.Stdout)), res.ExitCode, string(res.Stderr)
}

func TestGuardKeepsTheScriptAsIs(t *testing.T) {
	out, code, _ := runGuard(t, "cat; echo ran; exit 7", modules.Parent(t.TempDir()+"/x"))
	if code != 7 || out != "ran" {
		t.Fatalf("got %q, exit %d", out, code)
	}
}

// Each case builds a tree as root and says who the script must run as, or
// that it must not run. Needs root on Linux; go test -c and run it in a
// container to exercise it.
func TestGuardRoutes(t *testing.T) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Skip("needs root on Linux")
	}
	const kept = "/var/conn3x-route-test"
	const root, refused, asNobody = "root", "", "nobody"

	for _, c := range []struct {
		name, setup string
		route       func(string) modules.Route
		path        string
		want        string
	}{
		{"plain", "mkdir d", modules.Parent, "$T/d/f", root},
		{"missing under root", "", modules.Parent, "$T/a/b/f", root},
		{"root link", "mkdir d; ln -s d l", modules.Follow, "$T/l/f", root},
		{"relative root link going up", "mkdir -p d/e; ln -s ../d d/l", modules.Follow, "$T/d/l/f", root},
		{"absolute root link", "mkdir d; ln -s $T/d l", modules.Follow, "$T/l", root},
		{"parent leaves a leaf link alone", "ln -s /etc l; chown -h nobody l", modules.Parent, "$T/l", root},
		{"link owned by someone", "ln -s /etc l; chown -h nobody l", modules.Follow, "$T/l", asNobody},
		{"link in the middle owned by someone", "ln -s /etc l; chown -h nobody l", modules.Parent, "$T/l/f", asNobody},
		{"directory owned by someone", "mkdir d; chown nobody d", modules.Parent, "$T/d/f", asNobody},
		{"root link into someone's directory", "mkdir d; chown nobody d; ln -s d l", modules.Parent, "$T/l/f", asNobody},
		{"leaf owned by someone", "mkdir d; chown nobody d", modules.Follow, "$T/d", root},
		{"whole minds the leaf", "mkdir d; chown nobody d", modules.Whole, "$T/d", asNobody},
		{"other-writable directory", "mkdir d; chmod 0777 d", modules.Parent, "$T/d/f", refused},
		{"other-writable leaf", "mkdir d; chmod 0777 d", modules.Follow, "$T/d", root},
		{"group-writable, a person's group", "mkdir d; chgrp 2000 d; chmod 0775 d", modules.Parent, "$T/d/f", refused},
		{"group-writable, a quiet system group", "mkdir d; chgrp 999 d; chmod 0775 d", modules.Parent, "$T/d/f", root},
		{"sticky, child of root", "mkdir -m 1777 s; mkdir s/d", modules.Parent, "$T/s/d/f", root},
		{"sticky, child of someone", "mkdir -m 1777 s; mkdir s/d; chown nobody s/d", modules.Parent, "$T/s/d/f", asNobody},
		{"sticky, leaf of someone", "mkdir -m 1777 s; mkdir s/d; chown nobody s/d", modules.Follow, "$T/s/d", asNobody},
		{"sticky, missing leaf", "mkdir -m 1777 s", modules.Follow, "$T/s/f", root},
		{"sticky, missing parent", "mkdir -m 1777 s", modules.Parent, "$T/s/d/f", refused},
		{"no name for the owner", "mkdir d; chown 54321 d", modules.Parent, "$T/d/f", refused},
		{"a link loop", "ln -s b a; ln -s a b", modules.Follow, "$T/a/f", refused},
	} {
		t.Run(c.name, func(t *testing.T) {
			// Not under t.TempDir, whose parents may belong to anyone.
			if err := os.MkdirAll(kept, 0o755); err != nil {
				t.Fatal(err)
			}
			dir, err := os.MkdirTemp(kept, "t")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { os.RemoveAll(dir) })
			if err := os.Chmod(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			setup := exec.Command("sh", "-ec", strings.ReplaceAll(c.setup, "$T", dir))
			setup.Dir = dir
			if out, err := setup.CombinedOutput(); err != nil {
				t.Fatalf("setup: %v\n%s", err, out)
			}
			out, code, stderr := runGuard(t, who, c.route(strings.ReplaceAll(c.path, "$T", dir)))
			if c.want == refused {
				if code != 125 || !strings.Contains(stderr, "refusing ") {
					t.Fatalf("ran as %q, exit %d: %s", out, code, stderr)
				}
				return
			}
			if code != 0 || out != c.want {
				t.Fatalf("got %q, exit %d: %s; want %s", out, code, stderr, c.want)
			}
		})
	}
}
