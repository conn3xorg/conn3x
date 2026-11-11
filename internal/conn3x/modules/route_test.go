// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package modules_test

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"

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
		{"group-writable, a system group nobody is in", "groupadd -f -g 970 conn3xquiet; mkdir d; chgrp 970 d; chmod 0775 d", modules.Parent, "$T/d/f", root},
		{"sticky, child of root", "mkdir -m 1777 s; mkdir s/d", modules.Parent, "$T/s/d/f", root},
		{"sticky, child of someone", "mkdir -m 1777 s; mkdir s/d; chown nobody s/d", modules.Parent, "$T/s/d/f", asNobody},
		{"sticky, leaf of someone", "mkdir -m 1777 s; mkdir s/d; chown nobody s/d", modules.Follow, "$T/s/d", asNobody},
		{"sticky, missing leaf", "mkdir -m 1777 s", modules.Follow, "$T/s/f", root},
		{"sticky, missing parent", "mkdir -m 1777 s", modules.Parent, "$T/s/d/f", refused},
		{"group-writable, the group of one service account", "mkdir d; chgrp daemon d; chmod 0775 d", modules.Parent, "$T/d/f", "daemon"},
		{"group-writable, one service account is in the group", "groupadd -f -g 971 conn3xsvc; usermod -aG conn3xsvc daemon; mkdir d; chgrp 971 d; chmod 0775 d", modules.Parent, "$T/d/f", "daemon"},
		{"group-writable, two accounts are in the group", "groupadd -f -g 972 conn3xtwo; usermod -aG conn3xtwo daemon; usermod -aG conn3xtwo bin; mkdir d; chgrp 972 d; chmod 0775 d", modules.Parent, "$T/d/f", refused},
		{"group-writable, one account's group with an ACL too", "command -v setfacl >/dev/null || exit 77; mkdir d; chgrp daemon d; chmod 0775 d; setfacl -m u:nobody:rwx d", modules.Parent, "$T/d/f", refused},
		{"an ACL that lets someone write", "command -v setfacl >/dev/null || exit 77; mkdir d; setfacl -m u:nobody:rwx d", modules.Parent, "$T/d/f", refused},
		{"an ACL that only lets someone read", "command -v setfacl >/dev/null || exit 77; mkdir d; setfacl -m u:nobody:r-x d", modules.Parent, "$T/d/f", root},
		{"dot-dot after a link into someone's tree", "mkdir -p u/d/e; chown -R nobody u; ln -s u/d/e cur", modules.Parent, "$T/cur/../conf/f", asNobody},
		{"dot-dot back into root's", "mkdir -p d/e", modules.Parent, "$T/d/e/../f", root},
		{"whole minds a leaf anyone can write", "mkdir d; chmod 0777 d", modules.Whole, "$T/d", refused},
		{"whole refuses a sticky leaf", "mkdir -m 1777 s", modules.Whole, "$T/s", refused},
		{"no name for the owner", "mkdir d; chown 54321 d", modules.Parent, "$T/d/f", refused},
		{"a link loop", "ln -s b a; ln -s a b", modules.Follow, "$T/a/f", refused},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := moduletest.RootDir(t)
			setup := exec.Command("sh", "-ec", strings.ReplaceAll(c.setup, "$T", dir))
			setup.Dir = dir
			if out, err := setup.CombinedOutput(); err != nil {
				if setup.ProcessState.ExitCode() == 77 {
					t.Skip("the host lacks a tool this case needs")
				}
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

// A script that runs as the user who owns the way there never holds a group
// that user isn't in. Root gives the group afterwards, to the file the user
// wrote and to nothing a swapped path leads to.
func TestGuardWriteGroup(t *testing.T) {
	dir := moduletest.RootDir(t)
	moduletest.Sh(t, dir, "mkdir d; chown nobody d; echo kept > roots; chmod 0600 roots")
	run := func(script string, w modules.Write, p string) (string, int, string) {
		t.Helper()
		w.Path = p
		res, err := moduletest.Local{}.Run(context.Background(), modules.GuardWrite(script, w, modules.Parent(p)), nil)
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(string(res.Stdout)), res.ExitCode, string(res.Stderr)
	}
	f := dir + "/d/f"
	out, code, stderr := run(`id -G; echo "$CONN3X_ROUTE_OWN"; : > `+f, modules.Write{Group: "root"}, f)
	if code != 0 || strings.Contains(" "+strings.SplitN(out, "\n", 2)[0]+" ", " 0 ") || !strings.HasSuffix(out, "later") {
		t.Fatalf("the script ran with groups and flag %q, exit %d: %s", out, code, stderr)
	}
	if got := moduletest.Sh(t, dir, "stat -c %U:%G d/f"); got != "nobody:root" {
		t.Fatalf("the file is %s", got)
	}
	// A directory gets its group the same way.
	if _, code, stderr := run("mkdir "+dir+"/d/sub", modules.Write{Group: "root"}, dir+"/d/sub"); code != 0 || moduletest.Sh(t, dir, "stat -c %U:%G d/sub") != "nobody:root" {
		t.Fatalf("a directory, exit %d: %s", code, stderr)
	}
	// What the user left at the path instead of their own file is refused
	// and untouched: a link, a hard link, someone else's file.
	for _, planted := range []string{"ln -s ../roots " + dir + "/d/l", "ln " + dir + "/d/f " + dir + "/d/l", "mkfifo " + dir + "/d/l"} {
		moduletest.Sh(t, dir, "rm -f d/l; chgrp daemon roots d/f")
		if _, code, _ := run(planted, modules.Write{Group: "root"}, dir+"/d/l"); code != 125 {
			t.Errorf("%s: exit %d", planted, code)
		}
		if got := moduletest.Sh(t, dir, "stat -c %G roots d/f | tr '\n' ' '; cat roots"); got != "daemon daemon kept" {
			t.Errorf("%s: groups and root's file are now %q", planted, got)
		}
	}
	// A group of the user's own needs no help.
	own := moduletest.Sh(t, dir, "id -gn nobody")
	if out, code, stderr := run(`echo "${CONN3X_ROUTE_OWN:-own}"`, modules.Write{Group: own}, f); code != 0 || out != "own" {
		t.Fatalf("with nobody's own group: %q, exit %d: %s", out, code, stderr)
	}
	// Someone else as owner is still refused in a directory that is a user's.
	if _, code, stderr := run("true", modules.Write{Owner: "root"}, f); code != 125 || !strings.Contains(stderr, "can't give a file to root") {
		t.Fatalf("owner root in nobody's directory, exit %d: %s", code, stderr)
	}
}

// Root looks at what the user left by name before it opens it, and the user
// can swap in a FIFO in between. Opening one would wait for a writer for
// ever: the step has to come back.
func TestGuardWriteComesBackFromAFIFO(t *testing.T) {
	dir := moduletest.RootDir(t)
	moduletest.Sh(t, dir, "mkdir d; chown nobody d; : > d/f; chown nobody d/f")
	// The user swaps a file and a FIFO at the path, over and over.
	swap := exec.Command("runuser", "-u", "nobody", "--", "sh", "-c", "cd "+dir+"/d && while :; do mkfifo p; mv -f p f; : > r; mv -f r f; done")
	if err := swap.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = swap.Process.Kill(); _, _ = swap.Process.Wait() })
	f := dir + "/d/f"
	guarded := modules.GuardWrite("true", modules.Write{Group: "root", Path: f}, modules.Parent(f))
	for start := time.Now(); time.Since(start) < 30*time.Second; {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		began := time.Now()
		res, err := moduletest.Local{}.Run(ctx, guarded, nil)
		late := ctx.Err() != nil
		cancel()
		if late {
			t.Fatal("root is still waiting on the FIFO after a minute")
		}
		if err != nil {
			t.Fatal(err)
		}
		// Only an open that had to be given up takes this long.
		if time.Since(began) > 5*time.Second {
			if res.ExitCode != 125 {
				t.Fatalf("root gave up on the FIFO with exit %d: %s", res.ExitCode, res.Stderr)
			}
			return
		}
	}
	t.Log("the swap never landed between root's look and its open: nothing was tested")
}

// A directory of root's that one service account's group can write to is
// worked in as that account, and root gives the result the owner asked for.
func TestGuardWriteInAServiceGroupsDirectory(t *testing.T) {
	dir := moduletest.RootDir(t)
	moduletest.Sh(t, dir, "mkdir d; chgrp daemon d; chmod 0775 d")
	f := dir + "/d/zone"
	res, err := moduletest.Local{}.Run(context.Background(), modules.GuardWrite("id -un; : > "+f+"; chmod 4755 "+f, modules.Write{Owner: "root", Group: "daemon", Path: f}, modules.Parent(f)), nil)
	if err != nil || res.ExitCode != 0 || strings.TrimSpace(string(res.Stdout)) != "daemon" {
		t.Fatalf("ran as %q, exit %d, %v: %s", res.Stdout, res.ExitCode, err, res.Stderr)
	}
	// Changing the owner drops the setuid bit the account could have set.
	if got := moduletest.Sh(t, dir, "stat -c '%U:%G %a' d/zone"); got != "root:daemon 755" {
		t.Fatalf("the file is %s", got)
	}
}

// In a directory anyone can create in, only what root owns can be acted on
// by name.
func TestSettled(t *testing.T) {
	dir := moduletest.RootDir(t)
	moduletest.Sh(t, dir, "mkdir -m 1777 s; mkdir -m 0700 guard; touch s/roots; touch s/theirs; chown nobody s/theirs; ln -s ../guard s/link; chown -h nobody s/link; mkdir plain")
	for _, c := range []struct {
		name, script string
		code         int
		out          string
	}{
		{"missing", `route_settled "$T/s/x" || echo missing`, 0, "missing"},
		{"root's", `route_settled "$T/s/roots" && echo there`, 0, "there"},
		{"someone's file", `route_settled "$T/s/theirs"; echo ran`, 125, ""},
		{"someone's link", `route_settled "$T/s/link"; echo ran`, 125, ""},
		{"missing where only root creates", `route_settled "$T/plain/x" && echo fine`, 0, "fine"},
		{"mkdir of a missing one", `route_mkdir "$T/s/new" && stat -c %U "$T/s/new"`, 0, "root"},
		{"mkdir over someone's link", `route_mkdir "$T/s/link"; echo ran`, 125, ""},
		{"mkdir with parents elsewhere", `route_mkdir "$T/plain/a/b" && echo made`, 0, "made"},
	} {
		t.Run(c.name, func(t *testing.T) {
			res, err := moduletest.Local{}.Run(context.Background(), modules.Settled+strings.ReplaceAll(c.script, "$T", dir), nil)
			if err != nil {
				t.Fatal(err)
			}
			if res.ExitCode != c.code || strings.TrimSpace(string(res.Stdout)) != c.out {
				t.Fatalf("got %q, exit %d: %s", res.Stdout, res.ExitCode, res.Stderr)
			}
		})
	}
	if got := moduletest.Sh(t, dir, "stat -c %a guard"); got != "700" {
		t.Fatalf("the directory behind the link is now %s", got)
	}
}
