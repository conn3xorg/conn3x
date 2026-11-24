// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package fetch

import (
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/opentofu/opentofu/internal/conn3x/modules/moduletest"
)

// Each status line starts with a space when the submodule is at the pinned
// commit, "-" when it isn't initialised, "+" at another commit, "U" with a
// merge conflict (#1348).
func TestSubmodulesClean(t *testing.T) {
	const a, b = "1111111111111111111111111111111111111111", "2222222222222222222222222222222222222222"
	for status, want := range map[string]bool{
		"":                              true,
		" " + a + " lib (heads/main)\n": true,
		" " + a + " lib (heads/main)\n " + b + " lib/nested (v1)\n": true,
		"-" + a + " lib\n":                                          false,
		"+" + b + " lib (heads/main)\n":                             false,
		"U" + a + " lib\n":                                          false,
		" " + a + " lib (heads/main)\n-" + b + " lib/nested\n":      false,
		" " + a + " lib (heads/main)\n+" + b + " lib/nested (v2)\n": false,
	} {
		if got := submodulesClean(status); got != want {
			t.Errorf("submodulesClean(%q) = %v, want %v", status, got, want)
		}
	}
}

// Submodules are synced and updated after the checkout, with the step's depth
// and key file; without submodules, apply never touches them.
func TestApplyGitSubmodulesScript(t *testing.T) {
	commit := strings.Repeat("a", 40)
	g := Git{Repo: "ssh://deploy@git.example.com/app.git", Dest: "/srv/app", Ref: "main", KeyFile: "/root/.ssh/deploy", Depth: 1, Submodules: true}
	r := &scriptRunner{}
	if err := ApplyGit(context.Background(), r, g, commit); err != nil {
		t.Fatal(err)
	}
	checkout := strings.Index(r.script, "checkout --quiet --force --detach")
	sync := strings.Index(r.script, "submodule --quiet sync --recursive")
	update := strings.Index(r.script, "submodule --quiet update --init --recursive --force --depth 1")
	if checkout < 0 || sync < checkout || update < sync {
		t.Errorf("want checkout, then sync, then update with --depth 1:\n%s", r.script)
	}
	if !strings.Contains(r.script, "GIT_SSH_COMMAND=") || strings.Index(r.script, "GIT_SSH_COMMAND=") > update {
		t.Errorf("the key file isn't set before the submodule update:\n%s", r.script)
	}
	if out, err := exec.Command("sh", "-n", "-c", r.script).CombinedOutput(); err != nil {
		t.Errorf("script doesn't parse: %v\n%s", err, out)
	}

	g.Depth = 0
	_ = ApplyGit(context.Background(), r, g, commit)
	if !strings.Contains(r.script, "update --init --recursive --force") || strings.Contains(r.script, "--force --depth") {
		t.Errorf("without depth the update is shallow or missing:\n%s", r.script)
	}

	g.Submodules = false
	_ = ApplyGit(context.Background(), r, g, commit)
	if strings.Contains(r.script, "submodule") {
		t.Errorf("submodules = false still runs git submodule:\n%s", r.script)
	}
}

// Against real repositories: apply checks out a nested submodule, the read
// sees it in sync, and moving it by hand or leaving it out shows as drift.
func TestApplyGitSubmodules(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("needs git")
	}
	// git refuses file:// submodules unless told otherwise (CVE-2022-39253).
	t.Setenv("GIT_CONFIG_COUNT", "1")
	t.Setenv("GIT_CONFIG_KEY_0", "protocol.file.allow")
	t.Setenv("GIT_CONFIG_VALUE_0", "always")
	ctx, r := context.Background(), moduletest.Local{}
	dir := t.TempDir()
	sh := func(script string) string {
		t.Helper()
		out, err := exec.Command("sh", "-c", "set -e; cd \"$0\"; "+script, dir).CombinedOutput()
		if err != nil {
			t.Fatalf("%s: %v\n%s", script, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	c := "git -c user.name=t -c user.email=t@example.com"
	sh(`git init -q -b main inner && echo in > inner/f && git -C inner add f && ` + c + ` -C inner commit -qm in
git init -q -b main lib && echo lib > lib/f && git -C lib add f && ` + c + ` -C lib submodule --quiet add "file://$PWD/inner" inner && ` + c + ` -C lib commit -qm lib
git init -q -b main app && ` + c + ` -C app submodule --quiet add "file://$PWD/lib" lib && ` + c + ` -C app commit -qm app`)

	g := Git{Repo: "file://" + filepath.Join(dir, "app"), Dest: filepath.Join(dir, "dest"), Ref: "main", Submodules: true}
	want, err := Remote(ctx, r, g)
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyGit(ctx, r, g, want); err != nil {
		t.Fatal(err)
	}
	if got := sh("cat dest/lib/f dest/lib/inner/f"); got != "lib\nin" {
		t.Fatalf("submodule files = %q", got)
	}
	inSync := func(when string, want bool) {
		t.Helper()
		if ok, err := SubmodulesInSync(ctx, r, g.Dest); err != nil || ok != want {
			t.Fatalf("%s: in sync = %v, %v; want %v", when, ok, err, want)
		}
	}
	inSync("after apply", true)

	sh(`echo moved > lib/f && ` + c + ` -C lib commit -qam moved && git -C dest/lib fetch -q origin main && git -C dest/lib checkout -q FETCH_HEAD`)
	inSync("after moving lib by hand", false)
	if err := ApplyGit(ctx, r, g, want); err != nil {
		t.Fatal(err)
	}
	inSync("after apply restores it", true)
	if got := sh("cat dest/lib/f"); got != "lib" {
		t.Fatalf("lib/f after restore = %q", got)
	}

	sh("git -C dest submodule --quiet deinit --all --force")
	inSync("after deinit", false)

	off := Git{Repo: g.Repo, Dest: filepath.Join(dir, "off"), Ref: "main"}
	if err := ApplyGit(ctx, r, off, want); err != nil {
		t.Fatal(err)
	}
	if got := sh("ls -A off/lib | wc -l"); got != "0" {
		t.Fatalf("submodules = false filled lib: %s entries", got)
	}
}
