// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package fetch

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/opentofu/opentofu/internal/conn3x/modules/file"
	"github.com/opentofu/opentofu/internal/conn3x/modules/moduletest"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

const sum = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"

func TestDownloadValidate(t *testing.T) {
	if err := (Download{URL: "https://example.com/a.tgz", Dest: "/opt/a.tgz", SHA256: sum}).Validate(); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []Download{
		{URL: "ftp://example.com/a", Dest: "/opt/a", SHA256: sum},
		{URL: "https://example.com/a b", Dest: "/opt/a", SHA256: sum},
		{URL: "https://example.com/a", Dest: "opt/a", SHA256: sum},
		{URL: "https://example.com/a", Dest: "/opt/a", SHA256: ""},
		{URL: "https://example.com/a", Dest: "/opt/a", SHA256: strings.ToUpper(sum)[:63]},
		{URL: "https://example.com/a", Dest: "/opt/a", SHA256: sum, Mode: "rwx"},
		{URL: "https://user:secret@example.com/a", Dest: "/opt/a", SHA256: sum},
		{URL: "https://token@example.com/a", Dest: "/opt/a", SHA256: sum},
		{URL: "https://example.com/a", Dest: "/opt/a", SHA256: sum, NetrcFile: "netrc"},
	} {
		if bad.Validate() == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}

func TestArchiveValidate(t *testing.T) {
	if err := (Archive{Src: "/tmp/a.tgz", Dest: "/opt/a", Creates: "/opt/a/bin/a"}).Validate(); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []Archive{
		{Src: "a.tgz", Dest: "/opt/a", Creates: "/opt/a/x"},
		{Src: "/tmp/a.tgz", Dest: "/opt/a", Creates: ""},
		{Src: "/tmp/a.tgz", Dest: "relative", Creates: "/opt/a/x"},
	} {
		if bad.Validate() == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}

func TestGitValidate(t *testing.T) {
	for _, ok := range []Git{
		{Repo: "https://github.com/octocat/Hello-World.git", Dest: "/srv/app"},
		{Repo: "git@github.com:octocat/Hello-World.git", Dest: "/srv/app", Ref: "v1.2.3"},
		{Repo: "ssh://git@example.com/app.git", Dest: "/srv/app", Ref: "release/2026"},
		{Repo: "http://example.com/app.git", Dest: "/srv/app", Ref: "0123456789abcdef0123456789abcdef01234567"},
	} {
		if err := ok.Validate(); err != nil {
			t.Errorf("rejected %+v: %v", ok, err)
		}
	}
	for _, bad := range []Git{
		{Repo: "", Dest: "/srv/app"},
		{Repo: "https://example.com/a b", Dest: "/srv/app"},
		{Repo: "--upload-pack=touch /tmp/x", Dest: "/srv/app"},
		{Repo: "https://example.com/a.git", Dest: "srv"},
		{Repo: "https://example.com/a.git", Dest: "/srv/app", Ref: "-x"},
		{Repo: "https://example.com/a.git", Dest: "/srv/app", Ref: "main;reboot"},
		{Repo: "http://example.com/a.git", Dest: "/srv/app"},
		{Repo: "http://example.com/a.git", Dest: "/srv/app", Ref: "v1.2.3"},
		{Repo: "https://token@example.com/a.git", Dest: "/srv/app"},
		{Repo: "https://example.com/a.git", Dest: "/srv/app", Depth: -1},
	} {
		if bad.Validate() == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}

func TestResolve(t *testing.T) {
	out := "aaaa000000000000000000000000000000000001\tHEAD\n" +
		"aaaa000000000000000000000000000000000002\trefs/heads/main\n" +
		"aaaa000000000000000000000000000000000003\trefs/tags/v1\n" +
		"aaaa000000000000000000000000000000000004\trefs/tags/v1^{}\n"
	for ref, want := range map[string]string{
		"HEAD": "aaaa000000000000000000000000000000000001",
		"main": "aaaa000000000000000000000000000000000002",
		"v1":   "aaaa000000000000000000000000000000000004",
	} {
		if got, err := resolve(out, ref); err != nil || got != want {
			t.Errorf("resolve(%q) = %q, %v; want %q", ref, got, err, want)
		}
	}
	if got, err := resolve("", "7fd1a60b01f91b314f59955a4e4d4e80d8edf11d"); err != nil || got != "7fd1a60b01f91b314f59955a4e4d4e80d8edf11d" {
		t.Errorf("a full commit resolves to itself: %q, %v", got, err)
	}
	if _, err := resolve(out, "nope"); err == nil {
		t.Error("resolved a ref the remote does not have")
	}
}

// scriptRunner records the script and reports success without running it.
type scriptRunner struct{ script string }

func (r *scriptRunner) Run(_ context.Context, cmd string, _ []byte) (ssh.Result, error) {
	r.script = cmd
	return ssh.Result{}, nil
}

// A download must reach the disk before it replaces the old file.
func TestDownloadSyncsBeforeAndAfterRename(t *testing.T) {
	r := &scriptRunner{}
	d := Download{URL: "https://example.com/a.tar.gz", Dest: "/opt/a.tar.gz", SHA256: strings.Repeat("a", 64)}
	if err := ApplyDownload(context.Background(), r, d); err != nil {
		t.Fatal(err)
	}
	syncTmp, rename, syncDir := strings.Index(r.script, file.SyncFile), strings.Index(r.script, `mv -f -- "$tmp" "$p"`), strings.Index(r.script, file.SyncDir)
	if syncTmp < 0 || rename < 0 || syncDir < 0 || syncTmp > rename || rename > syncDir {
		t.Fatalf("want sync of the temp file, then the rename, then sync of the directory:\n%s", r.script)
	}
}

// A download that needs a login takes it from a netrc file on the host, so
// it is never in the URL or on curl's command line.
func TestDownloadLogsInWithANetrcFile(t *testing.T) {
	for _, tool := range []string{"curl", "sha256sum"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip("needs " + tool)
		}
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); !ok || u != "deploy" || p != "s3cret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte("test"))
	}))
	defer srv.Close()
	dir := t.TempDir()
	netrc := filepath.Join(dir, "netrc")
	if err := os.WriteFile(netrc, []byte("machine 127.0.0.1 login deploy password s3cret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	d := Download{URL: srv.URL + "/a", Dest: filepath.Join(dir, "a"), SHA256: sum}
	if err := ApplyDownload(context.Background(), moduletest.Local{}, d); err == nil {
		t.Fatal("downloaded without a login")
	}
	d.NetrcFile = netrc
	if err := ApplyDownload(context.Background(), moduletest.Local{}, d); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(d.Dest); string(got) != "test" {
		t.Fatalf("dest holds %q", got)
	}
}

// A shallow checkout keeps only depth commits, stays shallow when the branch
// moves, and can still check out an older commit named in full (#1182).
func TestApplyGitShallow(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("needs git")
	}
	ctx, r := context.Background(), moduletest.Local{}
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	commit := func() string {
		out, err := exec.Command("sh", "-c", `cd "$0" && n=$(git rev-list --count HEAD 2>/dev/null || echo 0) && echo "$n" > f && git add f && git -c user.name=t -c user.email=t@example.com commit -qm "c$n" && git rev-parse HEAD`, src).CombinedOutput()
		if err != nil {
			t.Fatalf("commit: %v\n%s", err, out)
		}
		return strings.TrimSpace(string(out))
	}
	if out, err := exec.Command("git", "init", "-q", "-b", "main", src).CombinedOutput(); err != nil {
		t.Fatalf("init: %v\n%s", err, out)
	}
	var commits []string
	for range 5 {
		commits = append(commits, commit())
	}
	count := func(dest string) string {
		out, err := exec.Command("git", "-C", dest, "rev-list", "--count", "HEAD").CombinedOutput()
		if err != nil {
			t.Fatalf("rev-list: %v\n%s", err, out)
		}
		return strings.TrimSpace(string(out))
	}
	apply := func(g Git) string {
		t.Helper()
		want, err := Remote(ctx, r, g)
		if err != nil {
			t.Fatal(err)
		}
		if err := ApplyGit(ctx, r, g, want); err != nil {
			t.Fatal(err)
		}
		if have, err := Checkout(ctx, r, g.Dest); err != nil || have != want {
			t.Fatalf("checked out %q, %v; want %s", have, err, want)
		}
		return want
	}

	g := Git{Repo: "file://" + src, Dest: filepath.Join(dir, "shallow"), Ref: "main", Depth: 1}
	apply(g)
	if n := count(g.Dest); n != "1" {
		t.Errorf("depth 1 checkout has %s commits", n)
	}
	moved := commit()
	if got := apply(g); got != moved || count(g.Dest) != "1" {
		t.Errorf("after main moved: at %s with %s commits, want %s with 1", got, count(g.Dest), moved)
	}

	old := Git{Repo: "file://" + src, Dest: filepath.Join(dir, "old"), Ref: commits[2], Depth: 1}
	apply(old)

	full := Git{Repo: "file://" + src, Dest: filepath.Join(dir, "full"), Ref: "main"}
	apply(full)
	if n := count(full.Dest); n != "6" {
		t.Errorf("full checkout has %s commits, want 6", n)
	}
}
