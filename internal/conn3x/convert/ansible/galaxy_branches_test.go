// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeGalaxy answers the roles API with roles and every archive with
// archive, or with status when it isn't 200.
func fakeGalaxy(t *testing.T, roles string, status int, archive func(w http.ResponseWriter)) *[]string {
	t.Helper()
	var asked []string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/roles/", func(w http.ResponseWriter, r *http.Request) {
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		_, _ = w.Write([]byte(roles))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		asked = append(asked, r.URL.Path)
		archive(w)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	oldAPI, oldGH := GalaxyAPI, GitHubArchive
	GalaxyAPI, GitHubArchive = srv.URL+"/api/v1", srv.URL
	t.Cleanup(func() { GalaxyAPI, GitHubArchive = oldAPI, oldGH })
	return &asked
}

func galaxyRole(user, repo, commit, versions string) string {
	return `{"results":[{"github_user":"` + user + `","github_repo":"` + repo + `","commit":"` + commit + `","summary_fields":{"versions":[` + versions + `]}}]}`
}

// gzipped is a gzipped tar of the headers given, each body written in full
// unless short.
func gzipped(t *testing.T, short bool, hs ...*tar.Header) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, h := range hs {
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if !short {
			_, _ = tw.Write(bytes.Repeat([]byte("x"), int(h.Size)))
		}
	}
	if !short {
		_ = tw.Close()
	}
	_ = gz.Close()
	return buf.Bytes()
}

func TestFetchGalaxyRoleFailures(t *testing.T) {
	ctx := context.Background()
	commit := strings.Repeat("b", 40)
	file := func(name, body string) *tar.Header {
		return &tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}
	}
	serve := func(b []byte) func(http.ResponseWriter) { return func(w http.ResponseWriter) { _, _ = w.Write(b) } }
	good := gzipped(t, false, &tar.Header{Name: "top/", Typeflag: tar.TypeDir, Mode: 0o755}, &tar.Header{Name: "top/meta/", Typeflag: tar.TypeDir, Mode: 0o755}, file("top/tasks/main.yml", "- ping:\n"))

	// No versions: the commit Galaxy names is what's downloaded.
	asked := fakeGalaxy(t, galaxyRole("acme", "web", commit, ""), http.StatusOK, serve(good))
	g, err := FetchGalaxyRole(ctx, "acme.web", t.TempDir())
	if err != nil || g.Version != commit || len(*asked) != 1 || !strings.HasSuffix((*asked)[0], "/acme/web/archive/"+commit+".tar.gz") {
		t.Fatalf("by commit: %+v, %v, asked %v", g, err, *asked)
	}
	if fi, err := os.Stat(filepath.Join(g.Dir, "meta")); err != nil || !fi.IsDir() {
		t.Errorf("a directory entry wasn't made: %v", err)
	}

	for name, c := range map[string]struct {
		roles   string
		status  int
		archive func(http.ResponseWriter)
		want    string
	}{
		"API down":       {"", http.StatusInternalServerError, nil, "looking up acme.web on Galaxy: 127.0.0.1"},
		"API garbled":    {"{", http.StatusOK, nil, "looking up acme.web on Galaxy: unexpected EOF"},
		"odd repository": {galaxyRole("acme", "web/../x", commit, ""), http.StatusOK, nil, "an odd repository, acme/web/../x"},
		"no versions":    {galaxyRole("acme", "web", "", ""), http.StatusOK, nil, "has no versions on Galaxy; give one, as acme.web,<version>"},
		"no archive": {galaxyRole("acme", "web", commit, ""), http.StatusOK, func(w http.ResponseWriter) { w.WriteHeader(http.StatusNotFound) },
			"downloading acme.web " + commit + " from github.com/acme/web: 127.0.0.1"},
		"too big": {galaxyRole("acme", "web", commit, ""), http.StatusOK, func(w http.ResponseWriter) { w.Header().Set("Content-Length", "100000000") },
			"the archive is 100000000 bytes"},
		"not gzip":  {galaxyRole("acme", "web", commit, ""), http.StatusOK, serve([]byte("plain text, not an archive")), "gzip: invalid header"},
		"truncated": {galaxyRole("acme", "web", commit, ""), http.StatusOK, serve(gzipped(t, true, file("top/a", "abc"))[:20]), "downloading"},
		"unpacks big": {galaxyRole("acme", "web", commit, ""), http.StatusOK, serve(gzipped(t, true, &tar.Header{Name: "top/big", Mode: 0o644, Size: 300 << 20, Typeflag: tar.TypeReg})),
			"unpacks to more than a role should be"},
		"twice": {galaxyRole("acme", "web", commit, ""), http.StatusOK, serve(gzipped(t, false, file("top/a", "1"), file("top/a", "2"))), "downloading"},
	} {
		fakeGalaxy(t, c.roles, c.status, c.archive)
		if _, err := FetchGalaxyRole(ctx, "acme.web", t.TempDir()); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}

	// A role already downloaded there isn't written over.
	fakeGalaxy(t, galaxyRole("acme", "web", commit, ""), http.StatusOK, serve(good))
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "acme.web"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := FetchGalaxyRole(ctx, "acme.web", dir); !os.IsExist(err) {
		t.Errorf("existing directory: %v", err)
	}
}

// With no semantic version, it's Galaxy's first.
func TestHighestVersionNotSemantic(t *testing.T) {
	if got := highest([]string{"stable", "latest"}); got != "stable" {
		t.Errorf("highest = %s", got)
	}
}
