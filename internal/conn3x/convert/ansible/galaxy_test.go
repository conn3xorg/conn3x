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

type tarEntry struct {
	name, body string
	flag       byte
}

func tarball(t *testing.T, entries ...tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeXGlobalHeader, Name: "pax_global_header", PAXRecords: map[string]string{"comment": "abc"}}); err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		h := &tar.Header{Name: e.name, Mode: 0o644, Size: int64(len(e.body)), Typeflag: e.flag}
		if e.flag == tar.TypeDir {
			h.Size, h.Mode = 0, 0o755
		}
		if e.flag == tar.TypeSymlink {
			h.Size, h.Linkname = 0, "/etc/passwd"
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if e.flag == tar.TypeReg {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func galaxyServer(t *testing.T, archive []byte) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/roles/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("owner__username") != "acme" || r.URL.Query().Get("name") != "web" {
			_, _ = w.Write([]byte(`{"results":[]}`))
			return
		}
		_, _ = w.Write([]byte(`{"results":[{"github_user":"acme","github_repo":"ansible-role-web","commit":"` + strings.Repeat("a", 40) + `","summary_fields":{"versions":[{"name":"1.10.0"},{"name":"1.9.2"},{"name":"1.2.0"}]}}]}`))
	})
	mux.HandleFunc("/acme/ansible-role-web/archive/", func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/1.10.0.tar.gz") && !strings.HasSuffix(r.URL.Path, "/1.2.0.tar.gz") {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(archive)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	oldAPI, oldGH := GalaxyAPI, GitHubArchive
	GalaxyAPI, GitHubArchive = srv.URL+"/api/v1", srv.URL
	t.Cleanup(func() { GalaxyAPI, GitHubArchive = oldAPI, oldGH })
}

func TestFetchGalaxyRole(t *testing.T) {
	galaxyServer(t, tarball(t,
		tarEntry{name: "ansible-role-web-1.10.0/", flag: tar.TypeDir},
		tarEntry{name: "ansible-role-web-1.10.0/tasks/main.yml", body: "- name: vim\n  package: { name: vim }\n", flag: tar.TypeReg},
		tarEntry{name: "ansible-role-web-1.10.0/defaults/main.yml", body: "port: 80\n", flag: tar.TypeReg},
	))
	dir := t.TempDir()
	g, err := FetchGalaxyRole(context.Background(), "acme.web", dir)
	if err != nil {
		t.Fatal(err)
	}
	if g.Name != "acme.web" || g.Version != "1.10.0" || g.Repo != "https://github.com/acme/ansible-role-web" || g.Dir != filepath.Join(dir, "acme.web") {
		t.Errorf("got %+v", g)
	}
	if b, err := os.ReadFile(filepath.Join(g.Dir, "tasks", "main.yml")); err != nil || !strings.Contains(string(b), "vim") {
		t.Errorf("tasks/main.yml: %q, %v", b, err)
	}
	res, err := ConvertRole(g.Dir)
	if err != nil || res.Converted != 1 {
		t.Errorf("converting the fetched role: %d, %v", res.Converted, err)
	}

	if _, err := FetchGalaxyRole(context.Background(), "acme.web,1.2.0", t.TempDir()); err != nil {
		t.Errorf("a listed version: %v", err)
	}
	for spec, want := range map[string]string{
		"acme.web,9.9.9": "has no version 9.9.9",
		"acme.nope":      "has no role acme.nope",
		"acme":           "isn't a Galaxy role",
		"acme.web/../x":  "isn't a Galaxy role",
	} {
		if _, err := FetchGalaxyRole(context.Background(), spec, t.TempDir()); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: want %q, got %v", spec, want, err)
		}
	}
}

func TestFetchGalaxyRoleRefusesHostileArchives(t *testing.T) {
	for want, entry := range map[string]tarEntry{
		"outside the role":  {name: "top/../../escape", body: "x", flag: tar.TypeReg},
		"a link or special": {name: "top/tasks/main.yml", flag: tar.TypeSymlink},
	} {
		galaxyServer(t, tarball(t, tarEntry{name: "top/", flag: tar.TypeDir}, entry))
		dir := t.TempDir()
		if _, err := FetchGalaxyRole(context.Background(), "acme.web", dir); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("want %q, got %v", want, err)
		}
		if _, err := os.Lstat(filepath.Join(dir, "..", "escape")); err == nil {
			t.Error("an entry escaped the role directory")
		}
	}
}

func TestHighestVersion(t *testing.T) {
	if got := highest([]string{"1.9.2", "1.10.0", "v1.2.0"}); got != "1.10.0" {
		t.Errorf("highest = %s", got)
	}
}
