// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type repositorySUSEVars struct {
	Port, KeyFile, KnownHosts string
	Repo                      bool
}

// On openSUSE, repository writes a zypper .repo file and imports its key,
// and package installs posh, which only openSUSE's shells repository on
// the Open Build Service has. package_sources keeps Leap's own repo-*.repo
// files and the step's, and moves one added by hand.
func TestRepositorySUSE(t *testing.T) {
	const keyURL = "https://download.opensuse.org/repositories/shells/15.6/repodata/repomd.xml.key"
	resp, err := http.Get(keyURL)
	if err != nil {
		t.Fatal(err)
	}
	key, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("fetching %s: %v %s", keyURL, err, resp.Status)
	}
	h := startHost(t, "leap156")
	w := newWorkdir(t, "repository_suse")
	if err := os.WriteFile(filepath.Join(w.dir, "shells.key"), key, 0o644); err != nil {
		t.Fatal(err)
	}
	const repoFile = "/etc/zypp/repos.d/shells.repo"
	h.exec("[stray]\nbaseurl=http://127.0.0.1:9/stray\nenabled=0\n", "sh", "-c", "cat > /etc/zypp/repos.d/stray.repo")
	vars := repositorySUSEVars{Port: h.port, KeyFile: h.keyFile, KnownHosts: h.knownHosts, Repo: true}
	w.writeAs("main.circuit.hcl", vars)
	w.mustConn3x("init", "-no-color")
	w.mustConn3x("apply", "-auto-approve", "-no-color")

	if got := h.exec("", "rpm", "-q", "--qf", "%{DISTRIBUTION}", "posh"); !strings.Contains(got, "shells") {
		t.Fatalf("posh came from %q, not the shells repository", got)
	}
	if got := h.exec("", "sh", "-c", "zypper -n -x lr shells"); !strings.Contains(got, `priority="90"`) || !strings.Contains(got, `gpgcheck="1"`) {
		t.Fatalf("zypper lr shells:\n%s", got)
	}
	ls := h.exec("", "sh", "-c", "ls /etc/zypp/repos.d; echo --; ls /var/lib/conn3x/disabled-sources 2>/dev/null || :")
	kept, moved, _ := strings.Cut(ls, "--")
	if !strings.Contains(kept, "repo-oss.repo") || !strings.Contains(kept, "shells.repo") || strings.Contains(kept, "stray.repo") || !strings.Contains(moved, "stray.repo") {
		t.Fatalf("package_sources left:\n%s", ls)
	}
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
		t.Fatalf("plan after apply:\n%s", out)
	}

	// A hand edit to the .repo file is drift, and apply puts it back.
	h.exec("", "sed", "-i", "s/^gpgcheck=1/gpgcheck=0/", repoFile)
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "conn3x_repository.zrepo__shells") || !strings.Contains(out, "1 to change") {
		t.Fatalf("plan after editing %s:\n%s", repoFile, out)
	}
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if got := h.exec("", "cat", repoFile); !strings.Contains(got, "gpgcheck=1") {
		t.Fatalf("after apply, %s:\n%s", repoFile, got)
	}

	// With on_remove = "delete", dropping the step removes both files.
	vars.Repo = false
	w.writeAs("main.circuit.hcl", vars)
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if got := h.exec("", "sh", "-c", "ls "+repoFile+" /etc/pki/rpm-gpg/RPM-GPG-KEY-conn3x-shells 2>&1; zypper -n lr shells 2>&1; true"); strings.Count(got, "No such file") != 2 || !strings.Contains(got, "not found") {
		t.Fatalf("after removing the step:\n%s", got)
	}
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
		t.Fatalf("plan after removing the step:\n%s", out)
	}
}
