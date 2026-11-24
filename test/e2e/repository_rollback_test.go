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

type repositoryBadKeyVars struct{ Port, KeyFile, KnownHosts, URL, Key string }

// A repository whose key doesn't sign its Release file fails apt-get
// update. The apply fails, puts the files back as they were, and the next
// plan shows the step to do again instead of reading it in sync (#1308).
func TestRepositoryRollback(t *testing.T) {
	fetch := func(url string) []byte {
		resp, err := http.Get(url)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(resp.Body)
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("fetching %s: %v %s", url, err, resp.Status)
		}
		return b
	}
	h := startHost(t, "ubuntu2404")
	w := newWorkdir(t, "repository_badkey")
	// openSUSE's shells key is a real key, just not nginx.org's.
	for name, url := range map[string]string{
		"nginx.key": "https://nginx.org/keys/nginx_signing.key",
		"wrong.key": "https://download.opensuse.org/repositories/shells/15.6/repodata/repomd.xml.key",
	} {
		if err := os.WriteFile(filepath.Join(w.dir, name), fetch(url), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	const (
		keyFile = "/etc/apt/keyrings/conn3x-nginx-org.asc"
		srcFile = "/etc/apt/sources.list.d/nginx-org.sources"
		check   = "stat -c '%a %U' " + keyFile + "; cat " + keyFile + "; ls " + srcFile + " 2>&1; true"
	)
	vars := repositoryBadKeyVars{h.port, h.keyFile, h.knownHosts, "https://nginx.org/packages/ubuntu", "wrong.key"}

	// A key file was there before; the .sources file wasn't.
	h.exec("old\n", "sh", "-c", "mkdir -p /etc/apt/keyrings && cat > "+keyFile+" && chmod 0640 "+keyFile)
	w.writeAs("main.circuit.hcl", vars)
	w.mustConn3x("init", "-no-color")
	if out, code := w.conn3x("apply", "-auto-approve", "-no-color"); code == 0 || !strings.Contains(out, "apt-get update") || !strings.Contains(out, "back as they were before this apply") {
		t.Fatalf("apply with the wrong key exited %d:\n%s", code, out)
	}
	if got := h.exec("", "sh", "-c", check); !strings.HasPrefix(got, "640 root\nold\n") || !strings.Contains(got, "No such file") {
		t.Fatalf("after the failed apply:\n%s", got)
	}
	if out, code := w.conn3x("plan", "-no-color", "-detailed-exitcode"); code != 2 || !strings.Contains(out, "conn3x_repository.") {
		t.Fatalf("plan after the failed apply exited %d:\n%s", code, out)
	}

	// In state, with the right key, then the wrong one: the files go back
	// to the right key's, and the next plan still has the change to make.
	// The URL moves to mainline too, since apt doesn't check a Release
	// file again that it already has.
	vars.Key = "nginx.key"
	w.writeAs("main.circuit.hcl", vars)
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	good := h.exec("", "cat", keyFile, srcFile)
	vars.URL, vars.Key = "https://nginx.org/packages/mainline/ubuntu", "wrong.key"
	w.writeAs("main.circuit.hcl", vars)
	if out, code := w.conn3x("apply", "-auto-approve", "-no-color"); code == 0 || !strings.Contains(out, "back as they were before this apply") {
		t.Fatalf("changing to the wrong key exited %d:\n%s", code, out)
	}
	if got := h.exec("", "cat", keyFile, srcFile); got != good {
		t.Fatalf("after the failed change, the files are:\n%s\nwant:\n%s", got, good)
	}
	if out, code := w.conn3x("plan", "-no-color", "-detailed-exitcode"); code != 2 || !strings.Contains(out, "1 to change") {
		t.Fatalf("plan after the failed change exited %d:\n%s", code, out)
	}
}
