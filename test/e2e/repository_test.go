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

type repositoryVars struct{ Port, KeyFile, KnownHosts, URL, Suite string }

// nginx.org publishes signed repositories for every test image.
func TestRepository(t *testing.T) {
	resp, err := http.Get("https://nginx.org/keys/nginx_signing.key")
	if err != nil {
		t.Fatal(err)
	}
	key, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("fetching the nginx signing key: %v %s", err, resp.Status)
	}
	// rpm: nginx installs from nginx.org, whose releases carry .ngx.
	// deb: the images already have the distribution's nginx, so check
	// that apt lists nginx.org's builds, which it does only once the
	// repository's signature checks out.
	repos := map[string]struct{ url, suite, check, want string }{
		"rocky10": {"https://nginx.org/packages/centos/10/$basearch/", "", "rpm -q --qf %{RELEASE} nginx", ".ngx"},
		// Fedora has no nginx.org build, so check dnf trusts the repository
		// enough to read its metadata.
		"fedora45":   {"https://nginx.org/packages/centos/10/$basearch/", "", "dnf -q repoquery --repo nginx-org nginx", ".ngx"},
		"ubuntu2404": {"https://nginx.org/packages/ubuntu", "noble", "apt-cache madison nginx", "https://nginx.org/packages/ubuntu noble/nginx"},
		"debian13":   {"https://nginx.org/packages/debian", "trixie", "apt-cache madison nginx", "https://nginx.org/packages/debian trixie/nginx"},
	}
	for _, image := range linuxImages {
		t.Run(image, func(t *testing.T) {
			r := repos[image]
			h := startHost(t, image)
			w := newWorkdir(t, "repository")
			if err := os.WriteFile(filepath.Join(w.dir, "nginx_signing.key"), key, 0o644); err != nil {
				t.Fatal(err)
			}
			w.writeAs("main.circuit.hcl", repositoryVars{h.port, h.keyFile, h.knownHosts, r.url, r.suite})
			w.mustConn3x("init", "-no-color")
			w.mustConn3x("apply", "-auto-approve", "-no-color")

			if got := h.exec("", "sh", "-c", r.check); !strings.Contains(got, r.want) {
				t.Fatalf("%s:\n%s\nwant %q", r.check, got, r.want)
			}
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("plan after apply:\n%s", out)
			}
		})
	}
}
