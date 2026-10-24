// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"strings"
	"testing"
)

type fetchVars struct{ Port, KeyFile, KnownHosts, SHA256 string }

// octocat/Hello-World's master has not moved since 2012.
const helloWorldMaster = "7fd1a60b01f91b314f59955a4e4d4e80d8edf11d"

func TestDownloadArchiveGit(t *testing.T) {
	resp, err := http.Get("https://nginx.org/keys/nginx_signing.key")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(body)
	sum := hex.EncodeToString(digest[:])

	for _, image := range linuxImages {
		t.Run(image, func(t *testing.T) {
			h := startHost(t, image)
			w := newWorkdir(t, "fetch")
			w.writeAs("main.circuit.hcl", fetchVars{h.port, h.keyFile, h.knownHosts, sum})
			w.mustConn3x("init", "-no-color")
			w.mustConn3x("apply", "-auto-approve", "-no-color")

			if got := h.exec("", "sh", "-c", "sha256sum /opt/conn3x/nginx.key | cut -d' ' -f1; stat -c %a /opt/conn3x/nginx.key"); got != sum+"\n600\n" {
				t.Fatalf("download = %q", got)
			}
			h.exec("", "test", "-s", "/opt/conn3x/unpacked/passwd")
			if got := strings.TrimSpace(h.exec("", "git", "-C", "/srv/hello", "rev-parse", "HEAD")); got != helloWorldMaster {
				t.Fatalf("checkout at %s", got)
			}
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("plan after apply:\n%s", out)
			}

			// A wrong checksum fails the apply and leaves the good file alone.
			w.writeAs("main.circuit.hcl", fetchVars{h.port, h.keyFile, h.knownHosts, strings.Repeat("0", 64)})
			if out, code := w.conn3x("apply", "-auto-approve", "-no-color"); code == 0 || !strings.Contains(out, "checksum mismatch") {
				t.Fatalf("apply with a wrong checksum exited %d:\n%s", code, out)
			}
			if got := h.exec("", "sh", "-c", "sha256sum /opt/conn3x/nginx.key | cut -d' ' -f1"); got != sum+"\n" {
				t.Fatalf("the good file was replaced: %q", got)
			}
		})
	}
}
