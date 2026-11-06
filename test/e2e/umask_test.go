// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"testing"
)

// A hardened host sets UMASK 027 in /etc/login.defs, and pam_umask applies
// it to every SSH session, root's included. The parents a download, file or
// archive step creates must still come out 0755, so other users can reach
// what's in them, while an explicit mode stays what it says. Only the
// Debian family runs pam_umask by default; Rocky and Fedora don't, so
// login.defs doesn't shape their sessions.
func TestLoginUmask027(t *testing.T) {
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

	for _, image := range []string{"ubuntu2404", "debian13"} {
		t.Run(image, func(t *testing.T) {
			h := startHost(t, image)
			h.exec("", "sh", "-c", "sed -i '/^UMASK/d' /etc/login.defs && echo 'UMASK 027' >> /etc/login.defs")
			// The session really has the hardened umask, or this test proves nothing.
			out, err := exec.Command("ssh", "-i", h.keyFile, "-o", "UserKnownHostsFile="+h.knownHosts, "-o", "BatchMode=yes",
				"-p", h.port, "root@127.0.0.1", "umask").CombinedOutput()
			if err != nil || strings.TrimSpace(string(out)) != "0027" {
				t.Fatalf("login umask = %q, %v; want 0027", out, err)
			}

			w := newWorkdir(t, "umask")
			w.writeAs("main.circuit.hcl", fetchVars{h.port, h.keyFile, h.knownHosts, sum})
			w.mustConn3x("init", "-no-color")
			w.mustConn3x("apply", "-auto-approve", "-no-color")

			got := h.exec("", "stat", "-c", "%a %n", "/opt/umask", "/opt/umask/dl", "/opt/umask/dl/nginx.key",
				"/opt/umask/conf", "/opt/umask/conf/secret", "/opt/umask/unpacked", "/opt/umask/unpacked/deep")
			want := "755 /opt/umask\n755 /opt/umask/dl\n644 /opt/umask/dl/nginx.key\n" +
				"755 /opt/umask/conf\n600 /opt/umask/conf/secret\n755 /opt/umask/unpacked\n755 /opt/umask/unpacked/deep\n"
			if got != want {
				t.Fatalf("modes:\n%swant:\n%s", got, want)
			}
			// What the modes are for: a user other than root can read through them.
			h.exec("", "runuser", "-u", "nobody", "--", "sh", "-c", "test -r /opt/umask/dl/nginx.key && test -r /opt/umask/unpacked/deep/passwd && ! test -r /opt/umask/conf/secret")
		})
	}
}
