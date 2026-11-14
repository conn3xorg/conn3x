// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

type sshKeypairVars struct {
	Port, KeyFile, KnownHosts, Type, Comment string
	Bits                                     int
}

// ssh_keypair makes a key for a service account on the host, puts the
// public key in state, keeps the key through a chmod and a new comment,
// makes a new one for a new type, and removes both files.
func TestSSHKeypair(t *testing.T) {
	for _, image := range linuxImages {
		t.Run(image, func(t *testing.T) {
			h := startHost(t, image)
			w := newWorkdir(t, "ssh_keypair")
			vars := sshKeypairVars{Port: h.port, KeyFile: h.keyFile, KnownHosts: h.knownHosts, Type: "ed25519", Comment: "deploy@box"}
			w.writeAs("main.circuit.hcl", vars)
			w.mustConn3x("init", "-no-color")
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			const key = "/home/deploy/.ssh/id_deploy"
			pub := func() string { return strings.TrimSpace(h.exec("", "sh", "-c", "ssh-keygen -y -f "+key+" | cut -d' ' -f1,2")) }
			if got := strings.TrimSpace(h.exec("", "stat", "-c", "%a %U", key, key+".pub")); got != "600 deploy\n644 deploy" {
				t.Fatalf("files are %q", got)
			}
			first := pub()
			if got := strings.TrimSpace(h.exec("", "cat", key+".pub")); got != first+" deploy@box" || !strings.HasPrefix(first, "ssh-ed25519 ") {
				t.Fatalf(".pub holds %q, key is %q", got, first)
			}
			if out := w.mustConn3x("state", "show", "-no-color", `conn3x_ssh_keypair.keys__deploy_key["box"]`); !strings.Contains(out, first+" deploy@box") {
				t.Fatalf("state has no public key:\n%s", out)
			}
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("plan after apply:\n%s", out)
			}

			h.exec("", "chmod", "0644", key)
			vars.Comment = "deploy@web1"
			w.writeAs("main.circuit.hcl", vars)
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if got := strings.TrimSpace(h.exec("", "stat", "-c", "%a", key)); got != "600" || pub() != first {
				t.Fatalf("after a chmod and a new comment: mode %s, same key %v", got, pub() == first)
			}
			if got := strings.TrimSpace(h.exec("", "cat", key+".pub")); got != first+" deploy@web1" {
				t.Fatalf(".pub after a new comment: %q", got)
			}

			vars.Type, vars.Bits = "rsa", 4096
			w.writeAs("main.circuit.hcl", vars)
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if got := h.exec("", "sh", "-c", "ssh-keygen -l -f "+key+".pub"); !strings.HasPrefix(got, "4096 ") || !strings.Contains(got, "(RSA)") {
				t.Fatalf("type = rsa: %s", got)
			}
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("plan after the new key:\n%s", out)
			}

			w.mustConn3x("destroy", "-auto-approve", "-no-color")
			if got := h.exec("", "sh", "-c", "ls /home/deploy/.ssh/ 2>&1; true"); strings.Contains(got, "id_deploy") {
				t.Fatalf("on_remove = \"delete\" left:\n%s", got)
			}
		})
	}
}
