// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"os"
	"strings"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

type authkeyVars struct{ Port, KeyFile, KnownHosts, PublicKey string }

func TestAuthorizedKeyLetsTheUserLogIn(t *testing.T) {
	for _, image := range linuxImages {
		t.Run(image, func(t *testing.T) {
			h := startHost(t, image)
			pemBytes, _ := os.ReadFile(h.keyFile)
			signer, err := gossh.ParsePrivateKey(pemBytes)
			if err != nil {
				t.Fatal(err)
			}
			pub := strings.TrimSpace(string(gossh.MarshalAuthorizedKey(signer.PublicKey()))) + " carol@test"
			w := newWorkdir(t, "authkey")
			w.writeAs("main.circuit.hcl", authkeyVars{h.port, h.keyFile, h.knownHosts, pub})
			w.mustConn3x("init", "-no-color")
			w.mustConn3x("apply", "-auto-approve", "-no-color")

			if got := strings.TrimSpace(h.exec("", "stat", "-c", "%a %U", "/home/carol/.ssh", "/home/carol/.ssh/authorized_keys")); got != "700 carol\n600 carol" {
				t.Fatalf("modes = %q", got)
			}
			hostKeys, err := knownhosts.New(h.knownHosts)
			if err != nil {
				t.Fatal(err)
			}
			client, err := gossh.Dial("tcp", "127.0.0.1:"+h.port, &gossh.ClientConfig{
				User:            "carol",
				Auth:            []gossh.AuthMethod{gossh.PublicKeys(signer)},
				HostKeyCallback: hostKeys,
				// known_hosts only records the ed25519 key, so ask for that one.
				HostKeyAlgorithms: []string{gossh.KeyAlgoED25519},
				Timeout:           10 * time.Second,
			})
			if err != nil {
				t.Fatalf("carol can't log in with the installed key: %v", err)
			}
			client.Close()
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("plan after apply:\n%s", out)
			}
		})
	}
}
