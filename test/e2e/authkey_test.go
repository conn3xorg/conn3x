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

type guardVars struct{ Port, KeyFile, KnownHosts, User, PublicKey string }

// guardKey is a valid public key the guard test installs; it logs in nowhere.
const guardKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl guard@test"

// TestAuthorizedKeyStaysWithinTheUsersFiles checks that a symlink in a
// user's ~/.ssh can't make Conn3x, connected as root, read or change a file
// the user couldn't reach themselves. The work is done as the user, so the
// kernel stops it at the user's own permissions.
func TestAuthorizedKeyStaysWithinTheUsersFiles(t *testing.T) {
	for _, image := range linuxImages {
		t.Run(image, func(t *testing.T) {
			h := startHost(t, image)

			// A file only root can read, pointed at from the user's
			// authorized_keys. Apply must leave it untouched and must not
			// copy its content into the user's file.
			h.exec("", "sh", "-c", "useradd -m k1 && runuser -u k1 -- mkdir -p -m 700 /home/k1/.ssh && "+
				"printf 'root-only\\n' > /root/secret && chmod 600 /root/secret && "+
				"runuser -u k1 -- ln -sf /root/secret /home/k1/.ssh/authorized_keys")
			w := newWorkdir(t, "authkey_guard")
			w.writeAs("main.circuit.hcl", guardVars{h.port, h.keyFile, h.knownHosts, "k1", guardKey})
			w.mustConn3x("init", "-no-color")
			w.mustConn3x("apply", "-auto-approve", "-no-color")

			if got := strings.TrimSpace(h.exec("", "stat", "-c", "%U %a", "/root/secret")); got != "root 600" {
				t.Fatalf("protected file changed: %q", got)
			}
			if got := h.exec("", "cat", "/root/secret"); got != "root-only\n" {
				t.Fatalf("protected file content changed: %q", got)
			}
			if got := strings.TrimSpace(h.exec("", "stat", "-c", "%F %U %a", "/home/k1/.ssh/authorized_keys")); got != "regular file k1 600" {
				t.Fatalf("authorized_keys = %q, want a user-owned regular file", got)
			}
			if got := h.exec("", "cat", "/home/k1/.ssh/authorized_keys"); got != guardKey+"\n" {
				t.Fatalf("authorized_keys content = %q", got)
			}

			// ~/.ssh pointed at a directory only root owns. Apply can't make
			// the modes or ownership it needs, so it fails and leaves the
			// directory as it was.
			h.exec("", "sh", "-c", "useradd -m k2 && mkdir -m 700 /root/vault && "+
				"runuser -u k2 -- ln -s /root/vault /home/k2/.ssh")
			w2 := newWorkdir(t, "authkey_guard")
			w2.writeAs("main.circuit.hcl", guardVars{h.port, h.keyFile, h.knownHosts, "k2", guardKey})
			w2.mustConn3x("init", "-no-color")
			if out, code := w2.conn3x("apply", "-auto-approve", "-no-color"); code == 0 {
				t.Fatalf("apply through a root-owned ~/.ssh link should fail:\n%s", out)
			}
			if got := strings.TrimSpace(h.exec("", "stat", "-c", "%U %a", "/root/vault")); got != "root 700" {
				t.Fatalf("protected directory changed: %q", got)
			}
			if got := strings.TrimSpace(h.exec("", "sh", "-c", "ls -A /root/vault")); got != "" {
				t.Fatalf("something was written into the protected directory: %q", got)
			}
		})
	}
}

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
			// Rootless CI containers can't run PAM's account check, so sshd
			// would refuse any non-root login; real hosts are covered by the
			// droplet suite's deploy user.
			// Without PAM, sshd also refuses accounts that have no password at
			// all, as useradd leaves them; "*" marks "no usable password".
			h.exec("", "sh", "-c", "usermod -p '*' carol && usermod -p '*' root && echo 'UsePAM no' > /etc/ssh/sshd_config.d/00-conn3x-test.conf && (systemctl restart sshd 2>/dev/null || systemctl restart ssh)")
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
