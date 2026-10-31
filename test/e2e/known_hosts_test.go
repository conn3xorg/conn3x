// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

const (
	hostKeyAlice = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
	hostKeyBob   = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA2WYZ1jUjx7b5r3v0xZq2tq8Yw3Wv3lH2pZk7u3Jt0b"
)

type knownHostsVars struct{ Port, KeyFile, KnownHosts, Key string }

// One step per kind of file: the one every user trusts, and one user's own.
// Both settle, both catch a hand edit, and removing a key is put right too.
func TestKnownHosts(t *testing.T) {
	for _, image := range linuxImages {
		t.Run(image, func(t *testing.T) {
			h := startHost(t, image)
			h.exec("", "useradd", "-m", "kh")
			h.exec("old.example "+hostKeyBob+"\n", "sh", "-c", "cat > /etc/ssh/ssh_known_hosts; chmod 0640 /etc/ssh/ssh_known_hosts")
			w := newWorkdir(t, "known_hosts")
			w.writeAs("main.circuit.hcl", knownHostsVars{h.port, h.keyFile, h.knownHosts, hostKeyAlice})
			w.mustConn3x("init", "-no-color")
			w.mustConn3x("apply", "-auto-approve", "-no-color")

			check := func(when, wantUser string) {
				t.Helper()
				want := "git.example " + hostKeyAlice + "\n"
				if got := h.exec("", "cat", "/etc/ssh/ssh_known_hosts"); got != want {
					t.Fatalf("%s: system file = %q", when, got)
				}
				if got := h.exec("", "cat", "/home/kh/.ssh/known_hosts"); got != wantUser {
					t.Fatalf("%s: user file = %q", when, got)
				}
			}
			wantUser := "[git.example]:2222 " + hostKeyAlice + "\n"
			check("after apply", wantUser)
			// A file an admin set up keeps its mode; what Conn3x creates has
			// modes ssh accepts and belongs to the user.
			if got := strings.TrimSpace(h.exec("", "stat", "-c", "%a %U", "/etc/ssh/ssh_known_hosts", "/home/kh/.ssh", "/home/kh/.ssh/known_hosts")); got != "640 root\n700 kh\n644 kh" {
				t.Fatalf("modes = %q", got)
			}

			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("plan after apply is not empty:\n%s", out)
			}
			if out, code := w.conn3x("drift", "-no-color"); code != 0 || !strings.Contains(out, "No drift") {
				t.Fatalf("drift right after apply exited %d:\n%s", code, out)
			}

			// Someone swaps the host key by hand, in each file.
			h.exec("", "sh", "-c", "sed -i 's/ssh-ed25519 .*/"+strings.ReplaceAll(hostKeyBob, "/", `\/`)+"/' /etc/ssh/ssh_known_hosts")
			out, code := w.conn3x("drift", "-no-color")
			if code != 2 || !strings.Contains(out, `conn3x_known_hosts.trust__system["box"]`) {
				t.Fatalf("system drift exited %d:\n%s", code, out)
			}
			h.exec("", "runuser", "-u", "kh", "--", "sh", "-c", "echo '[git.example]:2222 "+hostKeyBob+"' > ~/.ssh/known_hosts")
			out, code = w.conn3x("drift", "-no-color")
			if code != 2 || !strings.Contains(out, `conn3x_known_hosts.trust__user["box"]`) {
				t.Fatalf("user drift exited %d:\n%s", code, out)
			}
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			check("after repair", wantUser)

			// A different key of the same type takes over, and the old one
			// stops being trusted.
			w.writeAs("main.circuit.hcl", knownHostsVars{h.port, h.keyFile, h.knownHosts, hostKeyBob})
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if got := h.exec("", "cat", "/home/kh/.ssh/known_hosts"); got != "[git.example]:2222 "+hostKeyBob+"\n" {
				t.Fatalf("after changing the key: %q", got)
			}

			// ssh's own tooling reads what was written.
			if got := h.exec("", "ssh-keygen", "-F", "[git.example]:2222", "-f", "/home/kh/.ssh/known_hosts"); !strings.Contains(got, strings.Fields(hostKeyBob)[1]) {
				t.Fatalf("ssh-keygen can't find the entry:\n%s", got)
			}
		})
	}
}

// A symlink in the user's ~/.ssh can't make Conn3x, connected as root, read
// or change a file the user couldn't reach themselves.
func TestKnownHostsStaysWithinTheUsersFiles(t *testing.T) {
	for _, image := range linuxImages {
		t.Run(image, func(t *testing.T) {
			h := startHost(t, image)
			// known_hosts points at a root-only file. As the user, that link
			// can't be followed, so the file stays out of it: its content isn't
			// copied, and the link gives way to the user's own file.
			h.exec("", "sh", "-c", "useradd -m k1 && runuser -u k1 -- mkdir -p -m 700 /home/k1/.ssh && "+
				"printf 'root-only\\n' > /root/secret && chmod 600 /root/secret && "+
				"runuser -u k1 -- ln -s /root/secret /home/k1/.ssh/known_hosts")
			w := newWorkdir(t, "known_hosts_guard")
			w.writeAs("main.circuit.hcl", guardVars{h.port, h.keyFile, h.knownHosts, "k1", hostKeyAlice})
			w.mustConn3x("init", "-no-color")
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if got := h.exec("", "sh", "-c", "stat -c '%U %a' /root/secret; cat /root/secret"); got != "root 600\nroot-only\n" {
				t.Fatalf("protected file changed: %q", got)
			}
			if got := strings.TrimSpace(h.exec("", "stat", "-c", "%F %U", "/home/k1/.ssh/known_hosts")); got != "regular file k1" {
				t.Fatalf("known_hosts = %q, want a user-owned regular file", got)
			}
			if got := h.exec("", "cat", "/home/k1/.ssh/known_hosts"); got != "git.example "+hostKeyAlice+"\n" {
				t.Fatalf("known_hosts content = %q", got)
			}

			// ~/.ssh itself points at a directory only root can use.
			h.exec("", "sh", "-c", "useradd -m k2 && mkdir -m 700 /root/vault && runuser -u k2 -- ln -s /root/vault /home/k2/.ssh")
			w2 := newWorkdir(t, "known_hosts_guard")
			w2.writeAs("main.circuit.hcl", guardVars{h.port, h.keyFile, h.knownHosts, "k2", hostKeyAlice})
			w2.mustConn3x("init", "-no-color")
			if out, code := w2.conn3x("apply", "-auto-approve", "-no-color"); code == 0 {
				t.Fatalf("apply through a root-owned ~/.ssh link should fail:\n%s", out)
			}
			if got := strings.TrimSpace(h.exec("", "sh", "-c", "stat -c '%U %a' /root/vault; ls -A /root/vault")); got != "root 700" {
				t.Fatalf("protected directory changed: %q", got)
			}
		})
	}
}

type limitVars struct{ Port, KeyFile, KnownHosts string }

func TestLimit(t *testing.T) {
	for _, image := range linuxImages {
		t.Run(image, func(t *testing.T) {
			h := startHost(t, image)
			h.exec("# head\njoe   soft nofile 1024 # old\n", "sh", "-c", "mkdir -p /etc/security && cat > /etc/security/limits.d/90-c3x.conf")
			w := newWorkdir(t, "limit")
			w.writeAs("main.circuit.hcl", limitVars{h.port, h.keyFile, h.knownHosts})
			w.mustConn3x("init", "-no-color")
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			want := "# head\njoe\tsoft\tnofile\t64000\t# old\n@ops\t-\tcore\tunlimited\n"
			if got := h.exec("", "cat", "/etc/security/limits.d/90-c3x.conf"); got != want {
				t.Fatalf("file = %q", got)
			}
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("plan after apply is not empty:\n%s", out)
			}
			h.exec("", "sh", "-c", "sed -i 's/64000/5/' /etc/security/limits.d/90-c3x.conf")
			out, code := w.conn3x("drift", "-no-color")
			if code != 2 || !strings.Contains(out, `conn3x_limit.limits__joe["box"]`) {
				t.Fatalf("drift exited %d:\n%s", code, out)
			}
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if got := h.exec("", "cat", "/etc/security/limits.d/90-c3x.conf"); got != want {
				t.Fatalf("after repair: %q", got)
			}
		})
	}
}
