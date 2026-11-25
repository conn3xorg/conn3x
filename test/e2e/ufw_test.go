// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

type ufwVars struct{ Port, KeyFile, KnownHosts, DNSPort string }

// ufw keeps rules whether or not it is enabled, so this runs in containers;
// the droplet suite enables it on a real kernel.
func TestUFWRules(t *testing.T) {
	for _, image := range linuxImages {
		if rpmImage(image) {
			continue // ufw is a Debian-family tool; the Red Hat family uses firewalld
		}
		t.Run(image, func(t *testing.T) {
			h := startHost(t, image)
			w := newWorkdir(t, "ufw")
			w.writeAs("main.circuit.hcl", ufwVars{h.port, h.keyFile, h.knownHosts, "53"})
			w.mustConn3x("init", "-no-color")
			w.mustConn3x("apply", "-auto-approve", "-no-color")

			added := h.exec("", "ufw", "show", "added")
			for _, want := range []string{"ufw allow 22/tcp", "ufw deny from 10.0.0.0/8 to any port 6000:6007 proto tcp", "ufw allow from 192.0.2.1 to any port 53"} {
				if !strings.Contains(added, want+"\n") {
					t.Fatalf("ufw show added is missing %q:\n%s", want, added)
				}
			}
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("plan after apply:\n%s", out)
			}

			w.writeAs("main.circuit.hcl", ufwVars{h.port, h.keyFile, h.knownHosts, "5353"})
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, `conn3x_ufw_rule.fw__dns["box"] must be replaced`) {
				t.Fatalf("port change not planned as a replacement:\n%s", out)
			}
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			added = h.exec("", "ufw", "show", "added")
			if strings.Contains(added, "port 53\n") || !strings.Contains(added, "ufw allow from 192.0.2.1 to any port 5353\n") {
				t.Fatalf("old rule left behind or new one missing:\n%s", added)
			}
		})
	}
}

type ufwAppVars struct{ Port, KeyFile, KnownHosts, WebApp string }

// An app rule allows a ufw application profile's ports: OpenSSH, which
// openssh-server ships, and a profile with a space in its name, which ufw
// quotes in "ufw show added". A rule deleted by hand shows as drift, and a
// removed step deletes its rule.
func TestUFWAppRules(t *testing.T) {
	h := startHost(t, "ubuntu2404")
	h.exec("[Nginx Full]\ntitle=Web Server (HTTP,HTTPS)\ndescription=Test profile\nports=80,443/tcp|8080/udp\n",
		"sh", "-c", "mkdir -p /etc/ufw/applications.d && cat > /etc/ufw/applications.d/conn3x-test")
	w := newWorkdir(t, "ufw_app")
	// ufw finds "nginx full" whatever its case, but stores it as Nginx Full,
	// so the step would never read back; it fails before ufw sees it.
	w.writeAs("main.circuit.hcl", ufwAppVars{h.port, h.keyFile, h.knownHosts, "nginx full"})
	w.mustConn3x("init", "-no-color")
	if out, code := w.conn3x("apply", "-auto-approve", "-no-color"); code == 0 || !strings.Contains(out, `no ufw application profile "nginx full" on the host`) {
		t.Fatalf("a profile spelt in another case should fail (exit %d):\n%s", code, out)
	}

	w.writeAs("main.circuit.hcl", ufwAppVars{h.port, h.keyFile, h.knownHosts, "Nginx Full"})
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	added := h.exec("", "ufw", "show", "added")
	for _, want := range []string{"ufw allow OpenSSH", "ufw allow from 10.0.0.0/8 to any app 'Nginx Full'"} {
		if !strings.Contains(added, want+"\n") {
			t.Fatalf("ufw show added is missing %q:\n%s", want, added)
		}
	}
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
		t.Fatalf("plan after apply:\n%s", out)
	}

	h.exec("", "ufw", "delete", "allow", "OpenSSH")
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, `conn3x_ufw_rule.fw__ssh["box"] will be updated in-place`) {
		t.Fatalf("a rule deleted by hand isn't drift:\n%s", out)
	}
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if added := h.exec("", "ufw", "show", "added"); !strings.Contains(added, "ufw allow OpenSSH\n") {
		t.Fatalf("apply didn't put the rule back:\n%s", added)
	}

	w.writeAs("main.circuit.hcl", ufwAppVars{h.port, h.keyFile, h.knownHosts, ""})
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if added := h.exec("", "ufw", "show", "added"); strings.Contains(added, "Nginx Full") || !strings.Contains(added, "ufw allow OpenSSH\n") {
		t.Fatalf("removing the step left its rule, or took the other:\n%s", added)
	}
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
		t.Fatalf("plan after removing the step:\n%s", out)
	}
}
