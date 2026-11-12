// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

type tlsVars struct {
	Port, KeyFile, KnownHosts, Type, Group string
	Days                                   int
}

// A key and a self-signed certificate made on the host: the next plan is
// clean, a mode changed by hand comes back without a new key, a new type
// makes a new key and certificate, and a certificate inside its renewal
// window is renewed.
func TestTLSKeyAndCert(t *testing.T) {
	for _, image := range linuxImages {
		t.Run(image, func(t *testing.T) {
			h := startHost(t, image)
			group := "adm"
			if rpmImage(image) {
				group = "wheel"
			}
			w := newWorkdir(t, "tls")
			write := func(typ string, days int) {
				w.writeAs("main.circuit.hcl", tlsVars{h.port, h.keyFile, h.knownHosts, typ, group, days})
			}
			write("ecdsa", 365)
			w.mustConn3x("init", "-no-color")
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			key := func() string { return h.exec("", "sh", "-c", "openssl pkey -in /etc/conn3x-tls/web.key -pubout") }
			if got := strings.TrimSpace(h.exec("", "stat", "-c", "%a %G", "/etc/conn3x-tls/web.key")); got != "640 "+group {
				t.Fatalf("key file is %q, want 640 %s", got, group)
			}
			if out := h.exec("", "sh", "-c", "openssl x509 -in /etc/conn3x-tls/web.crt -noout -text"); !strings.Contains(out, "DNS:web1.test, DNS:web.test, IP Address:10.0.0.5") || !strings.Contains(out, "CA:FALSE") {
				t.Fatalf("certificate:\n%s", out)
			}
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("plan after apply:\n%s", out)
			}

			before := key()
			h.exec("", "chmod", "0644", "/etc/conn3x-tls/web.key")
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if got := strings.TrimSpace(h.exec("", "stat", "-c", "%a", "/etc/conn3x-tls/web.key")); got != "640" || key() != before {
				t.Fatalf("after a chmod by hand: mode %s, same key %v; want 640 and the same key", got, key() == before)
			}

			write("rsa", 365)
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if !strings.Contains(key(), "BEGIN PUBLIC KEY") || key() == before {
				t.Fatal("type = rsa kept the ECDSA key")
			}
			// The certificate was planned before the key changed, so the
			// next plan finds it's for the old key and makes a new one.
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "tls__cert") {
				t.Fatalf("plan after the new key should renew the certificate for it:\n%s", out)
			}
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("plan after the certificate was made for the new key:\n%s", out)
			}

			// The same certificate with 5 days left, inside the 10 days'
			// notice: the next plan renews it, and the apply gives it a year.
			h.exec("", "sh", "-c", `openssl req -x509 -new -key /etc/conn3x-tls/web.key -days 5 -subj /CN=web1.test -addext "subjectAltName=DNS:web1.test,DNS:web.test,IP:10.0.0.5" -out /etc/conn3x-tls/web.crt`)
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "tls__cert") {
				t.Fatalf("a certificate inside its renewal window should plan a renewal:\n%s", out)
			}
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if out := h.exec("", "sh", "-c", "openssl x509 -in /etc/conn3x-tls/web.crt -noout -checkend 2592000 && echo renewed"); !strings.Contains(out, "renewed") {
				t.Fatalf("the renewed certificate expires within 30 days: %s", out)
			}
		})
	}
}
