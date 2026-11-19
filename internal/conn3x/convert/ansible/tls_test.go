// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"
)

func TestConvertTLS(t *testing.T) {
	for task, wants := range map[string][]string{
		"community.crypto.openssl_privatekey: {path: /etc/pki/web.key}":                                                                  {"tls_private_key {", `path = "/etc/pki/web.key"`, "bits = 4096"},
		"community.crypto.openssl_privatekey: {path: /k, type: ECC, curve: secp384r1, mode: '0640'}":                                     {`type  = "ecdsa"`, `curve = "P-384"`, `mode  = "0640"`},
		"community.crypto.openssl_privatekey: {path: /k, type: Ed25519, group: nginx}":                                                   {`type  = "ed25519"`, `group = "nginx"`},
		"community.crypto.openssl_csr: {path: /c, privatekey_path: /k, common_name: web1}":                                               {"tls_csr {", `common_name = "web1"`, `dns_names   = ["web1"]`},
		"community.crypto.openssl_csr: {path: /c, privatekey_path: /k, common_name: w, subject_alt_name: ['DNS:a.test', 'IP:10.0.0.1']}": {`dns_names    = ["a.test"]`, `ip_addresses = ["10.0.0.1"]`},
	} {
		res := convertString(t, "- hosts: all\n  tasks:\n    - "+task+"\n")
		if res.Converted != 1 || len(res.Review) != 0 {
			t.Errorf("%s: converted %d, review %+v", task, res.Converted, res.Review)
			continue
		}
		for _, want := range wants {
			if !strings.Contains(string(res.HCL), want) {
				t.Errorf("%s: output lacks %q:\n%s", task, want, res.HCL)
			}
		}
	}
	for task, reason := range map[string]string{
		"community.crypto.openssl_privatekey: {path: /k, passphrase: x}":                                                 "passphrase",
		"community.crypto.openssl_privatekey: {path: /k, mode: '0644'}":                                                  "anyone read",
		"community.crypto.openssl_privatekey: {path: /k, size: 1024}":                                                    "2048, 3072 or 4096",
		"community.crypto.openssl_privatekey: {path: /k, regenerate: always}":                                            "regenerate",
		"community.crypto.openssl_privatekey: {path: /k, type: DSA}":                                                     "DSA",
		"community.crypto.openssl_csr: {path: /c, privatekey_path: /k, common_name: w, key_usage: [digitalSignature]}":   "key_usage",
		"community.crypto.openssl_csr: {path: /c, privatekey_path: /k, common_name: w, subject_alt_name: ['email:a@b']}": "email:a@b",
	} {
		res := convertString(t, "- hosts: all\n  tasks:\n    - "+task+"\n")
		if res.Converted != 0 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, reason) {
			t.Errorf("%s: converted %d, review %+v, want %q", task, res.Converted, res.Review, reason)
		}
	}
}

// A self-signed x509_certificate takes its names from the play's
// openssl_csr task for its csr_path, and Ansible's +3650d default.
func TestConvertX509SelfSigned(t *testing.T) {
	const csr = "    - community.crypto.openssl_csr: {path: /etc/ssl/a.csr, privatekey_path: /etc/ssl/a.key, common_name: web1, subject_alt_name: ['DNS:web1', 'IP:10.0.0.5']}\n"
	cert := func(extra string) string {
		return "    - community.crypto.x509_certificate: {path: /etc/ssl/a.crt, privatekey_path: /etc/ssl/a.key, csr_path: /etc/ssl/a.csr" + extra + "}\n"
	}
	const play = "- hosts: all\n  tasks:\n"

	res := convertString(t, play+csr+cert(", provider: selfsigned"))
	hcl := string(res.HCL)
	if res.Converted != 2 || len(res.Review) != 0 {
		t.Fatalf("converted %d, review %+v", res.Converted, res.Review)
	}
	for _, want := range []string{"tls_self_signed_cert {", `common_name  = "web1"`, `dns_names    = ["web1"]`, `ip_addresses = ["10.0.0.5"]`, "days         = 3650"} {
		if !strings.Contains(hcl, want) {
			t.Errorf("missing %q:\n%s", want, hcl)
		}
	}
	if res := convertString(t, play+csr+cert(", provider: selfsigned, selfsigned_not_after: '+90d'")); !strings.Contains(string(res.HCL), "days         = 90") {
		t.Errorf("+90d:\n%s", res.HCL)
	}

	for playbook, reason := range map[string]string{
		play + cert(", provider: selfsigned"):                                      "no openssl_csr task in this play writes it",
		play + csr + cert(", provider: acme"):                                      "provider acme",
		play + csr + cert(", provider: selfsigned, force: yes"):                    "sets force",
		play + csr + cert(", provider: selfsigned, selfsigned_not_after: '+1y'"):   "takes a number of days",
		play + csr + cert(", provider: selfsigned, privatekey_passphrase: s3cret"): "privatekey_passphrase",
		play + csr + cert(", provider: selfsigned, selfsigned_not_before: '-1d'"):  "selfsigned_not_before",
	} {
		var got string
		for _, r := range convertString(t, playbook).Review {
			got += r.Reason
		}
		if !strings.Contains(got, reason) {
			t.Errorf("review %q, want %q, for:\n%s", got, reason, playbook)
		}
	}
}
