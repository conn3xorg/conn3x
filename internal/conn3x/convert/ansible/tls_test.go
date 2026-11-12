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
