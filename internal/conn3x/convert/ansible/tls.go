// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"cmp"
	"strconv"
	"strings"

	"github.com/zclconf/go-cty/cty"
)

// privateKeyModule converts community.crypto.openssl_privatekey. Ansible's
// default key is RSA 4096, which the step is told, since its own default
// is 3072. A passphrase, a format or a regenerate other than the default
// goes to review, and so does any argument the step has no answer for.
func privateKeyModule(in *input) ([]step, string) {
	in.state("present", "present")
	if r := in.str("regenerate"); r != "" && r != "full_idempotence" && r != "partial_idempotence" {
		return nil, "sets regenerate: " + r + ", and a tls_private_key step always makes a new key when the kind differs and keeps it otherwise"
	}
	attrs := []attr{s("path", in.str("path"))}
	switch typ := cmp.Or(in.str("type"), "RSA"); typ {
	case "RSA":
		bits := 4096
		if v := in.str("size"); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || (n != 2048 && n != 3072 && n != 4096) {
				return nil, "sets size " + v + "; a tls_private_key step makes RSA keys of 2048, 3072 or 4096 bits"
			}
			bits = n
		}
		attrs = append(attrs, attr{key: "bits", val: cty.NumberIntVal(int64(bits))})
	case "ECC":
		curve := map[string]string{"secp256r1": "P-256", "secp384r1": "P-384"}[in.str("curve")]
		if curve == "" {
			return nil, "uses an ECC curve other than secp256r1 or secp384r1, the two a tls_private_key step makes"
		}
		attrs = append(attrs, s("type", "ecdsa"), s("curve", curve))
	case "Ed25519":
		attrs = append(attrs, s("type", "ed25519"))
	default:
		return nil, "makes a " + typ + " key; a tls_private_key step makes RSA, ECC (P-256, P-384) and Ed25519 keys"
	}
	if m, ok := in.mode("mode"); ok {
		if !strings.HasSuffix(m.val.AsString(), "0") {
			return nil, "sets mode " + m.val.AsString() + ", which lets anyone read the private key; a tls_private_key step refuses it"
		}
		attrs = append(attrs, m)
	}
	in.ignore("return_content", "backup", "select_crypto_backend")
	return one("tls_private_key", in.owners(attrs))
}

// csrModule converts community.crypto.openssl_csr for a common name and
// DNS and IP alternative names, the request a tls_csr step makes. Other
// subject fields and extensions go to review, since the request would ask
// for something else.
func csrModule(in *input) ([]step, string) {
	in.state("present", "present")
	attrs := []attr{s("path", in.str("path")), s("key_path", in.str("privatekey_path")), s("common_name", in.str("common_name", "CN"))}
	var dns, ips []cty.Value
	for _, san := range in.list("subject_alt_name") {
		kind, v, _ := strings.Cut(san, ":")
		switch kind {
		case "DNS":
			dns = append(dns, cty.StringVal(v))
		case "IP":
			ips = append(ips, cty.StringVal(v))
		default:
			return nil, "asks for the alternative name " + san + "; a tls_csr step asks for DNS and IP names only"
		}
	}
	// With no alternative names, Ansible asks for the common name as one,
	// unless use_common_name_for_san is false.
	if len(dns) == 0 && len(ips) == 0 && in.bool("use_common_name_for_san", true) {
		dns = append(dns, cty.StringVal(in.str("common_name", "CN")))
	}
	if len(dns) > 0 {
		attrs = append(attrs, attr{key: "dns_names", val: cty.ListVal(dns)})
	}
	if len(ips) > 0 {
		attrs = append(attrs, attr{key: "ip_addresses", val: cty.ListVal(ips)})
	}
	if m, ok := in.mode("mode"); ok {
		attrs = append(attrs, m)
	}
	in.ignore("return_content", "backup", "select_crypto_backend")
	return one("tls_csr", in.owners(attrs))
}
