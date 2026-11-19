// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"cmp"
	"slices"
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

// sshKeypairModule converts community.crypto.openssh_keypair. Ansible's
// default key is RSA 4096, which the step is told, since its own default is
// ed25519. Both write the private key with ssh-keygen, at mode 0600. A
// passphrase, another format or mode, a regenerate other than the default,
// or a DSA key goes to review.
func sshKeypairModule(in *input) ([]step, string) {
	in.state("present", "present")
	if in.has("passphrase") {
		return nil, "sets a passphrase, and an ssh_keypair step makes keys without one"
	}
	if r := in.str("regenerate"); r != "" && r != "partial_idempotence" && r != "full_idempotence" {
		return nil, "sets regenerate: " + r + ", and an ssh_keypair step always makes a new key when the type or bits differ and keeps it otherwise"
	}
	if f := in.str("private_key_format"); f != "" && f != "auto" && f != "ssh" {
		return nil, "sets private_key_format: " + f + "; an ssh_keypair step writes the OpenSSH format ssh-keygen does"
	}
	if m, ok := in.mode("mode"); ok && m.val.AsString() != "0600" {
		return nil, "sets mode " + m.val.AsString() + "; an ssh_keypair step keeps the private key at 0600"
	}
	attrs := []attr{s("path", in.str("path"))}
	typ := cmp.Or(in.str("type"), "rsa")
	bits := map[string]int{"rsa": 4096, "ecdsa": 256}[typ]
	switch typ {
	case "rsa", "ecdsa":
		if v := in.str("size"); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil {
				return nil, "sets size " + v + ", which isn't a number"
			}
			bits = n
		}
		if ok := map[string][]int{"rsa": {3072, 4096}, "ecdsa": {256, 384, 521}}[typ]; !slices.Contains(ok, bits) {
			return nil, "makes a " + strconv.Itoa(bits) + "-bit " + typ + " key; an ssh_keypair step makes RSA keys of 3072 or 4096 bits and ECDSA keys of 256, 384 or 521"
		}
		attrs = append(attrs, s("type", typ), attr{key: "bits", val: cty.NumberIntVal(int64(bits))})
	case "ed25519":
		in.ignore("size") // Ansible ignores it for ed25519
		attrs = append(attrs, s("type", "ed25519"))
	default:
		return nil, "makes a " + typ + " key; an ssh_keypair step makes rsa, ecdsa and ed25519 keys"
	}
	if in.bool("force", false) {
		return nil, "sets force, so Ansible makes a new key on every run; an ssh_keypair step keeps the key it made"
	}
	attrs = in.optional(attrs, "comment", "comment")
	in.ignore("force", "backend")
	return one("ssh_keypair", in.owners(attrs))
}

// x509Module converts community.crypto.x509_certificate with provider:
// selfsigned. Ansible reads the subject and the alternative names from the
// CSR at csr_path, so they come from the play's openssl_csr task that
// writes it, converted as that task is. Its validity defaults to +3650d,
// where the step's is 365 days, so the step is told.
func x509Module(in *input) ([]step, string) {
	in.state("present", "present")
	if p := in.str("provider"); p != "selfsigned" {
		return nil, "uses provider " + cmp.Or(p, "(none)") + "; only provider: selfsigned becomes a tls_self_signed_cert step"
	}
	if in.has("privatekey_passphrase") {
		return nil, "sets privatekey_passphrase, and a tls_self_signed_cert step signs with a key that has none"
	}
	if b := in.str("selfsigned_not_before"); b != "" && b != "+0s" && b != "0" {
		return nil, "sets selfsigned_not_before " + b + ", and a tls_self_signed_cert step is valid from when it's made"
	}
	if in.bool("force", false) {
		return nil, "sets force, so Ansible makes a new certificate on every run; a tls_self_signed_cert step renews only before it expires"
	}
	if d := in.str("selfsigned_digest"); d != "" && d != "sha256" {
		return nil, "sets selfsigned_digest " + d + ", and a tls_self_signed_cert step uses openssl's default digest, sha256 on current openssl"
	}
	days := 3650
	if a := in.str("selfsigned_not_after"); a != "" {
		n, err := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(a, "+"), "d"))
		if err != nil || !strings.HasPrefix(a, "+") || !strings.HasSuffix(a, "d") || n < 1 || n > 3650 {
			return nil, "sets selfsigned_not_after " + a + "; a tls_self_signed_cert step takes a number of days, from 1 to 3650, as +Nd"
		}
		days = n
	}
	csrPath := in.str("csr_path")
	args, ok := in.csrs[csrPath]
	if !ok {
		return nil, "takes its names from the CSR at " + cmp.Or(csrPath, "csr_path") + ", and no openssl_csr task in this play writes it"
	}
	csr := &input{mod: "openssl_csr", role: in.role, args: args, vars: in.vars, dir: in.dir, used: map[string]bool{}}
	steps, why := csrModule(csr)
	if why == "" {
		why = csr.problem
	}
	if why != "" {
		return nil, "takes its names from a CSR whose openssl_csr task can't convert: it " + why
	}
	attrs := []attr{s("path", in.str("path")), s("key_path", in.str("privatekey_path")), {key: "days", val: cty.NumberIntVal(int64(days))}}
	for _, a := range steps[0].attrs {
		if a.key == "common_name" || a.key == "dns_names" || a.key == "ip_addresses" {
			attrs = append(attrs, a)
		}
	}
	if m, ok := in.mode("mode"); ok {
		attrs = append(attrs, m)
	}
	in.ignore("csr_path", "provider", "selfsigned_digest", "selfsigned_version", "selfsigned_create_subject_key_identifier", "return_content", "backup", "select_crypto_backend", "force", "ignore_timestamps")
	return one("tls_self_signed_cert", in.owners(attrs))
}
