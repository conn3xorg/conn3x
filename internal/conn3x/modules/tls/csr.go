// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package tls

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"slices"
	"strings"

	"github.com/opentofu/opentofu/internal/conn3x/modules"
	"github.com/opentofu/opentofu/internal/conn3x/modules/file"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// CSR is a certificate signing request, for a private CA to sign, made
// from a key already on the host. It takes a Cert's names and paths; its
// validity and renewal don't apply.
type CSR struct {
	Path, KeyPath      string
	CommonName         string
	DNSNames, IPs      []string
	Mode, Owner, Group string
}

func (c CSR) cert() Cert {
	return Cert{Path: c.Path, KeyPath: c.KeyPath, CommonName: c.CommonName, DNSNames: c.DNSNames, IPs: c.IPs, Mode: c.Mode, Owner: c.Owner, Group: c.Group}.WithDefaults()
}

// Validate checks a CSR before anything reaches the host.
func (c CSR) Validate() error { return c.cert().Validate() }

// CSRState is what a read finds at a request's path.
type CSRState struct {
	Exists             bool
	PEM                string // "" if the file isn't a request
	CommonName         string
	DNSNames, IPs      []string
	KeyMatches         bool
	Mode, Owner, Group string
}

// Matches reports whether the host's request is c.
func (c CSR) Matches(s CSRState) bool {
	w := c.cert()
	same := func(a, b []string) bool {
		a, b = slices.Clone(a), slices.Clone(b)
		slices.Sort(a)
		slices.Sort(b)
		return slices.Equal(a, b)
	}
	return s.Exists && s.PEM != "" && s.KeyMatches && s.CommonName == w.CommonName && same(s.DNSNames, w.DNSNames) && same(s.IPs, normalIPs(w.IPs)) &&
		s.Mode == w.Mode && (w.Owner == "" || s.Owner == w.Owner) && (w.Group == "" || s.Group == w.Group)
}

// ReadCSR reports what is at c.Path, and whether it is for the key at
// c.KeyPath.
func ReadCSR(ctx context.Context, r modules.Runner, c CSR) (CSRState, error) {
	script := modules.Settled + fmt.Sprintf(`p=%s
k=%s
route_settled "$p" || exit 0
[ -e "$p" ] || exit 0
[ -f "$p" ] || { echo "$p is not a regular file" >&2; exit 1; }
stat -c '%%a %%U %%G' -- "$p"
command -v openssl >/dev/null 2>&1 || { echo "openssl isn't installed; add a package step for it first" >&2; exit 1; }
openssl req -in "$p" 2>/dev/null || true
echo %s
route_settled "$k" || exit 0
[ -f "$k" ] && openssl pkey -in "$k" -passin pass: -pubout 2>/dev/null || true`, ssh.Quote(c.Path), ssh.Quote(c.KeyPath), certSplit)
	res, err := r.Run(ctx, modules.Guard(script, modules.Follow(c.Path), modules.Follow(c.KeyPath)), nil)
	if err := check(res, err); err != nil {
		return CSRState{}, err
	}
	out := string(res.Stdout)
	if strings.TrimSpace(out) == "" {
		return CSRState{}, nil
	}
	first, rest, _ := strings.Cut(out, "\n")
	f := strings.Fields(first)
	if len(f) != 3 {
		return CSRState{}, fmt.Errorf("reading %s: unexpected stat output %q", c.Path, first)
	}
	s := CSRState{Exists: true, Mode: strings.Repeat("0", max(0, 4-len(f[0]))) + f[0], Owner: f[1], Group: f[2]}
	reqPart, keyPart, _ := strings.Cut(rest, certSplit)
	block, _ := pem.Decode([]byte(reqPart))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return s, nil
	}
	req, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return s, nil
	}
	s.PEM = string(pem.EncodeToMemory(block))
	s.CommonName, s.DNSNames = req.Subject.CommonName, req.DNSNames
	for _, ip := range req.IPAddresses {
		s.IPs = append(s.IPs, ip.String())
	}
	if kb, _ := pem.Decode([]byte(keyPart)); kb != nil {
		s.KeyMatches = req.CheckSignature() == nil && bytes.Equal(kb.Bytes, req.RawSubjectPublicKeyInfo)
	}
	return s, nil
}

// ApplyCSR writes a new request for the key at c.KeyPath, unless the one
// there already matches, when only its mode, owner and group are set.
func ApplyCSR(ctx context.Context, r modules.Runner, c CSR) error {
	if err := c.Validate(); err != nil {
		return err
	}
	w := c.cert()
	have, err := ReadCSR(ctx, r, c)
	if err != nil {
		return err
	}
	// The same config as a certificate's, with the extensions requested.
	cfg := strings.Replace(w.config(), "[req]\n", "[req]\nreq_extensions = ext\n", 1)
	write := fmt.Sprintf(`[ -f "$k" ] || { echo "there's no key at $k; add a tls_private_key step before this one" >&2; exit 1; }
cfg=$(mktemp)
trap 'rm -f -- "$tmp" "$cfg"' EXIT
printf '%%s' %s > "$cfg"
openssl req -new -config "$cfg" -key "$k" -out "$tmp" 2>&1 >/dev/null
rm -f -- "$cfg"
trap 'rm -f -- "$tmp"' EXIT`, ssh.Quote(cfg))
	keep := c
	keep.Mode, keep.Owner, keep.Group = have.Mode, have.Owner, have.Group
	if keep.Matches(have) {
		write = `cp -- "$p" "$tmp"`
	}
	script := fmt.Sprintf(`set -e
p=%[1]s
k=%[2]s
[ ! -L "$p" ] || { echo "$p is a link; a request goes in a regular file" >&2; exit 1; }
command -v openssl >/dev/null 2>&1 || { echo "openssl isn't installed; add a package step for it first" >&2; exit 1; }
mkdir -p -- "$(dirname -- "$p")"
tmp=$(mktemp "$(dirname -- "$p")/.conn3x.XXXXXX")
trap 'rm -f -- "$tmp"' EXIT
%[3]s
chmod %[4]s "$tmp"
%[5]s`+file.SyncFile+`
`+file.Replace+`
trap - EXIT
`+file.SyncDir+`
if command -v restorecon >/dev/null 2>&1; then restorecon -- "$p" 2>/dev/null || true; fi`,
		ssh.Quote(w.Path), ssh.Quote(w.KeyPath), write, w.Mode, file.Ownership(w.Owner, w.Group))
	res, err := r.Run(ctx, modules.GuardWrite(script, modules.Write{Owner: w.Owner, Group: w.Group, Path: w.Path}, modules.Parent(w.Path), modules.Follow(w.KeyPath)), nil)
	if err := check(res, err); err != nil {
		return err
	}
	got, err := ReadCSR(ctx, r, c)
	if err != nil {
		return err
	}
	if !c.Matches(got) {
		return fmt.Errorf("%s doesn't hold the request asked for after writing it", w.Path)
	}
	return nil
}
