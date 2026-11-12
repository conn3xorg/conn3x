// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package tls

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/opentofu/opentofu/internal/conn3x/modules"
	"github.com/opentofu/opentofu/internal/conn3x/modules/file"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

var (
	commonName = regexp.MustCompile(`^[A-Za-z0-9*][A-Za-z0-9 .*_-]{0,63}$`)
	dnsName    = regexp.MustCompile(`^(\*\.)?([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)
)

// Cert is a self-signed certificate for a key already on the host.
type Cert struct {
	Path, KeyPath      string
	CommonName         string
	DNSNames, IPs      []string
	Days               int // valid for, default 365
	RenewDays          int // renewed this many days before it expires, default 30
	Mode, Owner, Group string
}

// WithDefaults fills in the validity, renewal and mode left unset.
func (c Cert) WithDefaults() Cert {
	if c.Days == 0 {
		c.Days = 365
	}
	if c.RenewDays == 0 {
		c.RenewDays = 30
	}
	if c.Mode == "" {
		c.Mode = "0644"
	}
	return c
}

// Validate checks a Cert, with its defaults, before anything reaches the host.
func (c Cert) Validate() error {
	c = c.WithDefaults()
	if err := absolute("path", c.Path); err != nil {
		return err
	}
	if err := absolute("key_path", c.KeyPath); err != nil {
		return err
	}
	if c.Path == c.KeyPath {
		return errors.New("path and key_path must be different files")
	}
	if !commonName.MatchString(c.CommonName) {
		return fmt.Errorf("common_name %q: use letters, digits, spaces and . * _ -, up to 64 characters", c.CommonName)
	}
	for _, d := range c.DNSNames {
		if !dnsName.MatchString(d) {
			return fmt.Errorf("dns_names: %q isn't a host name", d)
		}
	}
	for _, ip := range c.IPs {
		if net.ParseIP(ip) == nil {
			return fmt.Errorf("ip_addresses: %q isn't an IP address", ip)
		}
	}
	if c.Days < 1 || c.Days > 3650 {
		return fmt.Errorf("days %d must be from 1 to 3650", c.Days)
	}
	if c.RenewDays < 0 || c.RenewDays >= c.Days {
		return fmt.Errorf("renew_before_days %d must be less than days, %d, or every refresh would renew it", c.RenewDays, c.Days)
	}
	if !modeOctal.MatchString(c.Mode) {
		return fmt.Errorf("mode %q must be four octal digits, like \"0644\"", c.Mode)
	}
	return nil
}

// CertState is what a read finds at a certificate's path.
type CertState struct {
	Exists             bool
	PEM                string // "" if the file isn't a certificate
	CommonName         string
	DNSNames, IPs      []string
	NotAfter           time.Time
	KeyMatches         bool // signed with, and for, the key at key_path
	Mode, Owner, Group string
}

// Matches reports whether the host's certificate is c: its names, its key,
// its mode, owner and group, and more than renew_before_days left at now.
func (c Cert) Matches(s CertState, now time.Time) bool {
	c = c.WithDefaults()
	same := func(a, b []string) bool {
		a, b = slices.Clone(a), slices.Clone(b)
		slices.Sort(a)
		slices.Sort(b)
		return slices.Equal(a, b)
	}
	return s.Exists && s.PEM != "" && s.KeyMatches && s.CommonName == c.CommonName && same(s.DNSNames, c.DNSNames) && same(s.IPs, normalIPs(c.IPs)) &&
		s.NotAfter.Sub(now) > time.Duration(c.RenewDays)*24*time.Hour &&
		s.Mode == c.Mode && (c.Owner == "" || s.Owner == c.Owner) && (c.Group == "" || s.Group == c.Group)
}

func normalIPs(ips []string) []string {
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		if p := net.ParseIP(ip); p != nil {
			out = append(out, p.String())
		}
	}
	return out
}

const certSplit = "--conn3x-key--"

// ReadCert reports what is at c.Path, and whether it is for the key at
// c.KeyPath.
func ReadCert(ctx context.Context, r modules.Runner, c Cert) (CertState, error) {
	script := modules.Settled + fmt.Sprintf(`p=%s
k=%s
route_settled "$p" || exit 0
[ -e "$p" ] || exit 0
[ -f "$p" ] || { echo "$p is not a regular file" >&2; exit 1; }
stat -c '%%a %%U %%G' -- "$p"
command -v openssl >/dev/null 2>&1 || { echo "openssl isn't installed; add a package step for it first" >&2; exit 1; }
openssl x509 -in "$p" 2>/dev/null || true
echo %s
route_settled "$k" || exit 0
[ -f "$k" ] && openssl pkey -in "$k" -passin pass: -pubout 2>/dev/null || true`, ssh.Quote(c.Path), ssh.Quote(c.KeyPath), certSplit)
	res, err := r.Run(ctx, modules.Guard(script, modules.Follow(c.Path), modules.Follow(c.KeyPath)), nil)
	if err := check(res, err); err != nil {
		return CertState{}, err
	}
	out := string(res.Stdout)
	if strings.TrimSpace(out) == "" {
		return CertState{}, nil
	}
	first, rest, _ := strings.Cut(out, "\n")
	f := strings.Fields(first)
	if len(f) != 3 {
		return CertState{}, fmt.Errorf("reading %s: unexpected stat output %q", c.Path, first)
	}
	s := CertState{Exists: true, Mode: strings.Repeat("0", max(0, 4-len(f[0]))) + f[0], Owner: f[1], Group: f[2]}
	certPart, keyPart, _ := strings.Cut(rest, certSplit)
	block, _ := pem.Decode([]byte(certPart))
	if block == nil || block.Type != "CERTIFICATE" {
		return s, nil
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return s, nil
	}
	s.PEM = string(pem.EncodeToMemory(block))
	s.CommonName, s.DNSNames, s.NotAfter = cert.Subject.CommonName, cert.DNSNames, cert.NotAfter
	for _, ip := range cert.IPAddresses {
		s.IPs = append(s.IPs, ip.String())
	}
	if kb, _ := pem.Decode([]byte(keyPart)); kb != nil {
		// CheckSignatureFrom would refuse it: the certificate isn't a CA.
		self := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) == nil
		s.KeyMatches = self && bytes.Equal(kb.Bytes, cert.RawSubjectPublicKeyInfo)
	}
	return s, nil
}

// config is the openssl req config for c: no CA, the server and client
// uses, and its names. A config of its own keeps the distribution's
// defaults, which often make a CA, out of it.
func (c Cert) config() string {
	var b strings.Builder
	fmt.Fprintf(&b, "[req]\ndistinguished_name = dn\nprompt = no\n[dn]\nCN = %s\n[ext]\nbasicConstraints = critical,CA:FALSE\nkeyUsage = critical,digitalSignature,keyEncipherment\nextendedKeyUsage = serverAuth,clientAuth\nsubjectKeyIdentifier = hash\n", c.CommonName)
	var san []string
	for _, d := range c.DNSNames {
		san = append(san, "DNS:"+d)
	}
	for _, ip := range normalIPs(c.IPs) {
		san = append(san, "IP:"+ip)
	}
	if len(san) > 0 {
		fmt.Fprintf(&b, "subjectAltName = %s\n", strings.Join(san, ","))
	}
	return b.String()
}

// ApplyCert writes a new self-signed certificate for the key at c.KeyPath,
// unless the one there already matches, when only its mode, owner and group
// are set. now is when the read decided.
func ApplyCert(ctx context.Context, r modules.Runner, c Cert, now time.Time) error {
	if err := c.Validate(); err != nil {
		return err
	}
	c = c.WithDefaults()
	have, err := ReadCert(ctx, r, c)
	if err != nil {
		return err
	}
	write := fmt.Sprintf(`[ -f "$k" ] || { echo "there's no key at $k; add a tls_private_key step before this one" >&2; exit 1; }
cfg=$(mktemp)
trap 'rm -f -- "$tmp" "$cfg"' EXIT
printf '%%s' %s > "$cfg"
openssl req -x509 -new -config "$cfg" -extensions ext -key "$k" -days %d -out "$tmp" 2>&1 >/dev/null
rm -f -- "$cfg"
trap 'rm -f -- "$tmp"' EXIT`, ssh.Quote(c.config()), c.Days)
	keep := c
	keep.Mode, keep.Owner, keep.Group = have.Mode, have.Owner, have.Group
	if keep.Matches(have, now) {
		write = `cp -- "$p" "$tmp"`
	}
	script := fmt.Sprintf(`set -e
p=%[1]s
k=%[2]s
[ ! -L "$p" ] || { echo "$p is a link; a certificate goes in a regular file" >&2; exit 1; }
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
		ssh.Quote(c.Path), ssh.Quote(c.KeyPath), write, c.Mode, file.Ownership(c.Owner, c.Group))
	res, err := r.Run(ctx, modules.GuardWrite(script, modules.Write{Owner: c.Owner, Group: c.Group, Path: c.Path}, modules.Parent(c.Path), modules.Follow(c.KeyPath)), nil)
	if err := check(res, err); err != nil {
		return err
	}
	got, err := ReadCert(ctx, r, c)
	if err != nil {
		return err
	}
	if !c.Matches(got, now) {
		return fmt.Errorf("%s doesn't hold the certificate asked for after writing it", c.Path)
	}
	return nil
}

// DeleteCert removes the certificate file.
func DeleteCert(ctx context.Context, r modules.Runner, p string) error {
	return file.Delete(ctx, r, p)
}
