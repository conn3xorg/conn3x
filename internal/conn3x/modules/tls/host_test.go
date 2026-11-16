// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package tls

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// queue answers each command with the next of its results, and records
// the commands.
type queue struct {
	res  []ssh.Result
	err  error
	cmds []string
}

func (q *queue) Run(_ context.Context, cmd string, _ []byte) (ssh.Result, error) {
	q.cmds = append(q.cmds, cmd)
	if q.err != nil {
		return ssh.Result{}, q.err
	}
	if len(q.res) == 0 {
		return ssh.Result{}, errors.New("no more results")
	}
	r := q.res[0]
	q.res = q.res[1:]
	return r, nil
}

func out(s string) ssh.Result { return ssh.Result{Stdout: []byte(s)} }

func pubPEM(t *testing.T, pub crypto.PublicKey) string {
	t.Helper()
	b, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: b}))
}

func ecKey(t *testing.T, c elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestReadKey(t *testing.T) {
	ctx := context.Background()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	edPub, _, _ := ed25519.GenerateKey(rand.Reader)
	for name, c := range map[string]struct {
		stdout string
		want   KeyState
	}{
		"missing": {"", KeyState{}},
		"rsa":     {"600 root ssl\n" + pubPEM(t, &rsaKey.PublicKey), KeyState{Exists: true, Type: "rsa", Bits: 2048, Mode: "0600", Owner: "root", Group: "ssl"}},
		"ecdsa":   {"640 root ssl\n" + pubPEM(t, &ecKey(t, elliptic.P384()).PublicKey), KeyState{Exists: true, Type: "ecdsa", Curve: "P-384", Mode: "0640", Owner: "root", Group: "ssl"}},
		"ed25519": {"600 a b\n" + pubPEM(t, edPub), KeyState{Exists: true, Type: "ed25519", Mode: "0600", Owner: "a", Group: "b"}},
		// openssl printed nothing: the file isn't a key it can read.
		"not a key": {"644 a b\n", KeyState{Exists: true, Mode: "0644", Owner: "a", Group: "b"}},
		"bad PEM":   {"644 a b\n-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n", KeyState{Exists: true, Mode: "0644", Owner: "a", Group: "b"}},
	} {
		got, err := ReadKey(ctx, &queue{res: []ssh.Result{out(c.stdout)}}, "/k")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		pemOK := got.PublicKeyPEM != "" == (c.want.Type != "")
		got.PublicKeyPEM = ""
		if got != c.want || !pemOK {
			t.Errorf("%s: got %+v, want %+v", name, got, c.want)
		}
	}

	if _, err := ReadKey(ctx, &queue{res: []ssh.Result{out("weird\n")}}, "/k"); err == nil || !strings.Contains(err.Error(), `unexpected stat output "weird"`) {
		t.Errorf("bad stat: %v", err)
	}
	if _, err := ReadKey(ctx, &queue{res: []ssh.Result{{ExitCode: 1, Stderr: []byte("/k is not a regular file\n")}}}, "/k"); err == nil || err.Error() != "/k is not a regular file" {
		t.Errorf("failed read: %v", err)
	}
	if _, err := ReadKey(ctx, &queue{err: errors.New("connection lost")}, "/k"); err == nil || err.Error() != "connection lost" {
		t.Errorf("runner error: %v", err)
	}
}

func TestApplyKey(t *testing.T) {
	ctx := context.Background()
	ec := pubPEM(t, &ecKey(t, elliptic.P256()).PublicKey)
	k := Key{Path: "/etc/ssl/k.pem", Type: "ecdsa", Group: "ssl", Mode: "0640"}
	good := out("640 root ssl\n" + ec)

	t.Run("missing key is generated", func(t *testing.T) {
		q := &queue{res: []ssh.Result{out(""), {}, good}}
		if err := ApplyKey(ctx, q, k); err != nil {
			t.Fatal(err)
		}
		if len(q.cmds) != 3 || !strings.Contains(q.cmds[1], "openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256") || !strings.Contains(q.cmds[1], "chmod 0640") {
			t.Errorf("write script:\n%s", q.cmds[1])
		}
	})
	t.Run("key of the right kind is kept", func(t *testing.T) {
		q := &queue{res: []ssh.Result{out("600 root root\n" + ec), {}, good}}
		if err := ApplyKey(ctx, q, k); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(q.cmds[1], "genpkey") || !strings.Contains(q.cmds[1], `cp -- "$p" "$tmp"`) {
			t.Errorf("a matching key was replaced:\n%s", q.cmds[1])
		}
	})
	t.Run("key of another kind is replaced", func(t *testing.T) {
		q := &queue{res: []ssh.Result{out("640 root ssl\n" + ec), {}, out("600 root root\n" + ec)}}
		err := ApplyKey(ctx, q, Key{Path: "/k", Type: "ed25519"})
		if !strings.Contains(q.cmds[1], "openssl genpkey -algorithm ED25519") {
			t.Errorf("write script:\n%s", q.cmds[1])
		}
		// The read back still finds the old key.
		if err == nil || err.Error() != "/k doesn't hold the key asked for after writing it: found a ecdsa key, mode 0600, owner root:root" {
			t.Errorf("got %v", err)
		}
	})
	t.Run("rsa size", func(t *testing.T) {
		if got := (Key{Type: "rsa", Bits: 4096}).genpkey(); got != "openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096" {
			t.Errorf("got %q", got)
		}
	})
	t.Run("file that isn't a key is left alone", func(t *testing.T) {
		q := &queue{res: []ssh.Result{out("644 root root\n")}}
		if err := ApplyKey(ctx, q, k); err == nil || !strings.Contains(err.Error(), "isn't an unencrypted private key") || len(q.cmds) != 1 {
			t.Errorf("got %v after %d commands", err, len(q.cmds))
		}
	})
	t.Run("unreadable after writing", func(t *testing.T) {
		q := &queue{res: []ssh.Result{out(""), {}, out("")}}
		if err := ApplyKey(ctx, q, k); err == nil || !strings.Contains(err.Error(), "found a unreadable key") {
			t.Errorf("got %v", err)
		}
	})
	t.Run("errors", func(t *testing.T) {
		q := &queue{}
		if err := ApplyKey(ctx, q, Key{Path: "rel"}); err == nil || len(q.cmds) != 0 {
			t.Errorf("an invalid key reached the host: %v", err)
		}
		if err := ApplyKey(ctx, &queue{err: errors.New("down")}, k); err == nil || err.Error() != "down" {
			t.Errorf("read: %v", err)
		}
		q = &queue{res: []ssh.Result{out(""), {ExitCode: 1, Stderr: []byte("openssl isn't installed")}}}
		if err := ApplyKey(ctx, q, k); err == nil || err.Error() != "openssl isn't installed" {
			t.Errorf("write: %v", err)
		}
		q = &queue{res: []ssh.Result{out(""), {}, {ExitCode: 1, Stdout: []byte("gone")}}}
		if err := ApplyKey(ctx, q, k); err == nil || err.Error() != "gone" {
			t.Errorf("read back: %v", err)
		}
	})
}

func TestKeyValidateMore(t *testing.T) {
	for want, k := range map[string]Key{
		"curve is for an ecdsa key":  {Path: "/k", Curve: "P-256"},
		"size comes from its curve":  {Path: "/k", Type: "ecdsa", Bits: 256},
		"four octal digits":          {Path: "/k", Mode: "600"},
		"must be an absolute path":   {Path: "/k\n/x"},
		"takes neither bits nor cur": {Path: "/k", Type: "ed25519", Curve: "P-256"},
	} {
		if err := k.Validate(); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%+v: %v, want %q", k, err, want)
		}
	}
	if k := (Key{Type: "ed25519"}).WithDefaults(); k.Bits != 0 || k.Curve != "" || k.Mode != "0600" {
		t.Errorf("ed25519 defaults %+v", k)
	}
}

// selfSigned makes a certificate for key, signed by signer.
func selfSigned(t *testing.T, key, signer *ecdsa.PrivateKey, notAfter time.Time) string {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "web1"},
		DNSNames:     []string{"web1.example"},
		IPAddresses:  []net.IP{net.ParseIP("10.0.0.1")},
		NotBefore:    notAfter.Add(-365 * 24 * time.Hour),
		NotAfter:     notAfter,
	}
	b, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b}))
}

func TestReadCert(t *testing.T) {
	ctx := context.Background()
	key, other := ecKey(t, elliptic.P256()), ecKey(t, elliptic.P256())
	notAfter := time.Date(2027, 11, 12, 0, 0, 0, 0, time.UTC)
	cert := selfSigned(t, key, key, notAfter)
	c := Cert{Path: "/c", KeyPath: "/k", CommonName: "web1"}
	read := func(stdout string) CertState {
		t.Helper()
		s, err := ReadCert(ctx, &queue{res: []ssh.Result{out(stdout)}}, c)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}

	s := read("644 root root\n" + cert + certSplit + "\n" + pubPEM(t, &key.PublicKey))
	if !s.Exists || s.PEM != cert || s.CommonName != "web1" || s.DNSNames[0] != "web1.example" || s.IPs[0] != "10.0.0.1" || !s.NotAfter.Equal(notAfter) || !s.KeyMatches || s.Mode != "0644" {
		t.Errorf("got %+v", s)
	}
	if s := read("644 root root\n" + cert + certSplit + "\n" + pubPEM(t, &other.PublicKey)); s.KeyMatches || s.PEM == "" {
		t.Errorf("a certificate for another key: %+v", s)
	}
	// Signed by another key, for this one: not self-signed with it.
	if s := read("644 root root\n" + selfSigned(t, key, other, notAfter) + certSplit + "\n" + pubPEM(t, &key.PublicKey)); s.KeyMatches {
		t.Errorf("a certificate another key signed: %+v", s)
	}
	if s := read("644 root root\n" + cert + certSplit + "\n"); s.KeyMatches || s.PEM == "" {
		t.Errorf("no key: %+v", s)
	}
	for name, body := range map[string]string{
		"not a certificate":  "junk\n",
		"another PEM":        pubPEM(t, &key.PublicKey),
		"broken certificate": "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
	} {
		if s := read("644 a b\n" + body + certSplit + "\n"); !s.Exists || s.PEM != "" || s.Owner != "a" {
			t.Errorf("%s: got %+v", name, s)
		}
	}
	if s := read(""); s.Exists {
		t.Errorf("missing: %+v", s)
	}
	if _, err := ReadCert(ctx, &queue{res: []ssh.Result{out("x y\n")}}, c); err == nil || !strings.Contains(err.Error(), "reading /c: unexpected stat output") {
		t.Errorf("bad stat: %v", err)
	}
	if _, err := ReadCert(ctx, &queue{err: errors.New("down")}, c); err == nil {
		t.Error("runner error ignored")
	}
}

func TestApplyCert(t *testing.T) {
	ctx := context.Background()
	key := ecKey(t, elliptic.P256())
	now := time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC)
	c := Cert{Path: "/c", KeyPath: "/k", CommonName: "web1", DNSNames: []string{"web1.example"}, IPs: []string{"10.0.0.1"}, Owner: "www"}
	fresh := "644 www root\n" + selfSigned(t, key, key, now.Add(300*24*time.Hour)) + certSplit + "\n" + pubPEM(t, &key.PublicKey)
	expiring := "600 root root\n" + selfSigned(t, key, key, now.Add(10*24*time.Hour)) + certSplit + "\n" + pubPEM(t, &key.PublicKey)

	// Only the mode and owner differ: the certificate is copied, not reissued.
	q := &queue{res: []ssh.Result{out("600 root root\n" + fresh[len("644 www root\n"):]), {}, out(fresh)}}
	if err := ApplyCert(ctx, q, c, now); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(q.cmds[1], "openssl req") || !strings.Contains(q.cmds[1], `cp -- "$p" "$tmp"`) {
		t.Errorf("a matching certificate was reissued:\n%s", q.cmds[1])
	}

	q = &queue{res: []ssh.Result{out(expiring), {}, out(fresh)}}
	if err := ApplyCert(ctx, q, c, now); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(q.cmds[1], "openssl req -x509 -new") || !strings.Contains(q.cmds[1], "-days 365") || !strings.Contains(q.cmds[1], "subjectAltName = DNS:web1.example,IP:10.0.0.1") {
		t.Errorf("an expiring certificate wasn't reissued:\n%s", q.cmds[1])
	}

	q = &queue{res: []ssh.Result{out(""), {}, out(expiring)}}
	if err := ApplyCert(ctx, q, c, now); err == nil || err.Error() != "/c doesn't hold the certificate asked for after writing it" {
		t.Errorf("read back still expiring: %v", err)
	}
	q = &queue{}
	if err := ApplyCert(ctx, q, Cert{Path: "/c", KeyPath: "k", CommonName: "x"}, now); err == nil || !strings.Contains(err.Error(), "key_path") || len(q.cmds) != 0 {
		t.Errorf("invalid: %v", err)
	}
	if err := ApplyCert(ctx, &queue{err: errors.New("down")}, c, now); err == nil {
		t.Error("read error ignored")
	}
	q = &queue{res: []ssh.Result{out(""), {ExitCode: 1, Stderr: []byte("there's no key at /k")}}}
	if err := ApplyCert(ctx, q, c, now); err == nil || err.Error() != "there's no key at /k" {
		t.Errorf("write: %v", err)
	}
	q = &queue{res: []ssh.Result{out(""), {}, {ExitCode: 1, Stderr: []byte("gone")}}}
	if err := ApplyCert(ctx, q, c, now); err == nil || err.Error() != "gone" {
		t.Errorf("read back: %v", err)
	}
}

func TestCertValidateMore(t *testing.T) {
	for want, bad := range map[string]Cert{
		"path \"\"":         {KeyPath: "/k", CommonName: "x"},
		"from 1 to 3650":    {Path: "/c", KeyPath: "/k", CommonName: "x", Days: 4000},
		"renew_before_days": {Path: "/c", KeyPath: "/k", CommonName: "x", RenewDays: -1},
		"four octal digits": {Path: "/c", KeyPath: "/k", CommonName: "x", Mode: "rw"},
	} {
		if err := bad.Validate(); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%+v: %v, want %q", bad, err, want)
		}
	}
	if cfg := (Cert{CommonName: "x"}).config(); strings.Contains(cfg, "subjectAltName") {
		t.Errorf("a certificate without names got subjectAltName:\n%s", cfg)
	}
	s := CertState{Exists: true, PEM: "x", KeyMatches: true, CommonName: "x", NotAfter: time.Now().Add(100 * 24 * time.Hour), Mode: "0644", Owner: "a", Group: "b"}
	c := Cert{CommonName: "x", Owner: "a", Group: "b"}
	if !c.Matches(s, time.Now()) {
		t.Error("owner and group as asked should match")
	}
	for _, d := range []Cert{{CommonName: "x", Owner: "z"}, {CommonName: "x", Group: "z"}, {CommonName: "x", IPs: []string{"10.0.0.1"}}, {CommonName: "y"}} {
		if d.Matches(s, time.Now()) {
			t.Errorf("%+v matched %+v", d, s)
		}
	}
}

func csrPEM(t *testing.T, key, signer *ecdsa.PrivateKey) string {
	t.Helper()
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "web1"}, DNSNames: []string{"web1.example"}, IPAddresses: []net.IP{net.ParseIP("::1")}}
	b, err := x509.CreateCertificateRequest(rand.Reader, tmpl, signer)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: b}))
}

func TestReadCSR(t *testing.T) {
	ctx := context.Background()
	key, other := ecKey(t, elliptic.P256()), ecKey(t, elliptic.P256())
	req := csrPEM(t, key, key)
	c := CSR{Path: "/r", KeyPath: "/k", CommonName: "web1"}
	read := func(stdout string) CSRState {
		t.Helper()
		s, err := ReadCSR(ctx, &queue{res: []ssh.Result{out(stdout)}}, c)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	s := read("644 root root\n" + req + certSplit + "\n" + pubPEM(t, &key.PublicKey))
	if !s.Exists || s.PEM != req || s.CommonName != "web1" || s.DNSNames[0] != "web1.example" || s.IPs[0] != "::1" || !s.KeyMatches {
		t.Errorf("got %+v", s)
	}
	if s := read("644 root root\n" + csrPEM(t, other, other) + certSplit + "\n" + pubPEM(t, &key.PublicKey)); s.KeyMatches {
		t.Errorf("a request for another key: %+v", s)
	}
	for name, body := range map[string]string{
		"not a request":  "junk\n",
		"a certificate":  selfSigned(t, key, key, time.Now()),
		"broken request": "-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----\n",
	} {
		if s := read("644 a b\n" + body + certSplit + "\n"); !s.Exists || s.PEM != "" {
			t.Errorf("%s: got %+v", name, s)
		}
	}
	if s := read("\n"); s.Exists {
		t.Errorf("missing: %+v", s)
	}
	if _, err := ReadCSR(ctx, &queue{res: []ssh.Result{out("x\n")}}, c); err == nil || !strings.Contains(err.Error(), "unexpected stat output") {
		t.Errorf("bad stat: %v", err)
	}
	if _, err := ReadCSR(ctx, &queue{err: errors.New("down")}, c); err == nil {
		t.Error("runner error ignored")
	}
}

func TestApplyCSR(t *testing.T) {
	ctx := context.Background()
	key := ecKey(t, elliptic.P256())
	c := CSR{Path: "/r", KeyPath: "/k", CommonName: "web1", DNSNames: []string{"web1.example"}, IPs: []string{"::1"}, Group: "ssl"}
	body := csrPEM(t, key, key) + certSplit + "\n" + pubPEM(t, &key.PublicKey)
	good := out("644 root ssl\n" + body)

	q := &queue{res: []ssh.Result{out("600 root root\n" + body), {}, good}}
	if err := ApplyCSR(ctx, q, c); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(q.cmds[1], "openssl req") || !strings.Contains(q.cmds[1], "chmod 0644") {
		t.Errorf("a matching request was made again:\n%s", q.cmds[1])
	}

	q = &queue{res: []ssh.Result{out(""), {}, good}}
	if err := ApplyCSR(ctx, q, c); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(q.cmds[1], "openssl req -new -config") || !strings.Contains(q.cmds[1], "req_extensions = ext") {
		t.Errorf("a missing request wasn't made:\n%s", q.cmds[1])
	}

	q = &queue{res: []ssh.Result{out(""), {}, out("")}}
	if err := ApplyCSR(ctx, q, c); err == nil || err.Error() != "/r doesn't hold the request asked for after writing it" {
		t.Errorf("read back: %v", err)
	}
	q = &queue{}
	if err := ApplyCSR(ctx, q, CSR{Path: "/r", KeyPath: "/r", CommonName: "x"}); err == nil || len(q.cmds) != 0 {
		t.Errorf("invalid: %v", err)
	}
	if err := ApplyCSR(ctx, &queue{err: errors.New("down")}, c); err == nil {
		t.Error("read error ignored")
	}
	q = &queue{res: []ssh.Result{out(""), {ExitCode: 1, Stderr: []byte("no")}}}
	if err := ApplyCSR(ctx, q, c); err == nil || err.Error() != "no" {
		t.Errorf("write: %v", err)
	}
	q = &queue{res: []ssh.Result{out(""), {}, {ExitCode: 2, Stderr: []byte("gone")}}}
	if err := ApplyCSR(ctx, q, c); err == nil || err.Error() != "gone" {
		t.Errorf("read back error: %v", err)
	}
	s := CSRState{Exists: true, PEM: "x", KeyMatches: true, CommonName: "web1", DNSNames: []string{"web1.example"}, IPs: []string{"::1"}, Mode: "0644", Owner: "a", Group: "ssl"}
	if !c.Matches(s) {
		t.Error("should match")
	}
	if d := c; func() bool { d.Owner = "b"; return d.Matches(s) }() {
		t.Error("another owner matched")
	}
}

func TestDelete(t *testing.T) {
	ctx := context.Background()
	q := &queue{res: []ssh.Result{{}, {}}}
	if err := DeleteKey(ctx, q, "/k"); err != nil {
		t.Fatal(err)
	}
	if err := DeleteCert(ctx, q, "/c"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(q.cmds[0], "route_walk parent '/k'") || !strings.Contains(q.cmds[1], "route_walk parent '/c'") {
		t.Errorf("commands %q", q.cmds)
	}
}
