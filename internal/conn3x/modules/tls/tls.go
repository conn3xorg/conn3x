// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package tls makes TLS private keys and self-signed certificates on a
// host with its own openssl, so a private key never leaves the host.
package tls

import (
	"cmp"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/opentofu/opentofu/internal/conn3x/modules"
	"github.com/opentofu/opentofu/internal/conn3x/modules/file"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

var modeOctal = regexp.MustCompile(`^[0-7]{4}$`)

// Key is a private key in a PEM file.
type Key struct {
	Path               string
	Type               string // "rsa" (default), "ecdsa" or "ed25519"
	Bits               int    // rsa: 2048, 3072 (default) or 4096
	Curve              string // ecdsa: "P-256" (default) or "P-384"
	Mode, Owner, Group string // mode defaults to 0600
}

// WithDefaults fills in the type, size, curve and mode left unset.
func (k Key) WithDefaults() Key {
	if k.Type == "" {
		k.Type = "rsa"
	}
	if k.Type == "rsa" && k.Bits == 0 {
		k.Bits = 3072
	}
	if k.Type == "ecdsa" && k.Curve == "" {
		k.Curve = "P-256"
	}
	if k.Mode == "" {
		k.Mode = "0600"
	}
	return k
}

func absolute(label, p string) error {
	if !path.IsAbs(p) || strings.ContainsAny(p, "\r\n") {
		return fmt.Errorf("%s %q must be an absolute path", label, p)
	}
	return nil
}

// Validate checks a Key, with its defaults, before anything reaches the host.
func (k Key) Validate() error {
	k = k.WithDefaults()
	if err := absolute("path", k.Path); err != nil {
		return err
	}
	switch k.Type {
	case "rsa":
		if k.Bits != 2048 && k.Bits != 3072 && k.Bits != 4096 {
			return fmt.Errorf("bits %d: an RSA key is 2048, 3072 or 4096 bits", k.Bits)
		}
		if k.Curve != "" {
			return errors.New("curve is for an ecdsa key, not rsa")
		}
	case "ecdsa":
		if k.Curve != "P-256" && k.Curve != "P-384" {
			return fmt.Errorf("curve %q: an ECDSA key uses P-256 or P-384", k.Curve)
		}
		if k.Bits != 0 {
			return errors.New("bits is for an rsa key; an ecdsa key's size comes from its curve")
		}
	case "ed25519":
		if k.Bits != 0 || k.Curve != "" {
			return errors.New("an ed25519 key takes neither bits nor curve")
		}
	default:
		return fmt.Errorf("type %q must be \"rsa\", \"ecdsa\" or \"ed25519\"", k.Type)
	}
	if !modeOctal.MatchString(k.Mode) {
		return fmt.Errorf("mode %q must be four octal digits, like \"0600\"", k.Mode)
	}
	if k.Mode[3] != '0' {
		return fmt.Errorf("mode %q lets anyone read the private key; end it in 0, like \"0600\" or \"0640\"", k.Mode)
	}
	return nil
}

// KeyState is what a read finds at a key's path.
type KeyState struct {
	Exists             bool
	Type               string // "" if the file isn't a private key openssl reads
	Bits               int
	Curve              string
	PublicKeyPEM       string
	Mode, Owner, Group string
}

// Matches reports whether the host's key is k: the same kind of key, and
// the same mode, and the owner and group where k sets them.
func (k Key) Matches(s KeyState) bool {
	k = k.WithDefaults()
	return s.Exists && s.Type == k.Type && s.Bits == k.Bits && s.Curve == k.Curve && s.Mode == k.Mode &&
		(k.Owner == "" || s.Owner == k.Owner) && (k.Group == "" || s.Group == k.Group)
}

// ReadKey reports what is at p. A file there that openssl can't read as an
// unencrypted private key exists with an empty Type.
func ReadKey(ctx context.Context, r modules.Runner, p string) (KeyState, error) {
	script := modules.Settled + fmt.Sprintf(`p=%s
route_settled "$p" || exit 0
[ -e "$p" ] || exit 0
[ -f "$p" ] || { echo "$p is not a regular file" >&2; exit 1; }
stat -c '%%a %%U %%G' -- "$p"
command -v openssl >/dev/null 2>&1 || { echo "openssl isn't installed; add a package step for it first" >&2; exit 1; }
openssl pkey -in "$p" -passin pass: -pubout 2>/dev/null || true`, ssh.Quote(p))
	res, err := r.Run(ctx, modules.Guard(script, modules.Follow(p)), nil)
	if err := check(res, err); err != nil {
		return KeyState{}, err
	}
	out := string(res.Stdout)
	if strings.TrimSpace(out) == "" {
		return KeyState{}, nil
	}
	first, rest, _ := strings.Cut(out, "\n")
	s := KeyState{Exists: true}
	f := strings.Fields(first)
	if len(f) != 3 {
		return KeyState{}, fmt.Errorf("reading %s: unexpected stat output %q", p, first)
	}
	s.Mode, s.Owner, s.Group = strings.Repeat("0", max(0, 4-len(f[0])))+f[0], f[1], f[2]
	if block, _ := pem.Decode([]byte(rest)); block != nil {
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err == nil {
			s.PublicKeyPEM = string(pem.EncodeToMemory(block))
			switch k := pub.(type) {
			case *rsa.PublicKey:
				s.Type, s.Bits = "rsa", k.N.BitLen()
			case *ecdsa.PublicKey:
				s.Type, s.Curve = "ecdsa", k.Curve.Params().Name
			case ed25519.PublicKey:
				s.Type = "ed25519"
			}
		}
	}
	return s, nil
}

// genpkey is the openssl command that makes a new key of k's kind.
func (k Key) genpkey() string {
	switch k.Type {
	case "ecdsa":
		return "openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:" + k.Curve + " -pkeyopt ec_param_enc:named_curve"
	case "ed25519":
		return "openssl genpkey -algorithm ED25519"
	}
	return fmt.Sprintf("openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:%d", k.Bits)
}

// ApplyKey makes the host's key k. A key of the right kind is kept and only
// its mode, owner and group are set; one of another kind, or a missing one,
// is generated anew on the host. A file there that isn't a private key is
// left alone, with an error, rather than overwritten.
func ApplyKey(ctx context.Context, r modules.Runner, k Key) error {
	if err := k.Validate(); err != nil {
		return err
	}
	k = k.WithDefaults()
	have, err := ReadKey(ctx, r, k.Path)
	if err != nil {
		return err
	}
	if have.Exists && have.Type == "" {
		return fmt.Errorf("%s is there but isn't an unencrypted private key openssl can read; move it away, or point path somewhere else", k.Path)
	}
	write := "cp -- \"$p\" \"$tmp\""
	if have.Type != k.Type || have.Bits != k.Bits || have.Curve != k.Curve {
		write = k.genpkey() + " -out \"$tmp\" 2>&1 >/dev/null"
	}
	// The temporary file is never readable by others, from mktemp on.
	script := fmt.Sprintf(`set -e
umask 077
p=%[1]s
[ ! -L "$p" ] || { echo "$p is a link; a private key goes in a regular file" >&2; exit 1; }
command -v openssl >/dev/null 2>&1 || { echo "openssl isn't installed; add a package step for it first" >&2; exit 1; }
mkdir -p -- "$(dirname -- "$p")"
tmp=$(mktemp "$(dirname -- "$p")/.conn3x.XXXXXX")
trap 'rm -f -- "$tmp"' EXIT
%[2]s
chmod %[3]s "$tmp"
%[4]s`+file.SyncFile+`
`+file.Replace+`
trap - EXIT
`+file.SyncDir+`
if command -v restorecon >/dev/null 2>&1; then restorecon -- "$p" 2>/dev/null || true; fi`,
		ssh.Quote(k.Path), write, k.Mode, file.Ownership(k.Owner, k.Group))
	res, err := r.Run(ctx, modules.GuardWrite(script, modules.Write{Owner: k.Owner, Group: k.Group, Path: k.Path}, modules.Parent(k.Path)), nil)
	if err := check(res, err); err != nil {
		return err
	}
	got, err := ReadKey(ctx, r, k.Path)
	if err != nil {
		return err
	}
	if !k.Matches(got) {
		return fmt.Errorf("%s doesn't hold the key asked for after writing it: found a %s key, mode %s, owner %s:%s", k.Path, cmp.Or(got.Type, "unreadable"), got.Mode, got.Owner, got.Group)
	}
	return nil
}

// DeleteKey removes the key file.
func DeleteKey(ctx context.Context, r modules.Runner, p string) error {
	return file.Delete(ctx, r, p)
}

func check(res ssh.Result, err error) error {
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return errors.New(strings.TrimSpace(string(res.Stderr) + string(res.Stdout)))
	}
	return nil
}
