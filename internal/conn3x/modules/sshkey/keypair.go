// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package sshkey

import (
	"cmp"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"fmt"
	"path"
	"strings"

	gossh "golang.org/x/crypto/ssh"

	"github.com/opentofu/opentofu/internal/conn3x/modules"
	"github.com/opentofu/opentofu/internal/conn3x/modules/file"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// Keypair is an SSH key made on the host with ssh-keygen: the private key
// at Path, mode 0600, and the public key at Path.pub.
type Keypair struct {
	Path         string
	Type         string // "ed25519" (default), "rsa" or "ecdsa"
	Bits         int    // rsa: 3072 (default) or 4096; ecdsa: 256 (default), 384 or 521
	Comment      string
	Owner, Group string
}

// WithDefaults fills in the type and size left unset.
func (k Keypair) WithDefaults() Keypair {
	if k.Type == "" {
		k.Type = "ed25519"
	}
	if k.Bits == 0 {
		k.Bits = map[string]int{"ed25519": 256, "rsa": 3072, "ecdsa": 256}[k.Type]
	}
	return k
}

// Validate checks a Keypair, with its defaults, before anything reaches the
// host.
func (k Keypair) Validate() error {
	if !path.IsAbs(k.Path) || path.Clean(k.Path) != k.Path || strings.ContainsAny(k.Path, "\r\n") {
		return fmt.Errorf("path %q must be a clean absolute path", k.Path)
	}
	if strings.ContainsAny(k.Comment, "\r\n") {
		return errors.New("comment must be one line")
	}
	bits := k.Bits
	k = k.WithDefaults()
	switch k.Type {
	case "ed25519":
		if bits != 0 {
			return errors.New("an ed25519 key takes no bits")
		}
	case "rsa":
		if k.Bits != 3072 && k.Bits != 4096 {
			return fmt.Errorf("bits %d: an RSA key here is 3072 or 4096 bits", k.Bits)
		}
	case "ecdsa":
		if k.Bits != 256 && k.Bits != 384 && k.Bits != 521 {
			return fmt.Errorf("bits %d: an ECDSA key is 256, 384 or 521 bits", k.Bits)
		}
	default:
		return fmt.Errorf("type %q must be \"ed25519\", \"rsa\" or \"ecdsa\"", k.Type)
	}
	return nil
}

// KeypairState is what a read finds at a keypair's path.
type KeypairState struct {
	Exists       bool
	Type         string // "" if ssh-keygen can't read it as an unencrypted key
	Bits         int
	Public       string // the public key ssh-keygen derives, "type base64"
	PubFile      string // what Path.pub holds, trimmed
	Mode         string
	Owner, Group string
}

// PublicKey is the line Path.pub should hold.
func (k Keypair) PublicKey(s KeypairState) string {
	return strings.TrimSpace(s.Public + " " + k.Comment)
}

// Matches reports whether the host has k: a key of its kind, mode 0600,
// the owner and group where k sets them, and Path.pub to go with it.
func (k Keypair) Matches(s KeypairState) bool {
	k = k.WithDefaults()
	return s.Exists && s.Type == k.Type && s.Bits == k.Bits && s.Mode == "0600" &&
		(k.Owner == "" || s.Owner == k.Owner) && (k.Group == "" || s.Group == k.Group) &&
		s.PubFile == k.PublicKey(s)
}

// keyKind is a public key's type and size in bits.
func keyKind(pub gossh.PublicKey) (string, int) {
	c, ok := pub.(gossh.CryptoPublicKey)
	if !ok {
		return "", 0
	}
	switch k := c.CryptoPublicKey().(type) {
	case ed25519.PublicKey:
		return "ed25519", 256
	case *rsa.PublicKey:
		return "rsa", k.N.BitLen()
	case *ecdsa.PublicKey:
		return "ecdsa", k.Curve.Params().BitSize
	}
	return "", 0
}

// ReadKeypair reports what is at p and p.pub.
func ReadKeypair(ctx context.Context, r modules.Runner, p string) (KeypairState, error) {
	script := modules.Settled + fmt.Sprintf(`p=%s
route_settled "$p" || exit 0
[ -e "$p" ] || exit 0
[ -f "$p" ] || { echo "$p is not a regular file" >&2; exit 1; }
command -v ssh-keygen >/dev/null 2>&1 || { echo "ssh-keygen isn't installed; add a package step for openssh-client first" >&2; exit 1; }
stat -c '%%a %%U %%G' -- "$p"
ssh-keygen -y -P '' -f "$p" 2>/dev/null | awk '{print $1, $2}' || echo
if [ -f "$p.pub" ] && [ ! -L "$p.pub" ]; then head -n 1 -- "$p.pub"; fi`, ssh.Quote(p))
	res, err := r.Run(ctx, modules.Guard(script, modules.Follow(p)), nil)
	if err := check(res, err); err != nil {
		return KeypairState{}, err
	}
	return parseKeypair(p, string(res.Stdout))
}

func parseKeypair(p, out string) (KeypairState, error) {
	if strings.TrimSpace(out) == "" {
		return KeypairState{}, nil
	}
	lines := strings.SplitN(out, "\n", 3)
	for len(lines) < 3 {
		lines = append(lines, "")
	}
	f := strings.Fields(lines[0])
	if len(f) != 3 {
		return KeypairState{}, fmt.Errorf("reading %s: unexpected stat output %q", p, lines[0])
	}
	s := KeypairState{Exists: true, Mode: strings.Repeat("0", max(0, 4-len(f[0]))) + f[0], Owner: f[1], Group: f[2]}
	// The type and size come from the key ssh-keygen derives from the
	// private key, never from Path.pub, which may be another key's.
	if pub, _, _, _, err := gossh.ParseAuthorizedKey([]byte(lines[1])); err == nil {
		s.Public = strings.TrimSpace(string(gossh.MarshalAuthorizedKey(pub)))
		s.Type, s.Bits = keyKind(pub)
	}
	s.PubFile = strings.Join(strings.Fields(lines[2]), " ")
	return s, nil
}

// ApplyKeypair makes the host's keypair k. A key of the right kind is kept,
// with its mode, owner and group set and Path.pub written again; a missing
// one, or one of another kind, is made anew with ssh-keygen on the host. A
// file there that isn't a key is left alone, with an error.
func ApplyKeypair(ctx context.Context, r modules.Runner, k Keypair) (KeypairState, error) {
	if err := k.Validate(); err != nil {
		return KeypairState{}, err
	}
	k = k.WithDefaults()
	have, err := ReadKeypair(ctx, r, k.Path)
	if err != nil {
		return KeypairState{}, err
	}
	if have.Exists && have.Type == "" {
		return KeypairState{}, fmt.Errorf("%s is there but isn't an unencrypted SSH key ssh-keygen can read; move it away, or point path somewhere else", k.Path)
	}
	gen := `cp -- "$p" "$d/key"`
	if have.Type != k.Type || have.Bits != k.Bits {
		gen = fmt.Sprintf(`ssh-keygen -q -t %s -b %d -N '' -C %s -f "$d/key" >/dev/null`, k.Type, k.Bits, ssh.Quote(k.Comment))
	}
	// Everything is made in a directory only its owner can read, then moved
	// into place, so the private key is never readable by others.
	script := fmt.Sprintf(`set -e
umask 077
p=%[1]s
for f in "$p" "$p.pub"; do [ ! -L "$f" ] || { echo "$f is a link; a key goes in a regular file" >&2; exit 1; }; done
command -v ssh-keygen >/dev/null 2>&1 || { echo "ssh-keygen isn't installed; add a package step for openssh-client first" >&2; exit 1; }
mkdir -p -m 0700 -- "$(dirname -- "$p")"
d=$(mktemp -d "$(dirname -- "$p")/.conn3x.XXXXXX")
trap 'rm -rf -- "$d"' EXIT
%[2]s
pub=$(ssh-keygen -y -P '' -f "$d/key" | awk '{print $1, $2}')
printf '%%s\n' "$(printf '%%s %%s' "$pub" %[3]s | sed 's/ *$//')" > "$d/key.pub"
chmod 0600 "$d/key"
chmod 0644 "$d/key.pub"
tmp=$d/key.pub
%[4]s
chown --reference="$d/key.pub" -- "$d/key" 2>/dev/null || true
mv -f -- "$d/key.pub" "$p.pub"
tmp=$d/key
`+file.SyncFile+`
`+file.Replace+`
trap - EXIT
rm -rf -- "$d"
`+file.SyncDir+`
if command -v restorecon >/dev/null 2>&1; then restorecon -- "$p" "$p.pub" 2>/dev/null || true; fi`,
		ssh.Quote(k.Path), gen, ssh.Quote(k.Comment), file.Ownership(k.Owner, k.Group))
	res, err := r.Run(ctx, modules.GuardWrite(script, modules.Write{Owner: k.Owner, Group: k.Group, Path: k.Path}, modules.Parent(k.Path)), nil)
	if err := check(res, err); err != nil {
		return KeypairState{}, err
	}
	got, err := ReadKeypair(ctx, r, k.Path)
	if err != nil {
		return KeypairState{}, err
	}
	if !k.Matches(got) {
		return KeypairState{}, fmt.Errorf("%s doesn't hold the key asked for after writing it: found a %s key, mode %s, owner %s:%s", k.Path, cmp.Or(got.Type, "unreadable"), got.Mode, got.Owner, got.Group)
	}
	return got, nil
}

// DeleteKeypair removes the private and public key files.
func DeleteKeypair(ctx context.Context, r modules.Runner, p string) error {
	if err := file.Delete(ctx, r, p); err != nil {
		return err
	}
	return file.Delete(ctx, r, p+".pub")
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
