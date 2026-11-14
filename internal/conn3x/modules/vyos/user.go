// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package vyos

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/opentofu/opentofu/internal/conn3x/modules/setcfg"
)

// User is a local account, as vyos_user owns it. VyOS keeps a crypt hash
// of the password, and Conn3x sends the hash, never the password, so a read
// can tell whether the account holds the step's.
type User struct {
	Name       string
	FullName   *string // nil leaves it alone
	WantSecret bool    // the step sets a password
	Secret     string  // its hash, "$6$...", at apply only
	// SecretIs reports whether hash is the step's password. Nil when a read
	// can't tell, having no HMAC key: then any password counts.
	SecretIs func(hash string) bool
	SSHKeys  []string // the account's whole set of public keys; nil leaves them alone
}

var (
	userName  = regexp.MustCompile(`^[a-z_][a-z0-9_.-]{0,31}$`)
	publicKey = regexp.MustCompile(`^(ssh-ed25519|ssh-rsa|ssh-dss|ecdsa-sha2-nistp(256|384|521)) ([A-Za-z0-9+/=]+)( [^"'\\]*)?$`)
	keyLabel  = regexp.MustCompile(`^[A-Za-z0-9@._-]{1,64}$`)
)

// Validate checks a User before anything reaches the router.
func (u User) Validate() error {
	if !userName.MatchString(u.Name) || u.Name == "root" {
		return fmt.Errorf("name %q is not an account name vyos_user can own: lower-case letters, digits, _ . and -, up to 32, starting with a letter or _, and not root", u.Name)
	}
	if u.FullName != nil {
		if strings.ContainsAny(*u.FullName, `"'\`) {
			return fmt.Errorf("full_name must not hold a quote or backslash")
		}
		if err := setcfg.CheckText(*u.FullName, "full_name"); err != nil {
			return err
		}
	}
	for _, k := range u.SSHKeys {
		if !publicKey.MatchString(k) {
			return fmt.Errorf("ssh_keys: %q is not one public key line, such as \"ssh-ed25519 AAAA... alice@laptop\"", k)
		}
	}
	return nil
}

func (u User) path() string { return "system login user " + u.Name }

func (u User) secretPath() string { return u.path() + " authentication encrypted-password" }

func (u User) keysPath() string { return u.path() + " authentication public-keys" }

// key is one public key on the router: its label, type and base64 body.
type key struct{ label, typ, body string }

// haveKeys reads the account's keys from set lines: each label has a key
// line and a type line.
func (u User) haveKeys(lines []string) []key {
	byLabel := map[string]*key{}
	var order []string
	for _, l := range lines {
		rest, ok := strings.CutPrefix(l, "set "+u.keysPath()+" ")
		if !ok {
			continue
		}
		f := strings.Fields(rest)
		if len(f) != 3 {
			continue
		}
		k := byLabel[f[0]]
		if k == nil {
			k = &key{label: f[0]}
			byLabel[f[0]] = k
			order = append(order, f[0])
		}
		switch f[1] {
		case "key":
			k.body = f[2]
		case "type":
			k.typ = f[2]
		}
	}
	keys := make([]key, 0, len(order))
	for _, l := range order {
		keys = append(keys, *byLabel[l])
	}
	return keys
}

// wantKeys are the step's keys, each labelled by its comment when that
// makes a label, or by a hash of its body.
func (u User) wantKeys() []key {
	var keys []key
	for _, line := range u.SSHKeys {
		m := publicKey.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		label := strings.TrimSpace(m[4])
		if !keyLabel.MatchString(label) || slices.ContainsFunc(keys, func(k key) bool { return k.label == label }) {
			sum := sha256.Sum256([]byte(m[3]))
			label = "conn3x-" + hex.EncodeToString(sum[:4])
		}
		keys = append(keys, key{label: label, typ: m[1], body: m[3]})
	}
	return keys
}

// InSync reports whether the account matches, its password included.
func (u User) InSync(config string) bool { return u.Commands(config) == nil }

// Commands are what makes the router's account match, or nil. A key is the
// same key whatever its label, so only a missing body is added and only a
// body not wanted is deleted, label and all.
func (u User) Commands(config string) []string {
	lines := setcfg.SetLines(config)
	var cmds []string
	if u.FullName != nil {
		cmds = append(cmds, setcfg.Leaf{Path: u.path() + " full-name", Value: Normalize("'" + *u.FullName + "'")}.Commands(config)...)
	}
	if u.WantSecret {
		got := strings.Trim(strings.TrimPrefix(setcfg.HaveLeaf(lines, u.secretPath()), "set "+u.secretPath()+" "), `"'`)
		if got == "" || (u.SecretIs != nil && !u.SecretIs(got)) {
			cmds = append(cmds, "set "+u.secretPath()+` "`+u.Secret+`"`)
		}
	}
	if u.SSHKeys != nil {
		have, want := u.haveKeys(lines), u.wantKeys()
		same := func(a, b key) bool { return a.typ == b.typ && a.body == b.body }
		for _, h := range have {
			if !slices.ContainsFunc(want, func(w key) bool { return same(w, h) }) {
				cmds = append(cmds, "delete "+u.keysPath()+" "+h.label)
			}
		}
		for _, w := range want {
			if !slices.ContainsFunc(have, func(h key) bool { return same(w, h) }) {
				cmds = append(cmds, "set "+u.keysPath()+" "+w.label+" key "+w.body, "set "+u.keysPath()+" "+w.label+" type "+w.typ)
			}
		}
	}
	return cmds
}

// RemoveCommands delete the account, when it's there.
func (u User) RemoveCommands(config string) []string {
	if !slices.ContainsFunc(setcfg.SetLines(config), func(l string) bool { return setcfg.Under(l, u.path()) }) {
		return nil
	}
	return []string{"delete " + u.path()}
}

// Guard refuses what would lock out login, the account Conn3x uses: taking
// all its keys away.
func (u User) Guard(login string) error {
	if u.Name == login && u.SSHKeys != nil && len(u.SSHKeys) == 0 {
		return fmt.Errorf("Conn3x logs in as %s with a key, so it won't delete all that account's keys", login)
	}
	return nil
}
