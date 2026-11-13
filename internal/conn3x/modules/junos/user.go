// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package junos

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// User is a local account, as junos_user owns it. Junos keeps a salted hash
// of the password, and Conn3x sends the hash, never the password, so a read
// can tell whether the account holds the step's.
type User struct {
	Name       string
	Class      string // required: Junos refuses an account without one
	WantSecret bool   // the step sets a password
	Secret     string // its hash, "$6$...", at apply only
	// SecretIs reports whether hash, as display set prints it, is the step's
	// password. Nil when a read can't tell, having no HMAC key: then any
	// password counts.
	SecretIs func(hash string) bool
	SSHKeys  []string // the account's whole set of public keys; nil leaves them alone
}

var (
	userName  = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$`)
	className = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	publicKey = regexp.MustCompile(`^(ssh-ed25519|ssh-rsa|ssh-dss|ecdsa-sha2-nistp(256|384|521)) [A-Za-z0-9+/=]+( [^"\\]*)?$`)
)

// Validate checks a User before anything reaches the device.
func (u User) Validate() error {
	if !userName.MatchString(u.Name) || u.Name == "root" {
		return fmt.Errorf("name %q is not an account name junos_user can own: letters, digits, _ . and -, up to 64, and not root", u.Name)
	}
	if !className.MatchString(u.Class) {
		return fmt.Errorf("class %q is not a login class, such as super-user, operator or read-only", u.Class)
	}
	for _, k := range u.SSHKeys {
		if !publicKey.MatchString(k) || strings.ContainsFunc(k, func(r rune) bool { return r < ' ' }) {
			return fmt.Errorf("ssh_keys: %q is not one public key line, such as \"ssh-ed25519 AAAA... alice@laptop\"", k)
		}
	}
	return nil
}

func (u User) path() string { return "system login user " + u.Name }

// keyStatement is the statement Junos files a public key under.
func keyStatement(key string) string {
	switch t, _, _ := strings.Cut(key, " "); {
	case t == "ssh-dss":
		return "ssh-dsa"
	case strings.HasPrefix(t, "ecdsa-"):
		return "ssh-ecdsa"
	default:
		return t
	}
}

func (u User) keyLine(key string) string {
	return "set " + u.path() + " authentication " + keyStatement(key) + ` "` + key + `"`
}

func (u User) secretPath() string { return u.path() + " authentication encrypted-password" }

// haveKeys are the account's key lines.
func (u User) haveKeys(lines []string) []string {
	var keys []string
	for _, l := range lines {
		for _, st := range []string{"ssh-ed25519", "ssh-rsa", "ssh-ecdsa", "ssh-dsa"} {
			if strings.HasPrefix(l, "set "+u.path()+" authentication "+st+" ") {
				keys = append(keys, l)
			}
		}
	}
	return keys
}

// secret is the hash in an encrypted-password line, without its quotes.
func secret(line string) string {
	f := strings.Fields(line)
	return strings.Trim(f[len(f)-1], `"`)
}

func (u User) secretOK(line string) bool {
	if line == "" {
		return false
	}
	return u.SecretIs == nil || u.SecretIs(secret(line))
}

// InSync reports whether the account matches, its password included.
func (u User) InSync(config string) bool { return u.Commands(config) == nil }

// Commands are what makes the device's account match, or nil. The class and
// the password are leaves, deleted before another value is set.
func (u User) Commands(config string) []string {
	lines := SetLines(config)
	cmds := Leaf{Path: u.path() + " class", Value: u.Class}.Commands(config)
	if u.WantSecret {
		if got := haveLeaf(lines, u.secretPath()); !u.secretOK(got) {
			if got != "" {
				cmds = append(cmds, "delete "+u.secretPath())
			}
			cmds = append(cmds, "set "+u.secretPath()+` "`+u.Secret+`"`)
		}
	}
	if u.SSHKeys != nil {
		have := u.haveKeys(lines)
		var want []string
		for _, k := range u.SSHKeys {
			want = append(want, u.keyLine(k))
		}
		for _, h := range have {
			if !slices.Contains(want, h) {
				cmds = append(cmds, "delete "+strings.TrimPrefix(h, "set "))
			}
		}
		for _, w := range want {
			if !slices.Contains(have, w) {
				cmds = append(cmds, w)
			}
		}
	}
	return cmds
}

// RemoveCommands delete the account, when it's there.
func (u User) RemoveCommands(config string) []string {
	if !slices.ContainsFunc(SetLines(config), func(l string) bool { return under(l, u.path()) }) {
		return nil
	}
	return []string{"delete " + u.path()}
}

// Guard refuses what would lock out login, the account Conn3x uses: a class
// other than super-user could stop it configuring the device.
func (u User) Guard(login string) error {
	if u.Name == login && u.Class != "super-user" {
		return fmt.Errorf("Conn3x logs in as %s, and class %s could stop it configuring the device; keep it super-user", login, u.Class)
	}
	return nil
}
