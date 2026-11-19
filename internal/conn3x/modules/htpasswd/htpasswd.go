// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package htpasswd edits one user's line in an Apache-style password file,
// as htpasswd, Apache and nginx's auth_basic read it: name:hash.
package htpasswd

import (
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// MaxPassword is bcrypt's limit: it reads no more than 72 bytes.
const MaxPassword = 72

// ValidateName checks a user name before it goes in a file.
func ValidateName(name string) error {
	switch {
	case name == "":
		return errors.New("name is empty")
	case strings.ContainsAny(name, ":\r\n\x00"):
		return fmt.Errorf("name %q has a :, a line break or NUL, which would break the file's name:hash lines", name)
	}
	return nil
}

// ValidatePassword checks a password before it's hashed.
func ValidatePassword(pw string) error {
	switch {
	case pw == "":
		return errors.New("the password is empty")
	case len(pw) > MaxPassword:
		return fmt.Errorf("the password is %d bytes, and bcrypt reads only the first %d", len(pw), MaxPassword)
	}
	return nil
}

// Hash hashes pw with bcrypt, as htpasswd -B writes it, with the $2y$
// prefix Apache's own tools use.
func Hash(pw string) (string, error) {
	if err := ValidatePassword(pw); err != nil {
		return "", err
	}
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return "$2y$" + strings.TrimPrefix(string(h), "$2a$"), nil
}

// Find returns the hash on name's line, if the content has one.
func Find(content, name string) (string, bool) {
	for _, l := range strings.Split(content, "\n") {
		if n, hash, ok := strings.Cut(strings.TrimSuffix(l, "\r"), ":"); ok && n == name {
			return hash, true
		}
	}
	return "", false
}

// Set gives name the hash: its line is replaced where it is, or added at
// the end. Every other line is left as it was.
func Set(content, name, hash string) string {
	line := name + ":" + hash
	lines := splitLines(content)
	for i, l := range lines {
		if n, _, ok := strings.Cut(strings.TrimSuffix(l, "\r"), ":"); ok && n == name {
			lines[i] = line
			return joinLines(lines)
		}
	}
	return joinLines(append(lines, line))
}

// Rename gives old's first line to name, with hash, where it is, and takes
// out any other line for old. If name already has a line, old's are taken
// out and name's is set. If old has no line, it's Set.
func Rename(content, old, name, hash string) string {
	if _, ok := Find(content, name); ok {
		return Set(Remove(content, old), name, hash)
	}
	lines := splitLines(content)
	for i, l := range lines {
		if n, _, ok := strings.Cut(strings.TrimSuffix(l, "\r"), ":"); ok && n == old {
			lines[i] = name + ":" + hash
			// Any other line for old, from a hand edit, goes too, or the
			// old name would still log in with that line's hash.
			return Remove(joinLines(lines), old)
		}
	}
	return Set(content, name, hash)
}

// Remove takes name's line out.
func Remove(content, name string) string {
	var kept []string
	for _, l := range splitLines(content) {
		if n, _, ok := strings.Cut(strings.TrimSuffix(l, "\r"), ":"); !ok || n != name {
			kept = append(kept, l)
		}
	}
	return joinLines(kept)
}

func splitLines(content string) []string {
	if content == "" {
		return nil
	}
	return strings.Split(strings.TrimSuffix(content, "\n"), "\n")
}

func joinLines(lines []string) string {
	if len(lines) == 0 {
		return ""
	}
	return strings.Join(lines, "\n") + "\n"
}
