// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Write-only content never reaches state. State keeps an HMAC of it instead,
// keyed by a secret that also stays out of state, so a copy of the state
// can't be used to guess the content, and drift on the host still shows.

const hmacKeyEnv = "CONN3X_HMAC_KEY"

// hmacKey returns the key from CONN3X_HMAC_KEY, or from a key file in the
// user's config directory, which it creates on first use.
func hmacKey() ([]byte, error) {
	if env := os.Getenv(hmacKeyEnv); env != "" {
		if len(env) < 32 {
			return nil, fmt.Errorf("%s must be at least 32 bytes long", hmacKeyEnv)
		}
		return []byte(env), nil
	}
	path, err := hmacKeyPath()
	if err != nil {
		return nil, err
	}
	key, err := os.ReadFile(path)
	if err == nil {
		if len(key) < 32 {
			return nil, fmt.Errorf("%s must hold at least 32 bytes", path)
		}
		return key, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	key = make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	// O_EXCL: if another process created the file first, use its key.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return hmacKey()
	}
	if err != nil {
		return nil, err
	}
	if _, err := f.Write(key); err != nil {
		f.Close()
		return nil, err
	}
	return key, f.Close()
}

func hmacKeyPath() (string, error) {
	dir := os.Getenv("XDG_CONFIG_HOME")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		dir = filepath.Join(home, ".config")
	}
	return filepath.Join(dir, "conn3x", "hmac.key"), nil
}

// keyID names a key without revealing it, so state can say which key it used.
func keyID(key []byte) string {
	sum := sha256.Sum256(key)
	return hex.EncodeToString(sum[:4])
}

// contentHMAC is what state records for write-only content.
func contentHMAC(key []byte, content string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(content))
	return "hmac-sha256:" + keyID(key) + ":" + hex.EncodeToString(mac.Sum(nil))
}

// checkHMACKey reports when state was hashed with a different key, which
// would otherwise look like every secret had drifted.
func checkHMACKey(stored string, key []byte) error {
	parts := strings.SplitN(stored, ":", 3)
	if len(parts) != 3 || parts[0] != "hmac-sha256" {
		return fmt.Errorf("content_hmac %q is not in the form hmac-sha256:<key id>:<mac>", stored)
	}
	if parts[1] == keyID(key) {
		return nil
	}
	path, _ := hmacKeyPath()
	return fmt.Errorf("this state's write-only content was hashed with key %s, but the key here is %s. "+
		"Use the same key everywhere you run Conn3x: set %s, or copy %s from the machine that applied it",
		parts[1], keyID(key), hmacKeyEnv, path)
}
