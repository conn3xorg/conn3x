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
	"sync"
)

// Write-only content never reaches state. State keeps an HMAC of it instead,
// keyed by a secret that also stays out of state, so a copy of the state
// can't be used to guess the content, and drift on the host still shows.

const hmacKeyEnv = "CONN3X_HMAC_KEY"

// keyFileMu serialises first use within one process; the hard link below
// covers other processes.
var keyFileMu sync.Mutex

// hmacKey returns the key from CONN3X_HMAC_KEY, or from a key file in the
// user's config directory. With create, a missing key file is made: 64 hex
// characters, so its content also works as CONN3X_HMAC_KEY.
func hmacKey(create bool) ([]byte, error) {
	if env := os.Getenv(hmacKeyEnv); env != "" {
		if len(env) < 32 {
			return nil, fmt.Errorf("%s must be at least 32 bytes long; generate one with: openssl rand -hex 32", hmacKeyEnv)
		}
		return []byte(env), nil
	}
	path, err := hmacKeyPath()
	if err != nil {
		return nil, err
	}
	keyFileMu.Lock()
	defer keyFileMu.Unlock()
	key, err := readKeyFile(path)
	if err == nil || !errors.Is(err, fs.ErrNotExist) {
		return key, err
	}
	if !create {
		return nil, fmt.Errorf("no HMAC key here: set %s, or copy %s from the machine that applied this state", hmacKeyEnv, path)
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	key = []byte(hex.EncodeToString(raw))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	// Write the whole key under a temporary name, then link it into place,
	// so no reader ever sees a half-written file. If another process won,
	// use its key.
	tmp, err := os.CreateTemp(filepath.Dir(path), ".hmac.key-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(key, '\n')); err != nil {
		tmp.Close()
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}
	if err := os.Link(tmp.Name(), path); errors.Is(err, fs.ErrExist) {
		return readKeyFile(path)
	} else if err != nil {
		return nil, err
	}
	return key, nil
}

func readKeyFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	key := []byte(strings.TrimSpace(string(data)))
	if len(key) < 32 {
		return nil, fmt.Errorf("%s must hold at least 32 bytes", path)
	}
	return key, nil
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

// contentHMAC is what state records for write-only content. The path is part
// of it, so the same secret in two files doesn't show as the same value.
func contentHMAC(key []byte, path, content string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(path))
	mac.Write([]byte{0})
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
		"Use the same key everywhere you run Conn3x: set %s, or copy %s from the machine that applied it. "+
		"If that key is lost, run conn3x state rm on this resource and apply again to rewrite the file with the key here",
		parts[1], keyID(key), hmacKeyEnv, path)
}
