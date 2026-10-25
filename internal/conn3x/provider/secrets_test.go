// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestHMACKeyFromEnv(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("CONN3X_HMAC_KEY", strings.Repeat("k", 32))
	key, err := hmacKey(true)
	if err != nil || string(key) != strings.Repeat("k", 32) {
		t.Fatalf("hmacKey() = %q, %v", key, err)
	}
}

func TestHMACKeyTooShort(t *testing.T) {
	t.Setenv("CONN3X_HMAC_KEY", "short")
	if _, err := hmacKey(true); err == nil || !strings.Contains(err.Error(), "32") {
		t.Fatalf("want an error about 32 bytes, got %v", err)
	}
}

func TestHMACKeyFileCreated(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("CONN3X_HMAC_KEY", "")
	first, err := hmacKey(true)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 64 {
		t.Fatalf("key is %d bytes, want 64 hex characters", len(first))
	}
	path := filepath.Join(dir, "conn3x", "hmac.key")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode %v, want 0600", info.Mode().Perm())
	}
	again, err := hmacKey(true)
	if err != nil || !bytes.Equal(first, again) {
		t.Fatalf("second call returned a different key: %v", err)
	}
}

func TestContentHMACFormat(t *testing.T) {
	a, b := []byte(strings.Repeat("a", 32)), []byte(strings.Repeat("b", 32))
	got := contentHMAC(a, "/p", "secret")
	if !strings.HasPrefix(got, "hmac-sha256:"+keyID(a)+":") || len(keyID(a)) != 8 {
		t.Fatalf("contentHMAC = %q", got)
	}
	if got != contentHMAC(a, "/p", "secret") {
		t.Fatal("not stable")
	}
	if got == contentHMAC(b, "/p", "secret") || got == contentHMAC(a, "/p", "other") {
		t.Fatal("did not change with the key or the content")
	}
	if strings.Contains(got, "secret") {
		t.Fatal("leaks the content")
	}
}

func TestCheckHMACKeyMismatch(t *testing.T) {
	a, b := []byte(strings.Repeat("a", 32)), []byte(strings.Repeat("b", 32))
	if err := checkHMACKey(contentHMAC(a, "/p", "x"), a); err != nil {
		t.Fatalf("same key: %v", err)
	}
	err := checkHMACKey(contentHMAC(a, "/p", "x"), b)
	if err == nil {
		t.Fatal("different key accepted")
	}
	for _, want := range []string{keyID(a), keyID(b), "CONN3X_HMAC_KEY", "hmac.key"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q doesn't mention %q", err, want)
		}
	}
}

func TestHMACKeyFileWorksAsEnv(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("CONN3X_HMAC_KEY", "")
	fromFile, err := hmacKey(true)
	if err != nil {
		t.Fatal(err)
	}
	path, _ := hmacKeyPath()
	data, _ := os.ReadFile(path)
	t.Setenv("CONN3X_HMAC_KEY", strings.TrimSpace(string(data)))
	fromEnv, err := hmacKey(true)
	if err != nil || keyID(fromEnv) != keyID(fromFile) {
		t.Fatalf("CONN3X_HMAC_KEY=$(cat hmac.key) gives key %s, file gives %s (%v)", keyID(fromEnv), keyID(fromFile), err)
	}
}

func TestHMACKeyFileTrimsNewline(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("CONN3X_HMAC_KEY", "")
	_ = os.MkdirAll(filepath.Join(dir, "conn3x"), 0o700)
	k := strings.Repeat("ab", 32)
	_ = os.WriteFile(filepath.Join(dir, "conn3x", "hmac.key"), []byte(k+"\n"), 0o600)
	got, err := hmacKey(false)
	if err != nil || string(got) != k {
		t.Fatalf("hmacKey = %q, %v", got, err)
	}
}

func TestHMACKeyConcurrentFirstUse(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("CONN3X_HMAC_KEY", "")
	var wg sync.WaitGroup
	keys := make([][]byte, 20)
	errs := make([]error, 20)
	for i := range keys {
		wg.Add(1)
		go func() { defer wg.Done(); keys[i], errs[i] = hmacKey(true) }()
	}
	wg.Wait()
	for i := range keys {
		if errs[i] != nil || !bytes.Equal(keys[i], keys[0]) {
			t.Fatalf("call %d: %q, %v", i, keys[i], errs[i])
		}
	}
}

func TestHMACKeyNotCreatedWhenAskedNotTo(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("CONN3X_HMAC_KEY", "")
	if _, err := hmacKey(false); err == nil || !strings.Contains(err.Error(), "CONN3X_HMAC_KEY") {
		t.Fatalf("want an error saying how to supply the key, got %v", err)
	}
	if path, _ := hmacKeyPath(); fileExists(path) {
		t.Fatal("created a key file")
	}
}

func TestContentHMACDependsOnPath(t *testing.T) {
	k := []byte(strings.Repeat("a", 32))
	if contentHMAC(k, "/a", "same") == contentHMAC(k, "/b", "same") {
		t.Fatal("the same secret in two files gives the same HMAC")
	}
}

func TestCheckHMACKeyExplainsRecovery(t *testing.T) {
	a, b := []byte(strings.Repeat("a", 32)), []byte(strings.Repeat("b", 32))
	err := checkHMACKey(contentHMAC(a, "/p", "x"), b)
	if err == nil || !strings.Contains(err.Error(), "state rm") {
		t.Fatalf("error should say how to recover if the key is lost: %v", err)
	}
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }
