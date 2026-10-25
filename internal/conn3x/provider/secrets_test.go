// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHMACKeyFromEnv(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("CONN3X_HMAC_KEY", strings.Repeat("k", 32))
	key, err := hmacKey()
	if err != nil || string(key) != strings.Repeat("k", 32) {
		t.Fatalf("hmacKey() = %q, %v", key, err)
	}
}

func TestHMACKeyTooShort(t *testing.T) {
	t.Setenv("CONN3X_HMAC_KEY", "short")
	if _, err := hmacKey(); err == nil || !strings.Contains(err.Error(), "32") {
		t.Fatalf("want an error about 32 bytes, got %v", err)
	}
}

func TestHMACKeyFileCreated(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("CONN3X_HMAC_KEY", "")
	first, err := hmacKey()
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 32 {
		t.Fatalf("key is %d bytes, want 32", len(first))
	}
	path := filepath.Join(dir, "conn3x", "hmac.key")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode %v, want 0600", info.Mode().Perm())
	}
	again, err := hmacKey()
	if err != nil || !bytes.Equal(first, again) {
		t.Fatalf("second call returned a different key: %v", err)
	}
}

func TestContentHMACFormat(t *testing.T) {
	a, b := []byte(strings.Repeat("a", 32)), []byte(strings.Repeat("b", 32))
	got := contentHMAC(a, "secret")
	if !strings.HasPrefix(got, "hmac-sha256:"+keyID(a)+":") || len(keyID(a)) != 8 {
		t.Fatalf("contentHMAC = %q", got)
	}
	if got != contentHMAC(a, "secret") {
		t.Fatal("not stable")
	}
	if got == contentHMAC(b, "secret") || got == contentHMAC(a, "other") {
		t.Fatal("did not change with the key or the content")
	}
	if strings.Contains(got, "secret") {
		t.Fatal("leaks the content")
	}
}

func TestCheckHMACKeyMismatch(t *testing.T) {
	a, b := []byte(strings.Repeat("a", 32)), []byte(strings.Repeat("b", 32))
	if err := checkHMACKey(contentHMAC(a, "x"), a); err != nil {
		t.Fatalf("same key: %v", err)
	}
	err := checkHMACKey(contentHMAC(a, "x"), b)
	if err == nil {
		t.Fatal("different key accepted")
	}
	for _, want := range []string{keyID(a), keyID(b), "CONN3X_HMAC_KEY", "hmac.key"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q doesn't mention %q", err, want)
		}
	}
}
