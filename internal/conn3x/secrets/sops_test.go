// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package secrets

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
)

func ids(t *testing.T, file string) []age.Identity {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", file))
	if err != nil {
		t.Fatal(err)
	}
	out, err := age.ParseIdentities(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func read(t *testing.T, file string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", file))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// The fixtures come from the real sops, so these check Conn3x reads its
// files: every value type, unencrypted keys, nesting, lists, and the MAC.
func TestDecryptSOPSFiles(t *testing.T) {
	got, err := Decrypt(read(t, "secrets.sops.yaml"), ids(t, "test-key.txt"))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"db_password": "hunter2", "api_token": "abc123", "port": "5432", "ratio": "1.5", "enabled": "true", "empty": "",
		"plain_unencrypted": "visible", "count_unencrypted": "7", "nested.inner": "deep", "list.0": "one", "list.1": "two",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	if len(got) != len(want) {
		t.Errorf("got %d values, want %d: %v", len(got), len(want), got)
	}

	js, err := Decrypt(read(t, "secrets.sops.json"), ids(t, "test-key.txt"))
	if err != nil || js["db_password"] != "hunter2" || js["port"] != "5432" {
		t.Errorf("json: %v, %v", js, err)
	}
	suffix, err := Decrypt(read(t, "suffix.sops.yaml"), ids(t, "test-key.txt"))
	if err != nil || suffix["a"] != "1" || suffix["b_secret"] != "two" {
		t.Errorf("encrypted_suffix and mac_only_encrypted: %v, %v", suffix, err)
	}
}

func TestDecryptRefuses(t *testing.T) {
	src := string(read(t, "secrets.sops.yaml"))
	key := ids(t, "test-key.txt")
	for want, file := range map[string]string{
		"isn't encrypted, though": strings.Replace(src, "db_password: ENC[", "db_password: x\nold: ENC[", 1),
		"MAC doesn't match":        strings.Replace(src, "plain_unencrypted: visible", "plain_unencrypted: changed", 1),
		"doesn't decrypt":          strings.Replace(src, "db_password:", "db_passwords:", 1),
		"no sops block":            "a: 1\n",
	} {
		if _, err := Decrypt([]byte(file), key); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("want %q, got %v", want, err)
		}
	}
	if _, err := Decrypt([]byte(src), ids(t, "other-key.txt")); err == nil || !strings.Contains(err.Error(), "none of your age keys") {
		t.Errorf("wrong key: %v", err)
	}
	if _, err := Decrypt([]byte(src), nil); err == nil || !strings.Contains(err.Error(), "no age key found") {
		t.Errorf("no key: %v", err)
	}
	if strings.Contains(src, "hunter2") {
		t.Fatal("the fixture holds the plaintext")
	}
}

func TestIdentitiesFromEnv(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("SOPS_AGE_KEY", string(read(t, "test-key.txt")))
	t.Setenv("SOPS_AGE_KEY_FILE", filepath.Join("testdata", "other-key.txt"))
	got, err := Identities()
	if err != nil || len(got) != 2 {
		t.Fatalf("got %d identities, %v", len(got), err)
	}
}
