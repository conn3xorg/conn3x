// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package secrets

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
		"MAC doesn't match":       strings.Replace(src, "plain_unencrypted: visible", "plain_unencrypted: changed", 1),
		"doesn't decrypt":         strings.Replace(src, "db_password:", "db_passwords:", 1),
		"no sops block":           "a: 1\n",
		"not YAML or JSON":        "a: [\n",
		"a mapping at the top":    "- a\n- b\n",
		"reading the sops block":  "a: 1\nsops: [1]\n",
		"by comment":              "a: 1\nsops:\n  encrypted_comment_regex: secret\n",
		"no age recipient":        "a: 1\nsops:\n  version: 3.13.3\n",
		"isn't base64":            strings.Replace(src, "data:uhVp67886g==", "data:!!", 1),
		"YAML alias":              strings.Replace(src, "plain_unencrypted: visible", "plain_unencrypted: &v visible\nalias_unencrypted: *v", 1),
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

func TestIdentitiesFromConfigDir(t *testing.T) {
	cfg := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", cfg)
	t.Setenv("SOPS_AGE_KEY", "")
	t.Setenv("SOPS_AGE_KEY_FILE", filepath.Join(cfg, "missing.txt"))
	if got, err := Identities(); err != nil || len(got) != 0 {
		t.Fatalf("with no keys: %d identities, %v", len(got), err)
	}
	if err := os.MkdirAll(filepath.Join(cfg, "sops", "age"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfg, "sops", "age", "keys.txt"), read(t, "test-key.txt"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := Identities(); err != nil || len(got) != 1 {
		t.Fatalf("got %d identities, %v", len(got), err)
	}
	// A key that won't parse is an error, not a key passed over.
	t.Setenv("SOPS_AGE_KEY", "AGE-SECRET-KEY-NOPE")
	if _, err := Identities(); err == nil || !strings.Contains(err.Error(), "reading age keys from SOPS_AGE_KEY") {
		t.Errorf("a bad SOPS_AGE_KEY: %v", err)
	}
	t.Setenv("SOPS_AGE_KEY", "")
	t.Setenv("SOPS_AGE_KEY_FILE", filepath.Join("testdata", "README.md"))
	if _, err := Identities(); err == nil || !strings.Contains(err.Error(), "README.md") {
		t.Errorf("a bad key file: %v", err)
	}
	t.Setenv("SOPS_AGE_KEY_FILE", cfg)
	if _, err := Identities(); err == nil {
		t.Error("read a directory as a key file")
	}
}

func TestReadFile(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("SOPS_AGE_KEY", "")
	t.Setenv("SOPS_AGE_KEY_FILE", filepath.Join("testdata", "test-key.txt"))
	// A byte order mark, as some Windows editors write, is ignored.
	p := filepath.Join(t.TempDir(), "secrets.sops.yaml")
	if err := os.WriteFile(p, append([]byte("\xef\xbb\xbf"), read(t, "secrets.sops.yaml")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := ReadFile(p); err != nil || got["db_password"] != "hunter2" {
		t.Fatalf("got %v, %v", got, err)
	}
	if _, err := ReadFile(filepath.Join("testdata", "README.md")); err == nil || !strings.HasPrefix(err.Error(), filepath.Join("testdata", "README.md")+": ") {
		t.Errorf("not a SOPS file: %v", err)
	}
	if _, err := ReadFile(filepath.Join("testdata", "missing.yaml")); err == nil {
		t.Error("read a missing file")
	}
	t.Setenv("SOPS_AGE_KEY", "AGE-SECRET-KEY-NOPE")
	if _, err := ReadFile(p); err == nil || !strings.Contains(err.Error(), "SOPS_AGE_KEY") {
		t.Errorf("a bad key: %v", err)
	}
}

// sops hashes each value as its recorded type prints, so both directions
// have to agree with it.
func TestTypedAndToBytes(t *testing.T) {
	for _, c := range []struct{ plain, typ, bytes string }{
		{"x", "str", "x"},
		{"42", "int", "42"},
		{"1.50", "float", "1.5"},
		{"true", "bool", "True"},
		{"False", "bool", "False"},
		{"2026-11-13T00:52:36Z", "time", "2026-11-13T00:52:36Z"},
	} {
		v, err := typed(c.plain, c.typ)
		if err != nil {
			t.Errorf("typed(%q, %s): %v", c.plain, c.typ, err)
			continue
		}
		if b, err := toBytes(v); err != nil || string(b) != c.bytes {
			t.Errorf("toBytes(%v) = %q, %v; want %q", v, b, err, c.bytes)
		}
	}
	for _, c := range [][2]string{{"x", "int"}, {"x", "float"}, {"maybe", "bool"}, {"yesterday", "time"}, {"x", "blob"}} {
		if _, err := typed(c[0], c[1]); err == nil {
			t.Errorf("typed(%q, %s) took it", c[0], c[1])
		}
	}
	if _, err := toBytes([]any{1}); err == nil {
		t.Error("toBytes took a list")
	}
	if _, err := toBytes(time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)); err == nil {
		t.Error("toBytes took a year past 9999")
	}
}

func TestEncrypted(t *testing.T) {
	for _, c := range []struct {
		meta metadata
		path string
		want bool
	}{
		{metadata{}, "a", true},
		{metadata{UnencryptedSuffix: "_plain"}, "a_plain:b", false},
		{metadata{EncryptedSuffix: "_secret"}, "a", false},
		{metadata{EncryptedSuffix: "_secret"}, "a_secret:b", true},
		{metadata{UnencryptedRegex: "^public"}, "public_key", false},
		{metadata{UnencryptedRegex: "^public"}, "private_key", true},
		{metadata{EncryptedRegex: "^(password|token)$"}, "db:password", true},
		{metadata{EncryptedRegex: "^(password|token)$"}, "db:host", false},
	} {
		r := reader{meta: &c.meta}
		if got := r.encrypted(strings.Split(c.path, ":")); got != c.want {
			t.Errorf("%+v %s: %v, want %v", c.meta, c.path, got, c.want)
		}
	}
}
