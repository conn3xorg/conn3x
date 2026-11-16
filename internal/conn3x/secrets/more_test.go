// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package secrets

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"regexp"
	"strings"
	"testing"

	"filippo.io/age"
	"filippo.io/age/armor"
	"gopkg.in/yaml.v3"
)

// enc encrypts plain as sops does, with the fixture's data key, under the
// path aad and recorded as typ.
func enc(t *testing.T, plain, aad, typ string) string {
	t.Helper()
	var f struct {
		Sops metadata `yaml:"sops"`
	}
	if err := yaml.Unmarshal(read(t, "secrets.sops.yaml"), &f); err != nil {
		t.Fatal(err)
	}
	key, err := dataKey(&f.Sops, ids(t, "test-key.txt"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCMWithNonceSize(block, 32)
	iv := bytes.Repeat([]byte{7}, 32)
	sealed := gcm.Seal(nil, iv, []byte(plain), []byte(aad))
	b := base64.StdEncoding.EncodeToString
	n := len(sealed) - 16
	return "ENC[AES256_GCM,data:" + b(sealed[:n]) + ",iv:" + b(iv) + ",tag:" + b(sealed[n:]) + ",type:" + typ + "]"
}

// An encrypted value whose recorded type doesn't fit it, or isn't one sops
// writes, is an error naming the key.
func TestDecryptBadTypes(t *testing.T) {
	src := string(read(t, "secrets.sops.yaml"))
	key := ids(t, "test-key.txt")
	port := regexp.MustCompile(`(?m)^port: .*$`)
	for want, value := range map[string]string{
		`port: strconv.Atoi: parsing "x"`:           enc(t, "x", "port:", "int"),
		`port: its encrypted value has type "blob"`: enc(t, "5432", "port:", "blob"),
	} {
		_, err := Decrypt([]byte(port.ReplaceAllString(src, "port: "+value)), key)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("want %q, got %v", want, err)
		}
	}
	// bytes reads as it is; sops hashes it as it does the int it replaces.
	got, err := Decrypt([]byte(port.ReplaceAllString(src, "port: "+enc(t, "5432", "port:", "bytes"))), key)
	if err != nil || got["port"] != "5432" {
		t.Errorf("bytes: %v, %v", got["port"], err)
	}
}

func TestDecryptPlainValues(t *testing.T) {
	src := string(read(t, "secrets.sops.yaml"))
	key := ids(t, "test-key.txt")
	// sops neither hashes nor keeps a null, so the MAC still holds.
	got, err := Decrypt([]byte(strings.Replace(src, "count_unencrypted: 7", "count_unencrypted: 7\nnull_unencrypted: null", 1)), key)
	if _, ok := got["null_unencrypted"]; err != nil || ok || got["count_unencrypted"] != "7" {
		t.Errorf("null: %v, %v", got, err)
	}
	for want, line := range map[string]string{
		"big_unencrypted: an unencrypted value of type uint64": "big_unencrypted: 18446744073709551615",
		"cannot decode !!str `x` as a !!int":                   "bad_unencrypted: !!int x",
	} {
		if _, err := Decrypt([]byte(strings.Replace(src, "count_unencrypted: 7", "count_unencrypted: 7\n"+line, 1)), key); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("want %q, got %v", want, err)
		}
	}
	// The MAC is encrypted under the last-modified stamp.
	for want, file := range map[string]string{
		"reading its MAC: isn't encrypted": regexp.MustCompile(`(?m)^    mac: .*$`).ReplaceAllString(src, "    mac: x"),
		"reading its MAC: doesn't decrypt": strings.Replace(src, `"2026-11-13T00:52:36Z"`, `"yesterday"`, 1),
		"unwrapping its data key":          regexp.MustCompile(`(?s)-----BEGIN AGE.*?-----END AGE ENCRYPTED FILE-----`).ReplaceAllString(src, "-----BEGIN AGE ENCRYPTED FILE-----\n            AAAA\n            -----END AGE ENCRYPTED FILE-----"),
		"its data key is 16 bytes, not 32": withDataKey(t, src, make([]byte, 16)),
	} {
		if _, err := Decrypt([]byte(file), key); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("want %q, got %v", want, err)
		}
	}
}

// withDataKey replaces the file's wrapped data key with key, wrapped to
// the test identity.
func withDataKey(t *testing.T, src string, key []byte) string {
	t.Helper()
	var buf bytes.Buffer
	a := armor.NewWriter(&buf)
	w, err := age.Encrypt(a, ids(t, "test-key.txt")[0].(*age.X25519Identity).Recipient())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write(key)
	_ = w.Close()
	_ = a.Close()
	wrapped := strings.ReplaceAll(strings.TrimSpace(buf.String()), "\n", "\n            ")
	return regexp.MustCompile(`(?s)-----BEGIN AGE.*?-----END AGE ENCRYPTED FILE-----`).ReplaceAllLiteralString(src, wrapped)
}

// With no config directory to be found, only the environment's keys count.
func TestIdentitiesWithoutConfigDir(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", "")
	t.Setenv("SOPS_AGE_KEY_FILE", "")
	t.Setenv("SOPS_AGE_KEY", string(read(t, "test-key.txt")))
	if got, err := Identities(); err != nil || len(got) != 1 {
		t.Errorf("got %d identities, %v", len(got), err)
	}
}
