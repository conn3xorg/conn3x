// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/zclconf/go-cty/cty"
	gossh "golang.org/x/crypto/ssh"

	"github.com/opentofu/opentofu/internal/providers"
)

func pemKey(t *testing.T, passphrase string) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var block *pem.Block
	if passphrase == "" {
		block, err = gossh.MarshalPrivateKey(priv, "")
	} else {
		block, err = gossh.MarshalPrivateKeyWithPassphrase(priv, "", []byte(passphrase))
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(block))
}

func TestProviderPrivateKeys(t *testing.T) {
	defer func() { providerKeys.keys = nil }()
	good := pemKey(t, "")
	cfg := func(keys ...string) cty.Value {
		vals := make([]cty.Value, len(keys))
		for i, k := range keys {
			vals[i] = cty.StringVal(k)
		}
		return cty.ObjectVal(map[string]cty.Value{"private_keys": cty.ListVal(vals).Mark("sensitive")})
	}
	p, _ := New()
	if resp := p.ConfigureProvider(ctx, providers.ConfigureProviderRequest{Config: cfg(good)}); resp.Diagnostics.HasErrors() {
		t.Fatal(resp.Diagnostics.Err())
	}
	_ = p.ConfigureProvider(ctx, providers.ConfigureProviderRequest{Config: cfg(good)})
	if got := currentProviderKeys(); len(got) != 1 || string(got[0]) != good {
		t.Fatalf("keys = %d, want the one key once", len(got))
	}
	conn, err := sshConfig(cty.ObjectVal(map[string]cty.Value{
		"host": cty.StringVal("203.0.113.10"), "user": cty.StringVal("root"), "port": cty.NullVal(cty.Number),
		"host_key": cty.NullVal(cty.String), "known_hosts_file": cty.NullVal(cty.String), "private_key_file": cty.NullVal(cty.String),
	}))
	if err != nil || len(conn.Keys) != 1 {
		t.Fatalf("sshConfig keys = %d, %v", len(conn.Keys), err)
	}

	for key, want := range map[string]string{"not a key": "isn't an SSH private key", pemKey(t, "secret"): "protected by a passphrase"} {
		resp := p.ValidateProviderConfig(ctx, providers.ValidateProviderConfigRequest{Config: cfg(key)})
		if !resp.Diagnostics.HasErrors() || !strings.Contains(resp.Diagnostics.Err().Error(), want) {
			t.Errorf("want %q, got %v", want, resp.Diagnostics.Err())
		}
		if strings.Contains(resp.Diagnostics.Err().Error(), "PRIVATE KEY") {
			t.Error("the error holds part of the key")
		}
	}
}
