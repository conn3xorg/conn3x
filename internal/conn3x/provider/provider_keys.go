// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"sync"

	"github.com/zclconf/go-cty/cty"
	gossh "golang.org/x/crypto/ssh"

	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

// The provider block's private_keys are SSH keys every login tries, after
// the ssh block's private_key_file and before the agent. They come in
// through the provider block because OpenTofu configures a provider before
// any refresh, in plan and in apply, and passes it ephemeral values; a
// step's own write-only argument wouldn't reach the refresh, which sees
// only state. Provider configuration isn't written to state or plan files.

var providerKeys struct {
	sync.Mutex
	keys [][]byte
}

func providerConfigSchema() *configschema.Block {
	return &configschema.Block{Attributes: map[string]*configschema.Attribute{
		"private_keys": {
			Type: cty.List(cty.String), Optional: true, Sensitive: true, WriteOnly: true,
			Description: "SSH private keys, PEM or OpenSSH format and without a passphrase, that every login tries after a step's private_key_file and before the SSH agent. Give them from an ephemeral variable or an ephemeral resource, such as a secret store's, so they never reach a file: provider configuration isn't kept in state or plan files, but a plain variable's value is kept in the plan.",
		},
	}}
}

// parseProviderKeys checks the private_keys in a provider configuration,
// and returns them, or nil while they aren't known yet. An error never
// holds any part of a key.
func parseProviderKeys(cfg cty.Value) ([][]byte, tfdiags.Diagnostics) {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() || !cfg.Type().HasAttribute("private_keys") {
		return nil, diags
	}
	v := cfg.GetAttr("private_keys")
	if v.IsNull() || !v.IsWhollyKnown() {
		return nil, diags
	}
	v, _ = v.Unmark()
	var keys [][]byte
	for i, k := range v.AsValueSlice() {
		k, _ = k.Unmark()
		if k.IsNull() {
			diags = diags.Append(attrError("private_keys", fmt.Sprintf("private_keys[%d] is null", i)))
			continue
		}
		raw := []byte(k.AsString())
		if _, err := gossh.ParsePrivateKey(raw); err != nil {
			var missing *gossh.PassphraseMissingError
			why := "isn't an SSH private key in PEM or OpenSSH format"
			if errors.As(err, &missing) {
				why = "is protected by a passphrase; Conn3x takes keys without one, so store it unencrypted in the secret store"
			}
			diags = diags.Append(attrError("private_keys", fmt.Sprintf("private_keys[%d] %s", i, why)))
			continue
		}
		keys = append(keys, raw)
	}
	return keys, diags
}

// addProviderKeys keeps keys for every login in this process. Two provider
// blocks, such as aliases, add theirs together: each login tries them all.
func addProviderKeys(keys [][]byte) {
	providerKeys.Lock()
	defer providerKeys.Unlock()
	for _, k := range keys {
		if !slices.ContainsFunc(providerKeys.keys, func(have []byte) bool { return bytes.Equal(have, k) }) {
			providerKeys.keys = append(providerKeys.keys, k)
		}
	}
}

func currentProviderKeys() [][]byte {
	providerKeys.Lock()
	defer providerKeys.Unlock()
	return slices.Clone(providerKeys.keys)
}
