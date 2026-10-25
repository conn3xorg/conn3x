// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/opentofu/opentofu/internal/command"
	"github.com/opentofu/opentofu/internal/configs"
	"github.com/opentofu/opentofu/internal/encryption/config"
)

// stderr is where init's suggestion goes; tests replace it.
var stderr io.Writer = os.Stderr

// Conn3x state holds what it reads from servers as well as the cloud, so
// init suggests OpenTofu's state encryption when it's off (spec §4.5).
const encryptionSuggestion = `
Warning: This configuration's state isn't encrypted

Conn3x state records cloud resources and what it reads from your servers,
and both can include things you'd rather keep private. Turn on state
encryption with an encryption block in the terraform block, or set
TF_ENCRYPTION:
https://opentofu.org/docs/language/state/encryption/
`

// suggestEncryption wraps init so a successful run ends with the
// suggestion when state isn't encrypted.
func suggestEncryption(run func(command.Meta) int) func(command.Meta) int {
	return func(m command.Meta) int {
		code := run(m)
		if code == 0 && !stateEncrypted(".") {
			fmt.Fprint(stderr, encryptionSuggestion)
		}
		return code
	}
}

// stateEncrypted reports whether the configuration in dir, together with
// TF_ENCRYPTION, encrypts state. When it can't tell, it says yes, so a broken
// configuration doesn't also get a warning about encryption.
func stateEncrypted(dir string) bool {
	mod, diags := configs.NewParser(nil).LoadConfigDirSelective(dir, configs.SelectiveLoadEncryption)
	if diags.HasErrors() {
		return true
	}
	cfg := mod.Encryption
	if env := strings.TrimSpace(os.Getenv("TF_ENCRYPTION")); env != "" {
		envCfg, envDiags := config.LoadConfigFromString("TF_ENCRYPTION", env)
		if envDiags.HasErrors() {
			return true
		}
		cfg = cfg.Merge(envCfg)
	}
	return cfg != nil && cfg.State != nil
}
