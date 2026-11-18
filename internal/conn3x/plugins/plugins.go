// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package plugins finds provider plugins a directory has installed, which
// running conn3x there would start. conn3x mcp and conn3x lsp both run
// conn3x validate in directories a user didn't choose to trust by running
// it themselves, such as a repository they only cloned, so they check first.
package plugins

import (
	"os"
	"path/filepath"

	"github.com/opentofu/opentofu/internal/depsfile"
)

// Installed returns what in dir would start a provider plugin: a
// .terraform.lock.hcl naming a provider, or one that doesn't parse, or a
// providers directory under the data directory (TF_DATA_DIR, .terraform by
// default). It returns "" when there's neither.
func Installed(dir string) string {
	lock := filepath.Join(dir, ".terraform.lock.hcl")
	if _, err := os.Lstat(lock); err == nil {
		locks, diags := depsfile.LoadLocksFromFile(lock)
		if diags.HasErrors() || len(locks.AllProviders()) > 0 {
			return ".terraform.lock.hcl"
		}
	}
	data := os.Getenv("TF_DATA_DIR")
	if data == "" {
		data = ".terraform"
	}
	if !filepath.IsAbs(data) {
		data = filepath.Join(dir, data)
	}
	if entries, _ := os.ReadDir(filepath.Join(data, "providers")); len(entries) > 0 {
		return filepath.Join(data, "providers")
	}
	return ""
}
