// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"os"
	"path/filepath"
)

func writeEmpty(w *workdir) error {
	return os.WriteFile(filepath.Join(w.dir, "main.tf"), []byte("# nothing managed\n"), 0o644)
}

func touch(path string) error {
	return os.WriteFile(path, nil, 0o600)
}
