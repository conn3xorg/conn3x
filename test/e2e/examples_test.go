// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// Every example in examples/ must init and validate with this build, so the
// README's promise holds.
func TestExamplesValidate(t *testing.T) {
	_, here, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(here), "..", "..", "examples")
	dirs, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		t.Run(d.Name(), func(t *testing.T) {
			dir := t.TempDir()
			if err := os.CopyFS(dir, os.DirFS(filepath.Join(root, d.Name()))); err != nil {
				t.Fatal(err)
			}
			// The digitalocean example reads the deploy user's key from here.
			if err := os.WriteFile(filepath.Join(dir, "deploy.pub"), []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleOnlyExampleOnlyExampleOnlyExampleOnly example\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			w := &workdir{t: t, dir: dir}
			w.mustConn3x("init", "-no-color")
			w.mustConn3x("validate", "-no-color")
		})
	}
}
