// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/opentofu/opentofu/internal/command"
	"github.com/opentofu/opentofu/internal/command/arguments"
)

const encryptedState = `terraform {
  encryption {
    key_provider "pbkdf2" "k" {
      passphrase = "correct-horse-battery-staple"
    }
    method "aes_gcm" "m" {
      keys = key_provider.pbkdf2.k
    }
    state {
      method = method.aes_gcm.m
    }
  }
}
`

func configDir(t *testing.T, tf string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte(tf), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestStateEncrypted(t *testing.T) {
	t.Setenv("TF_ENCRYPTION", "")
	plainPlanOnly := strings.Replace(encryptedState, "state {", "plan {", 1)
	for name, tc := range map[string]struct {
		tf, env string
		want    bool
	}{
		"no encryption":         {"terraform {}\n", "", false},
		"state encrypted":       {encryptedState, "", true},
		"only plans encrypted":  {plainPlanOnly, "", false},
		"encrypted through env": {"terraform {}\n", strings.TrimPrefix(strings.TrimSuffix(encryptedState, "}\n"), "terraform {\n"), true},
		"blank env":             {"terraform {}\n", "   ", false},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("TF_ENCRYPTION", tc.env)
			if got := stateEncrypted(configDir(t, tc.tf)); got != tc.want {
				t.Fatalf("stateEncrypted = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestInitSuggestsEncryption(t *testing.T) {
	t.Setenv("TF_ENCRYPTION", "")
	t.Chdir(configDir(t, "terraform {}\n"))
	var out strings.Builder
	old := stderr
	stderr = &out
	t.Cleanup(func() { stderr = old })

	if code := suggestEncryption(func(command.Meta) int { return 1 }, &arguments.View{})(command.Meta{}); code != 1 || out.Len() != 0 {
		t.Fatalf("a failed init warned anyway (exit %d): %q", code, out.String())
	}
	if code := suggestEncryption(func(command.Meta) int { return 0 }, &arguments.View{})(command.Meta{}); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(out.String(), "isn't encrypted") || !strings.Contains(out.String(), "TF_ENCRYPTION") {
		t.Fatalf("no suggestion after init:\n%s", out.String())
	}
}

// With -json, stderr belongs to machines; the plain-text suggestion is left out.
func TestInitJSONSkipsSuggestion(t *testing.T) {
	t.Setenv("TF_ENCRYPTION", "")
	t.Chdir(configDir(t, "terraform {}\n"))
	i, _ := findCommand(brandedRoot(t), "init")
	i.CommandLine.View.ViewType = arguments.ViewJSON
	var out strings.Builder
	old := stderr
	stderr = &out
	t.Cleanup(func() { stderr = old })
	inner := suggestEncryption(func(command.Meta) int { return 0 }, i.CommandLine.View)
	if inner(command.Meta{}); out.Len() != 0 {
		t.Fatalf("init -json printed %q", out.String())
	}
}
