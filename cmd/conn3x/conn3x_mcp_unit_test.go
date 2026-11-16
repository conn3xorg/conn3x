// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/opentofu/opentofu/internal/command"
)

// conn3x mcp answers on standard output what it's asked on standard input,
// and exits 0 when the input ends.
func TestMCPServesStdio(t *testing.T) {
	t.Chdir(t.TempDir())
	in := filepath.Join(t.TempDir(), "in")
	if err := os.WriteFile(in, []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(in)
	if err != nil {
		t.Fatal(err)
	}
	oldIn := os.Stdin
	os.Stdin = f
	t.Cleanup(func() { os.Stdin = oldIn; f.Close() })
	out := unitStdout(t)
	if code := mcpCommand().Run(command.Meta{}); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if got := out(); !strings.Contains(got, `"id":1`) || !strings.Contains(got, "search_modules") {
		t.Errorf("answered %q", got)
	}
}
