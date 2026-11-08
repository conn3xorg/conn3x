// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLintExitCodesAndJSON(t *testing.T) {
	dir := t.TempDir()
	write := func(name, src string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Only a warning: exit 0.
	write("main.circuit.hcl", "circuit \"c\" {\n  step \"s\" {\n    command {\n      command = \"app bootstrap\"\n    }\n  }\n}\n")
	var out, errOut bytes.Buffer
	if code := runLint([]string{dir}, false, &out, &errOut); code != 0 || !strings.Contains(out.String(), "C3X101 command-guard") {
		t.Fatalf("exit %d, out %q, err %q", code, out.String(), errOut.String())
	}
	// An error too: exit 1, and -json lists both.
	write("variables.tf", "variable \"a\" {\n  default = \"0.0.0.0\"\n}\n")
	out.Reset()
	if code := runLint([]string{dir}, true, &out, &errOut); code != 1 {
		t.Fatalf("exit %d, out %q", code, out.String())
	}
	var findings []struct {
		Rule struct{ ID string }
		Line int
	}
	if err := json.Unmarshal(out.Bytes(), &findings); err != nil || len(findings) != 2 {
		t.Fatalf("json %q: %v", out.String(), err)
	}
	// Nothing found: an empty JSON array, and exit 0.
	clean := t.TempDir()
	out.Reset()
	if code := runLint([]string{clean}, true, &out, &errOut); code != 0 || strings.TrimSpace(out.String()) != "[]" {
		t.Fatalf("exit %d, out %q", code, out.String())
	}
}
