// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConvertRoleWritesANewDirectory(t *testing.T) {
	role := "../../internal/conn3x/convert/ansible/testdata/role/app"
	out := filepath.Join(t.TempDir(), "circuit-app")
	var errOut bytes.Buffer
	if code := runConvertRole(role, out, "", "", &errOut); code != 0 || !strings.Contains(errOut.String(), "Converted all 7 tasks.") {
		t.Fatalf("exited %d: %s", code, errOut.String())
	}
	for _, f := range []string{"main.circuit.hcl", "variables.tf", "outputs.tf", "README.md", "files/app.service", "templates/app.conf.tftpl"} {
		if _, err := os.Stat(filepath.Join(out, f)); err != nil {
			t.Error(err)
		}
	}
	// Converting again would replace what's there, so it refuses.
	errOut.Reset()
	if code := runConvertRole(role, out, "", "", &errOut); code != 1 || !strings.Contains(errOut.String(), "already has files") {
		t.Fatalf("second run exited %d: %s", code, errOut.String())
	}
	for args, want := range map[[3]string]string{
		{"", "", ""}:           "-role needs -out",
		{out, "site.yml", ""}:  "not both",
		{out, "", "hosts.ini"}: "-i doesn't go with -role",
	} {
		errOut.Reset()
		if code := runConvertRole(role, args[0], args[1], args[2], &errOut); code != 1 || !strings.Contains(errOut.String(), want) {
			t.Errorf("%v: exited %d: %s", args, code, errOut.String())
		}
	}
}
