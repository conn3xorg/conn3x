// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// A role's no_log tasks convert to write-only arguments: the caller's secret
// reaches the host, and never the circuit, a plan, apply's output or state.
func TestConvertRoleNoLog(t *testing.T) {
	const secret = "n0l0g-e2e-7f3a9c41"
	t.Setenv("CONN3X_HMAC_KEY", strings.Repeat("e2e-key-", 4))
	t.Setenv("TF_VAR_nolog_password", secret)
	_, here, _, _ := runtime.Caller(0)
	role := filepath.Join(filepath.Dir(here), "testdata", "convert_no_log", "role", "nolog")
	h := startHost(t, "rocky10")

	w := newWorkdir(t, "convert_no_log")
	if out, code := w.conn3x("convert", "ansible", "-role", role, "-out", "circuit-nolog"); code != 0 || !strings.Contains(out, "Converted all 2 tasks.") {
		t.Fatalf("convert exited %d:\n%s", code, out)
	}
	w.writeAs("main.tf", secretVars{h.port, h.keyFile, h.knownHosts})
	leaks := func(what, s string) {
		t.Helper()
		if i := strings.Index(s, secret); i >= 0 {
			t.Fatalf("%s holds the secret: ...%s...", what, s[max(0, i-200):min(len(s), i+200)])
		}
	}
	vars, err := os.ReadFile(filepath.Join(w.dir, "circuit-nolog", "variables.tf"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(vars), "sensitive   = true\n  ephemeral   = true") {
		t.Fatalf("nolog_password isn't sensitive and ephemeral:\n%s", vars)
	}
	w.mustConn3x("init", "-no-color")
	leaks("plan", w.mustConn3x("plan", "-no-color", "-out=tfplan"))
	leaks("the saved plan", w.mustConn3x("show", "-json", "tfplan"))
	leaks("apply", w.mustConn3x("apply", "-auto-approve", "-no-color"))
	state, err := os.ReadFile(filepath.Join(w.dir, "terraform.tfstate"))
	if err != nil {
		t.Fatal(err)
	}
	leaks("terraform.tfstate", string(state))
	err = filepath.WalkDir(filepath.Join(w.dir, "circuit-nolog"), func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		leaks(p, string(b))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}

	if got := h.exec("", "cat", "/root/nolog.secret"); got != secret {
		t.Fatalf("/root/nolog.secret = %q", got)
	}
	if got := h.exec("", "cat", "/root/.nolog.cnf"); got != "[client]\npassword="+secret+"\n" {
		t.Fatalf("/root/.nolog.cnf = %q", got)
	}
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
		t.Fatalf("second plan:\n%s", out)
	}
}
