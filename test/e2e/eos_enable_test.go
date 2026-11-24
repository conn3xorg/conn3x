// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestEOSEnable logs in as ops, a privilege 1 user with the same key, and
// reaches privileged mode through enable with become. The switch needs
// "enable password EnPass1" and "username ops privilege 1 nopassword" with
// the key; the test sets both up through admin.
func TestEOSEnable(t *testing.T) {
	v := eosSwitch(t)
	pub, err := os.ReadFile(v.KeyFile + ".pub")
	if err != nil {
		t.Skipf("needs %s.pub to give ops the key: %v", v.KeyFile, err)
	}
	key := strings.Join(strings.Fields(string(pub))[:2], " ")
	v.mustCLI(t, "configure\nenable password EnPass1\nusername ops privilege 1 nopassword\nusername ops ssh-key "+key+"\nno vlan 472\nend\n")
	t.Cleanup(func() { _, _ = v.cli(t, "configure\nno vlan 472\nno username ops\nno enable password\nend\n") })

	dir := t.TempDir()
	pw := filepath.Join(dir, "enable")
	if err := os.WriteFile(pw, []byte("EnPass1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	vars := struct {
		eosVars
		PasswordFile string
	}{v, pw}
	w := newWorkdir(t, "eosenable")
	w.writeAs("main.circuit.hcl", vars)
	w.mustConn3x("init", "-no-color")
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if out := v.mustCLI(t, "show vlan 472\n"); !strings.Contains(out, "via-enable") {
		t.Fatalf("vlan 472 after apply:\n%s", out)
	}
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
		t.Fatalf("plan after apply:\n%s", out)
	}

	// A wrong password is an error that names the file, and never shows
	// the password.
	if err := os.WriteFile(pw, []byte("Wrong-Pass\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, code := w.conn3x("plan", "-refresh=true", "-no-color")
	if code == 0 || !strings.Contains(out, "refused the enable password from become_password_file") || strings.Contains(out, "Wrong-Pass") {
		t.Fatalf("plan with a wrong password exited %d:\n%s", code, out)
	}
}
