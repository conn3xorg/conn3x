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

// The provider block's private_keys log in with no key file and no agent,
// from an ephemeral variable, and the key reaches neither state nor plan.
func TestProviderPrivateKeys(t *testing.T) {
	box := startHost(t, "rocky10")
	knownFile := shareKey(t, box)
	key, err := os.ReadFile(box.keyFile)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSH_AUTH_SOCK", "")
	t.Setenv("TF_VAR_deploy_key", string(key))
	w := newWorkdir(t, "provider_keys")
	w.write(chainVars{PortA: box.port, KnownHosts: knownFile})
	w.mustConn3x("init", "-no-color")

	w.mustConn3x("plan", "-no-color", "-out=p.tfplan")
	w.mustConn3x("apply", "-auto-approve", "-no-color", "p.tfplan")
	if got := strings.TrimSpace(box.exec("", "cat", "/etc/motd")); got != "keys from the provider block" {
		t.Fatalf("motd = %q", got)
	}
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes") {
		t.Errorf("a second plan, which refreshes over SSH, should be clean:\n%s", out)
	}
	// The key's base64 body, not just its armour, must be nowhere on disk.
	body := strings.Split(strings.TrimSpace(string(key)), "\n")[1]
	for _, f := range []string{"terraform.tfstate", "p.tfplan"} {
		raw, err := os.ReadFile(filepath.Join(w.dir, f))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), body) {
			t.Errorf("%s holds the key", f)
		}
	}
}
