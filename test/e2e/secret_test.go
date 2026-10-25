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

type secretVars struct{ Port, KeyFile, KnownHosts, Secret string }

// Write-only content reaches the host but never the state, and drift on the
// host still shows.
func TestWriteOnlySecrets(t *testing.T) {
	const secret = "s3cret-e2e-value"
	t.Setenv("CONN3X_HMAC_KEY", strings.Repeat("e2e-key-", 4))
	h := startHost(t, "rocky10")
	w := newWorkdir(t, "secret")
	if err := os.WriteFile(filepath.Join(w.dir, "pgpass.tftpl"), []byte("db:5432:*:app:${password}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	w.writeAs("main.circuit.hcl", secretVars{h.port, h.keyFile, h.knownHosts, secret})
	w.mustConn3x("init", "-no-color")
	if out := w.mustConn3x("plan", "-no-color"); strings.Contains(out, secret) {
		t.Fatalf("plan shows the secret:\n%s", out)
	}
	w.mustConn3x("apply", "-auto-approve", "-no-color")

	if got := h.exec("", "cat", "/root/db-password"); got != secret {
		t.Fatalf("/root/db-password = %q", got)
	}
	if got := h.exec("", "cat", "/root/.pgpass"); got != "db:5432:*:app:"+secret+"\n" {
		t.Fatalf("/root/.pgpass = %q", got)
	}
	state, err := os.ReadFile(filepath.Join(w.dir, "terraform.tfstate"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(state), secret) {
		t.Fatal("the secret is in terraform.tfstate")
	}
	if !strings.Contains(string(state), "hmac-sha256:") {
		t.Fatal("state has no content_hmac")
	}
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
		t.Fatalf("second plan:\n%s", out)
	}

	// A hand edit on the host shows up, and apply puts the secret back.
	h.exec("", "sh", "-c", "echo changed > /root/db-password")
	out := w.mustConn3x("plan", "-no-color")
	if !strings.Contains(out, "content_hmac") || strings.Contains(out, secret) {
		t.Fatalf("drift plan:\n%s", out)
	}
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if got := h.exec("", "cat", "/root/db-password"); got != secret {
		t.Fatalf("after apply /root/db-password = %q", got)
	}
}
