// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// A value from an encrypted host data layer reaches a host through
// conn3x_hostdata and a write-only argument, and nowhere on disk on the way.
func TestHostdataSecrets(t *testing.T) {
	box := startHost(t, "rocky10")
	knownFile := shareKey(t, box)
	_, here, _, _ := runtime.Caller(0)
	fixtures := filepath.Join(filepath.Dir(here), "..", "..", "internal", "conn3x", "secrets", "testdata")
	key, err := os.ReadFile(filepath.Join(fixtures, "test-key.txt"))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOPS_AGE_KEY", string(key))
	t.Setenv("SOPS_AGE_KEY_FILE", "")
	w := newWorkdir(t, "hostdata_secrets")
	w.write(chainVars{PortA: box.port, Key: box.keyFile, KnownHosts: knownFile})
	src, err := os.ReadFile(filepath.Join(fixtures, "secrets.sops.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	data := filepath.Join(w.dir, "data")
	for name, body := range map[string][]byte{
		"hierarchy.yaml":   []byte("hierarchy: [\"hosts/{host}.yaml\", common.sops.yaml]\n"),
		"hosts/web1.yaml":  []byte("role: web\n"),
		"common.sops.yaml": src,
	} {
		p := filepath.Join(data, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, body, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	w.mustConn3x("init", "-no-color")
	w.mustConn3x("plan", "-no-color", "-out=p.tfplan")
	w.mustConn3x("apply", "-auto-approve", "-no-color", "p.tfplan")
	if got := box.exec("", "cat", "/etc/db_password"); got != "hunter2" {
		t.Fatalf("db_password = %q", got)
	}
	for _, f := range []string{"terraform.tfstate", "p.tfplan"} {
		raw, err := os.ReadFile(filepath.Join(w.dir, f))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), "hunter2") {
			t.Errorf("%s holds the secret", f)
		}
	}
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes") {
		t.Errorf("a second plan should be clean:\n%s", out)
	}
}
