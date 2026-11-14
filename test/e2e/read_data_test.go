// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"encoding/json"
	"strings"
	"testing"
)

type readDataVars struct {
	Port, KeyFile, KnownHosts string
	Small                     bool
}

// conn3x_file and conn3x_command read a host at plan without changing it:
// a file's content and metadata, a missing file, and a command's output
// and exit code, which is data, not an error.
func TestReadDataSources(t *testing.T) {
	h := startHost(t, "ubuntu2404")
	w := newWorkdir(t, "read_data")
	vars := readDataVars{Port: h.port, KeyFile: h.keyFile, KnownHosts: h.knownHosts}
	w.writeAs("main.tf", vars)
	w.mustConn3x("init", "-no-color")
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	var out map[string]struct {
		Value any `json:"value"`
	}
	if err := json.Unmarshal([]byte(w.mustConn3x("output", "-json")), &out); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"release_has_id": true, "missing": false, "stdout": "ready\n", "stderr": "warn\n", "exit_code": float64(3)}
	for k, v := range want {
		if out[k].Value != v {
			t.Errorf("%s = %#v, want %#v", k, out[k].Value, v)
		}
	}
	if sha := h.exec("", "sh", "-c", "sha256sum /etc/os-release | cut -d' ' -f1"); strings.TrimSpace(sha) != out["release_sha"].Value {
		t.Errorf("sha256 %v, the host says %s", out["release_sha"].Value, sha)
	}
	// Schema-sensitive values are masked wherever they're shown.
	shown := w.mustConn3x("show", "-no-color")
	for _, line := range []string{"content = (sensitive value)", "stdout    = (sensitive value)", "stderr    = (sensitive value)"} {
		if !strings.Contains(shown, line) {
			t.Errorf("show doesn't print %q:\n%s", line, shown)
		}
	}

	vars.Small = true
	w.writeAs("main.tf", vars)
	if out, code := w.conn3x("plan", "-no-color"); code == 0 || !strings.Contains(out, "over max_size") {
		t.Fatalf("a file over max_size (exit %d):\n%s", code, out)
	}
}
