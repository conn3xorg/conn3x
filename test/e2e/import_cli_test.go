// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
)

// conn3x import takes the same JSON ID that import = true and
// provider::conn3x::import_id write, as the steps reference documents: the
// file the host has is adopted, and the next plan has nothing to do.
func TestImportCommandTakesTheDocumentedID(t *testing.T) {
	h := startHost(t, "ubuntu2404")
	h.exec("", "sh", "-c", "printf 'Welcome\\n' > /etc/motd && chmod 0644 /etc/motd")

	w := newWorkdir(t, "import_cli")
	vars := struct{ Port, KeyFile, KnownHosts string }{h.port, h.keyFile, h.knownHosts}
	w.writeAs("main.circuit.hcl", vars)
	w.mustConn3x("init", "-no-color")

	port, err := strconv.Atoi(h.port)
	if err != nil {
		t.Fatal(err)
	}
	id, err := json.Marshal(map[string]any{
		"v": 1, "key": "box",
		"ssh":  map[string]any{"host": "127.0.0.1", "port": port, "user": "root", "private_key_file": h.keyFile, "known_hosts_file": h.knownHosts},
		"args": map[string]any{"path": "/etc/motd", "mode": "0644"},
	})
	if err != nil {
		t.Fatal(err)
	}
	out := w.mustConn3x("import", "-no-color", `conn3x_file.adopt__motd["box"]`, string(id))
	if !strings.Contains(out, "Import successful") {
		t.Fatalf("import:\n%s", out)
	}
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
		t.Fatalf("the plan after importing the file isn't empty:\n%s", out)
	}
}
