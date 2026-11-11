// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A role call in a file the play imports converts to a module in the
// play's order, as it would written in place: the task before the import
// runs first, the role (after its meta/ dependency) next, and the task
// after the import last.
func TestConvertPlayRolesInAnImport(t *testing.T) {
	h := startHost(t, "rocky10")
	w := newWorkdir(t, "convert_play_roles_import")
	w.writeAs("play.yml", nil)
	for name, content := range map[string]string{
		"calls.yml":                     "- name: Greet from the import\n  include_role:\n    name: greet\n",
		"roles/greet/defaults/main.yml": "greeting: from the role\n",
		"roles/greet/tasks/main.yml":    "- name: Greet\n  copy:\n    content: \"{{ greeting }}\\n\"\n    dest: /opt/greet/hello.txt\n",
		"roles/greet/meta/main.yml":     "dependencies:\n  - role: base\n    word: from meta\n",
		"roles/base/defaults/main.yml":  "word: from the default\n",
		"roles/base/tasks/main.yml":     "- name: Base\n  copy:\n    content: \"{{ word }}\\n\"\n    dest: /opt/greet/base.txt\n",
	} {
		path := filepath.Join(w.dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if out, code := w.conn3x("convert", "ansible", "-out", "play.tf", "play.yml"); code != 0 || !strings.Contains(out, "Converted all 5 tasks.") {
		t.Fatalf("convert exited %d:\n%s", code, out)
	}

	// The test host listens on a mapped port with its own known_hosts.
	tf, err := os.ReadFile(filepath.Join(w.dir, "play.tf"))
	if err != nil {
		t.Fatal(err)
	}
	patched := strings.ReplaceAll(string(tf), "\n    private_key_file = var.ssh_private_key_file",
		fmt.Sprintf("\n    private_key_file = var.ssh_private_key_file\n    port = %s\n    known_hosts_file = %q", h.port, h.knownHosts))
	patched = strings.ReplaceAll(patched, "\n  ssh_private_key_file = var.ssh_private_key_file",
		fmt.Sprintf("\n  ssh_private_key_file = var.ssh_private_key_file\n  ssh_port = %s\n  ssh_known_hosts_file = %q", h.port, h.knownHosts))
	if !strings.Contains(patched, "module \"greet\"") || !strings.Contains(patched, "ssh_port") {
		t.Fatalf("no module to patch:\n%s", tf)
	}
	vars := fmt.Sprintf("box_hosts = { box = \"127.0.0.1\" }\nssh_user = \"root\"\nssh_private_key_file = %q\n", h.keyFile)
	for name, content := range map[string]string{"play.tf": patched, "terraform.tfvars": vars} {
		if err := os.WriteFile(filepath.Join(w.dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	w.mustConn3x("init", "-no-color")
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if got := h.exec("", "sh", "-c", "cat /opt/greet/base.txt /opt/greet/hello.txt /opt/greet/after.txt"); got != "from meta\nfrom the play\nafter\n" {
		t.Fatalf("host after apply:\n%s", got)
	}
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
		t.Fatalf("plan after apply:\n%s", out)
	}
}
