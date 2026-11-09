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

// A role call with a when on the family runs the role only on that
// family's hosts, as Ansible does: on a Red Hat host and a Debian-family
// host together, each gets its own role, and the next plan is empty. With
// no host of a call's family left, its hosts filter to nothing and the
// apply still succeeds.
func TestConvertPlayRolesWhen(t *testing.T) {
	rh, deb := startHost(t, "rocky10"), startHost(t, "ubuntu2404")
	known := shareKey(t, rh, deb)

	w := newWorkdir(t, "convert_play_roles_when")
	w.writeAs("play.yml", nil)
	for name, content := range map[string]string{
		"roles/deb/tasks/main.yml": "- name: Debian mark\n  copy:\n    content: \"deb\\n\"\n    dest: /etc/role-deb\n",
		"roles/rh/tasks/main.yml":  "- name: Red Hat mark\n  copy:\n    content: \"rh\\n\"\n    dest: /srv/role-rh\n",
	} {
		path := filepath.Join(w.dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if out, code := w.conn3x("convert", "ansible", "-out", "play.tf", "play.yml"); code != 0 || !strings.Contains(out, "Converted all 3 tasks.") {
		t.Fatalf("convert exited %d:\n%s", code, out)
	}

	// The two test hosts listen on their own ports, so the hosts are
	// objects, and they share one known_hosts file.
	tf, err := os.ReadFile(filepath.Join(w.dir, "play.tf"))
	if err != nil {
		t.Fatal(err)
	}
	patched := strings.Replace(string(tf), "type        = map(string)", "type        = any", 1)
	patched = strings.ReplaceAll(patched, "\n    private_key_file = var.ssh_private_key_file",
		fmt.Sprintf("\n    private_key_file = var.ssh_private_key_file\n    known_hosts_file = %q", known))
	patched = strings.ReplaceAll(patched, "\n  ssh_private_key_file = var.ssh_private_key_file",
		fmt.Sprintf("\n  ssh_private_key_file = var.ssh_private_key_file\n  ssh_known_hosts_file = %q", known))
	if strings.Count(patched, "known_hosts_file") < 3 {
		t.Fatalf("not everything to patch is there:\n%s", tf)
	}
	tfvars := func(hosts string) {
		vars := fmt.Sprintf("box_hosts = {%s}\nssh_user = \"root\"\nssh_private_key_file = %q\n", hosts, rh.keyFile)
		for name, content := range map[string]string{"play.tf": patched, "terraform.tfvars": vars} {
			if err := os.WriteFile(filepath.Join(w.dir, name), []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	rhHost := fmt.Sprintf(" rh = { address = \"127.0.0.1\", port = %s }", rh.port)
	tfvars(rhHost + fmt.Sprintf(", deb = { address = \"127.0.0.1\", port = %s } ", deb.port))
	w.mustConn3x("init", "-no-color")
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	check := "for p in /etc/role-deb /srv/role-rh; do test -e $p && echo $p; done; true"
	if got := rh.exec("", "sh", "-c", check); got != "/srv/role-rh\n" {
		t.Errorf("rocky has %q, want only the Red Hat role's file", got)
	}
	if got := deb.exec("", "sh", "-c", check); got != "/etc/role-deb\n" {
		t.Errorf("ubuntu has %q, want only the Debian role's file", got)
	}
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
		t.Fatalf("plan after apply:\n%s", out)
	}

	// Only the Red Hat host left: the Debian call passes no hosts at all.
	tfvars(rhHost + " ")
	w.mustConn3x("apply", "-auto-approve", "-no-color")
	if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
		t.Fatalf("plan with no Debian host:\n%s", out)
	}
}
