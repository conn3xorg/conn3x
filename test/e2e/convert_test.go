// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// A playbook converted with conn3x convert ansible applies as it is.
func TestConvertAnsibleThenApply(t *testing.T) {
	for _, image := range linuxImages {
		t.Run(image, func(t *testing.T) {
			h := startHost(t, image)
			w := newWorkdir(t, "convert")
			w.writeAs("play.yml", nil)
			out, code := w.conn3x("convert", "ansible", "-out", "play.tf", "play.yml")
			if code != 0 || !strings.Contains(out, "Converted all 11 tasks.") {
				t.Fatalf("convert exited %d:\n%s", code, out)
			}

			// The test host listens on a mapped port with its own known_hosts.
			tf, err := os.ReadFile(filepath.Join(w.dir, "play.tf"))
			if err != nil {
				t.Fatal(err)
			}
			patched := strings.Replace(string(tf), "private_key_file = var.ssh_private_key_file",
				fmt.Sprintf("private_key_file = var.ssh_private_key_file\n    port = %s\n    known_hosts_file = %q", h.port, h.knownHosts), 1)
			vars := fmt.Sprintf("box_hosts = { box = \"127.0.0.1\" }\nssh_user = \"root\"\nssh_private_key_file = %q\n", h.keyFile)
			for name, content := range map[string]string{"play.tf": patched, "terraform.tfvars": vars} {
				if err := os.WriteFile(filepath.Join(w.dir, name), []byte(content), 0o644); err != nil {
					t.Fatal(err)
				}
			}

			h.exec("# mirrors\nmirror = old.example.com/base\nmirror = old.example.com/extra\n", "sh", "-c", "cat > /etc/conn3x-mirrors.conf")
			w.mustConn3x("init", "-no-color")
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if got := h.exec("", "sh", "-c", "stat -c '%a' /opt/app /opt/app/app.conf; cat /opt/app/app.conf; grep -c 'Managed by Conn3x' /etc/issue.net; id -u app >/dev/null && echo app; command -v tree"); !strings.HasPrefix(got, "750\n640\nport = 8080\n1\napp\n") {
				t.Fatalf("host after apply:\n%s", got)
			}
			if got := h.exec("", "cat", "/opt/app/app.ini", "/etc/conn3x-mirrors.conf"); got != "[main]\nport = 8080\n# mirrors\nmirror = new.example.com/base\nmirror = new.example.com/extra\n" {
				t.Fatalf("converted ini and replace steps left:\n%s", got)
			}
			if got := h.exec("", "sh", "-c", "cat /etc/ssh/ssh_known_hosts /root/.ssh/known_hosts; tail -n 1 /etc/security/limits.conf"); got != "git.example.com "+hostKeyAlice+"\nmirror.example.com "+hostKeyAlice+"\napp\tsoft\tnofile\t64000\n" {
				t.Fatalf("converted known_hosts and limit steps left:\n%s", got)
			}
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("plan after apply:\n%s", out)
			}
		})
	}
}

// A role converted with conn3x convert ansible -role applies as a module, and
// a second plan finds nothing to change.
func TestConvertAnsibleRoleThenApply(t *testing.T) {
	_, here, _, _ := runtime.Caller(0)
	role := filepath.Join(filepath.Dir(here), "..", "..", "internal", "conn3x", "convert", "ansible", "testdata", "role", "app")
	for _, image := range linuxImages {
		t.Run(image, func(t *testing.T) {
			h := startHost(t, image)
			w := newWorkdir(t, "convert_role")
			if out, code := w.conn3x("convert", "ansible", "-role", role, "-out", "circuit-app"); code != 0 || !strings.Contains(out, "Converted all 7 tasks.") {
				t.Fatalf("convert exited %d:\n%s", code, out)
			}
			w.write(struct{ Port, Key, KnownHosts string }{h.port, h.keyFile, h.knownHosts})
			w.mustConn3x("init", "-no-color")
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			want := "# Set by the caller\n# Written by the app role. Prices in ${currency} stay as they are.\nport = 8080\nuser = app\ndir = /opt/app\napp 750\napp 640\nactive\nenabled\nSet by the caller\n"
			if got := h.exec("", "sh", "-c", "cat /opt/app/app.conf; stat -c '%U %a' /opt/app /opt/app/app.conf; systemctl is-active app; systemctl is-enabled app; tail -n 1 /etc/issue.net; command -v tree >/dev/null"); got != want {
				t.Fatalf("host after apply:\n%s", got)
			}
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("plan after apply:\n%s", out)
			}
		})
	}
}

// A playbook that runs a role converts, with -out, into its own circuits and
// a module calling the role's circuit, which takes the play's vars over the
// role's defaults, and the whole thing applies in Ansible's order.
func TestConvertAnsiblePlayRolesThenApply(t *testing.T) {
	for _, image := range linuxImages {
		t.Run(image, func(t *testing.T) {
			h := startHost(t, image)
			w := newWorkdir(t, "convert_play_roles")
			w.writeAs("play.yml", nil)
			for name, content := range map[string]string{
				"roles/greet/defaults/main.yml": "greeting: from the role\n",
				"roles/greet/tasks/main.yml":    "- name: Greet\n  copy:\n    content: \"{{ greeting }}\\n\"\n    dest: /opt/greet/hello.txt\n",
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
			if got := h.exec("", "sh", "-c", "cat /opt/greet/hello.txt /opt/greet/after.txt"); got != "from the play\nafter\n" {
				t.Fatalf("host after apply:\n%s", got)
			}
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("plan after apply:\n%s", out)
			}
		})
	}
}
