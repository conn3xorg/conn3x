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

// A playbook converted with conn3x convert ansible applies as it is.
func TestConvertAnsibleThenApply(t *testing.T) {
	for _, image := range linuxImages {
		t.Run(image, func(t *testing.T) {
			h := startHost(t, image)
			w := newWorkdir(t, "convert")
			w.writeAs("play.yml", nil)
			out, code := w.conn3x("convert", "ansible", "-out", "play.tf", "play.yml")
			if code != 0 || !strings.Contains(out, "Converted all 5 tasks.") {
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

			w.mustConn3x("init", "-no-color")
			w.mustConn3x("apply", "-auto-approve", "-no-color")
			if got := h.exec("", "sh", "-c", "stat -c '%a' /opt/app /opt/app/app.conf; cat /opt/app/app.conf; grep -c 'Managed by Conn3x' /etc/issue.net; id -u app >/dev/null && echo app; command -v tree"); !strings.HasPrefix(got, "750\n640\nport = 8080\n1\napp\n") {
				t.Fatalf("host after apply:\n%s", got)
			}
			if out := w.mustConn3x("plan", "-no-color"); !strings.Contains(out, "No changes.") {
				t.Fatalf("plan after apply:\n%s", out)
			}
		})
	}
}
