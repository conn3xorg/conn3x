// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// conn3x test makes its own host: a setup run starts a conn3x_test_container,
// the next run applies a circuit to it twice, and the end of the file
// destroys the circuit's steps, then the container (#799).
func TestConn3xTestStartsItsOwnHost(t *testing.T) {
	_, here, _, _ := runtime.Caller(0)
	run(t, "podman", "build", "-q", "-t", "localhost/conn3x-e2e-rocky10", filepath.Join(filepath.Dir(here), "..", "images", "rocky10"))
	before := testContainers(t)

	w := &workdir{t: t, dir: t.TempDir()}
	files := map[string]string{
		"main.tf": `variable "port" { type = number }
variable "key" { type = string }
variable "known_hosts" { type = string }

circuit "web" {
  hosts = { web1 = "127.0.0.1" }

  ssh {
    port             = var.port
    user             = "root"
    private_key_file = var.key
    known_hosts_file = var.known_hosts
  }

  step "sshd" {
    service {
      name    = "sshd"
      state   = "started"
      enabled = true
    }
  }

  step "motd" {
    file {
      path      = "/etc/motd"
      content   = "tested\n"
      on_remove = "delete"
    }
  }
}
`,
		"tests/setup/main.tf": `variable "image" { type = string }

resource "conn3x_test_container" "web1" {
  image = var.image
}

output "port" { value = conn3x_test_container.web1.port }
output "key" { value = conn3x_test_container.web1.private_key_file }
output "known_hosts" { value = conn3x_test_container.web1.known_hosts_file }
`,
		"tests/web.tftest.hcl": `run "host" {
  module {
    source = "./tests/setup"
  }
  variables {
    image = "localhost/conn3x-e2e-rocky10"
  }
}

run "converge" {
  variables {
    port        = run.host.port
    key         = run.host.key
    known_hosts = run.host.known_hosts
  }
  idempotent = true
}
`,
	}
	for name, body := range files {
		p := filepath.Join(w.dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	w.mustConn3x("init")
	out := w.mustConn3x("test")
	for _, want := range []string{`run "host"... pass`, `run "converge"... pass`, "2 passed, 0 failed"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
	if after := testContainers(t); after != before {
		t.Errorf("%d test containers before and %d after; the end of the file should remove its own", before, after)
	}
}

func testContainers(t *testing.T) int {
	t.Helper()
	out, err := exec.Command("podman", "ps", "-aq", "--filter", "label=io.conn3x.test-container=true").Output()
	if err != nil {
		t.Fatal(err)
	}
	return len(strings.Fields(string(out)))
}
