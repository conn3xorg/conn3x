// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/afero"

	"github.com/opentofu/opentofu/internal/configs"
)

func TestConvertContainers(t *testing.T) {
	res := convertString(t, `- hosts: app
  tasks:
    - name: web
      community.docker.docker_container:
        name: web
        image: docker.io/library/nginx:1.27
        published_ports: ["8080:80"]
        volumes: ["/srv/site:/usr/share/nginx/html:ro"]
        env: { TZ: UTC }
        restart_policy: unless-stopped
    - name: worker
      containers.podman.podman_container:
        name: worker
        image: ghcr.io/example/worker:2.4.1
        command: worker --queue default
        publish: ["9000:9000"]
`)
	hcl := string(res.HCL)
	for _, want := range []string{`engine  = "docker"`, `ports   = ["8080:80"]`, `restart = "unless-stopped"`, `TZ = "UTC"`, `engine  = "podman"`, `command = ["worker", "--queue", "default"]`} {
		if !strings.Contains(hcl, want) {
			t.Errorf("missing %s:\n%s", want, hcl)
		}
	}
	if res.Converted != 2 || len(res.Review) != 0 {
		t.Errorf("converted %d, review %v", res.Converted, res.Review)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.circuit.hcl"), res.HCL, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, diags := configs.NewParser(afero.NewOsFs()).LoadConfigDir(dir); diags.HasErrors() {
		t.Errorf("the circuit doesn't load: %s\n%s", diags, hcl)
	}

	for task, want := range map[string]string{
		"docker_container: { name: web, image: nginx, state: present }":               `state "present"`,
		"docker_container: { name: web, image: nginx, networks: [{name: x}] }":        "sets networks",
		"docker_container: { name: web, image: nginx, command: \"sh -c 'echo hi'\" }": "write it as a list",
		"docker_container: { name: web, image: nginx, published_ports: [\"80\"] }":    "must be host:container",
	} {
		res := convertString(t, "- hosts: app\n  tasks:\n    - "+task+"\n")
		if res.Converted != 0 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, want) {
			t.Errorf("%s: converted %d, review %+v, want %q", task, res.Converted, res.Review, want)
		}
	}
}
