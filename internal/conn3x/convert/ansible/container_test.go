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
		"docker_container: { name: web, image: nginx, state: present }":                      `state "present"`,
		"docker_container: { name: web, image: nginx, networks: [{name: x, aliases: [y]}] }": "sets networks with aliases",
		"podman_container: { name: web, image: nginx, network: host }":                       "host and none are network modes",
		"docker_container: { name: web, image: nginx, command: \"sh -c 'echo hi'\" }":        "write it as a list",
		"docker_container: { name: web, image: nginx, published_ports: [\"80\"] }":           "must be host:container",
	} {
		res := convertString(t, "- hosts: app\n  tasks:\n    - "+task+"\n")
		if res.Converted != 0 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, want) {
			t.Errorf("%s: converted %d, review %+v, want %q", task, res.Converted, res.Review, want)
		}
	}
}

// A compose-style play: an image, a network and a volume, and a container
// on both.
func TestConvertContainerObjects(t *testing.T) {
	res := convertString(t, `- hosts: app
  tasks:
    - community.docker.docker_image: { name: docker.io/library/nginx, tag: "1.27", source: pull }
    - community.docker.docker_network: { name: app, ipam_config: [{ subnet: 10.89.0.0/24 }] }
    - community.docker.docker_volume: { volume_name: data }
    - community.docker.docker_container:
        name: web
        image: docker.io/library/nginx:1.27
        networks: [{ name: app }]
        volumes: ["data:/data"]
    - containers.podman.podman_image: { name: "ghcr.io/example/worker:2.4.1", tag: ignored }
    - containers.podman.podman_network: { name: back, driver: macvlan, subnet: 10.90.0.0/24 }
    - containers.podman.podman_volume: { name: cache, driver: local }
    - containers.podman.podman_container: { name: worker, image: "ghcr.io/example/worker:2.4.1", network: [app, back] }
`)
	hcl := string(res.HCL)
	for _, want := range []string{
		"container_image {", `name   = "docker.io/library/nginx"`, `tag    = "1.27"`,
		"container_network {", `subnet = "10.89.0.0/24"`, `driver = "macvlan"`,
		"container_volume {", `name   = "data"`, `name   = "cache"`,
		`networks = ["app"]`, `networks = ["app", "back"]`, `name   = "ghcr.io/example/worker:2.4.1"`,
	} {
		if !strings.Contains(hcl, want) {
			t.Errorf("missing %s:\n%s", want, hcl)
		}
	}
	if strings.Contains(hcl, "ignored") {
		t.Errorf("a tag in name wins, as in Ansible:\n%s", hcl)
	}
	if res.Converted != 8 || len(res.Review) != 0 {
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
		"docker_image: { name: app, source: build, build: { path: . } }":                               "builds the image",
		"docker_image: { name: app, source: local }":                                                   "source: local",
		"docker_image: { name: nginx, state: absent }":                                                 `state "absent"`,
		"docker_image: { name: nginx, force_source: yes }":                                             "sets force_source",
		"podman_image: { name: nginx, pull: no }":                                                      "pull: false",
		"podman_image: { name: app, build: { file: Containerfile } }":                                  "builds the image",
		"docker_network: { name: app, ipam_config: [{ subnet: 10.1.0.0/24 }, { subnet: fd00::/64 }] }": "2 entries",
		"docker_network: { name: app, ipam_config: [{ subnet: 10.1.0.0/24, gateway: 10.1.0.1 }] }":     "ipam_config gateway",
		"docker_network: { name: app, driver: overlay, scope: swarm }":                                 "Swarm",
		"docker_network: { name: app, internal: yes }":                                                 "sets internal",
		"docker_network: { name: app, ipam_config: [{ subnet: 10.1.0.1/24 }] }":                        "must be written 10.1.0.0/24",
		"podman_network: { name: app, gateway: 10.1.0.1 }":                                             "sets gateway",
		"docker_volume: { name: data, driver_options: { type: nfs } }":                                 "sets driver_options",
		"podman_volume: { name: data, state: absent }":                                                 `state "absent"`,
	} {
		res := convertString(t, "- hosts: app\n  tasks:\n    - "+task+"\n")
		if res.Converted != 0 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, want) {
			t.Errorf("%s: converted %d, review %+v, want %q", task, res.Converted, res.Review, want)
		}
	}
}

// user, labels, memory, cpus and log options map to the step's arguments
// under both modules' names; privileged stays for review (#1352).
func TestConvertContainerOptions(t *testing.T) {
	res := convertString(t, `- hosts: app
  tasks:
    - name: Run the app
      community.docker.docker_container:
        name: app
        image: ghcr.io/example/app:1.4
        user: "1000:1000"
        labels: {traefik.enable: "true"}
        memory: 512m
        cpus: 1.5
        log_driver: json-file
        log_options: {max-size: 10m}
    - containers.podman.podman_container:
        name: worker
        image: ghcr.io/example/worker:2.4.1
        label: {app: worker}
        cpus: "2"
        memory: "0"
        log_driver: k8s-file
        log_opt: {max_size: 5mb, path: /var/log/worker.json}
`)
	hcl := string(res.HCL)
	for _, want := range []string{`user       = "1000:1000"`, `memory     = "512m"`, "cpus       = 1.5", `log_driver = "json-file"`, `"traefik.enable" = "true"`, `max-size = "10m"`,
		`app = "worker"`, "cpus       = 2", `log_driver = "k8s-file"`, `max-size = "5mb"`, `path     = "/var/log/worker.json"`} {
		if !strings.Contains(hcl, want) {
			t.Errorf("missing %s:\n%s", want, hcl)
		}
	}
	if strings.Count(hcl, "memory") != 1 || strings.Contains(hcl, "max_size") {
		t.Errorf("memory 0 is no limit, and podman's max_size is max-size:\n%s", hcl)
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
		"docker_container: { name: web, image: nginx, privileged: yes }":                           "privileged",
		"docker_container: { name: web, image: nginx, memory: lots }":                              `memory "lots" must be a size`,
		"podman_container: { name: web, image: nginx, cpus: many }":                                `sets cpus "many", which isn't a number`,
		"docker_container: { name: web, image: nginx, user: 'root; id' }":                          "user",
		"docker_container: { name: web, image: nginx, labels: { 'a b': c } }":                      `labels key "a b"`,
		"docker_container: { name: web, image: nginx, labels: { a: [b] } }":                        "sets labels a to something other than one value",
		"docker_container: { name: web, image: nginx, log_options: { max-size: 10m } }":            "log_options needs log_driver",
		"podman_container: { name: web, image: nginx, log_driver: k8s-file, log_opt: { x: [1] } }": "sets log_opt x",
	} {
		res := convertString(t, "- hosts: app\n  tasks:\n    - "+task+"\n")
		if res.Converted != 0 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, want) {
			t.Errorf("%s: converted %d, review %+v, want %q", task, res.Converted, res.Review, want)
		}
	}
}
