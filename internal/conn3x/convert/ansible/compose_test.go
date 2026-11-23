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

func TestConvertCompose(t *testing.T) {
	res := convertString(t, `- hosts: app
  tasks:
    - community.docker.docker_compose_v2:
        project_src: /opt/app
        project_name: app
        files: [compose.yaml, compose.prod.yaml]
        env_files: [prod.env]
        profiles: [admin]
        remove_orphans: true
        pull: always
        wait: true
        recreate: auto
        build: policy
        remove_volumes: false
    - community.docker.docker_compose_v2: { project_src: /srv/tools, services: [adminer], state: stopped }
    - community.docker.docker_compose_v2: { project_src: /srv/old, state: absent }
`)
	hcl := string(res.HCL)
	for _, want := range []string{
		"compose_project {", `project_dir    = "/opt/app"`, `project_name   = "app"`, `files          = ["compose.yaml", "compose.prod.yaml"]`,
		`env_files      = ["prod.env"]`, `profiles       = ["admin"]`, `pull           = "always"`, `remove_orphans = true`, `wait           = true`,
		`services    = ["adminer"]`, `state       = "stopped"`, `state       = "absent"`, `engine         = "docker"`,
	} {
		if !strings.Contains(hcl, want) {
			t.Errorf("missing %s:\n%s", want, hcl)
		}
	}
	if strings.Contains(hcl, "recreate") || strings.Contains(hcl, "build") {
		t.Errorf("the defaults should be dropped:\n%s", hcl)
	}
	if res.Converted != 3 || len(res.Review) != 0 {
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
		"docker_compose_v2: { project_src: /opt/app, state: restarted }":                            "action rather than a state",
		"docker_compose_v2: { project_name: app, definition: { services: { web: { image: x } } } }": "temporary directory",
		"docker_compose_v2: { project_src: /opt/app, build: always }":                               "sets build: always",
		"docker_compose_v2: { project_src: /opt/app, recreate: always }":                            "sets recreate: always",
		"docker_compose_v2: { project_src: /opt/app, dependencies: false }":                         "dependencies: false",
		"docker_compose_v2: { project_src: /opt/app, state: absent, remove_volumes: true }":         "never removes volumes",
		"docker_compose_v2: { project_src: /opt/app, scale: { web: 2 } }":                           "scale",
		"docker_compose_v2: { project_src: /opt/app, remove_images: all, state: absent }":           "remove_images",
		"docker_compose_v2: { project_src: /opt/app, timeout: 30 }":                                 "timeout",
		"docker_compose_v2: { project_src: app }":                                                   "absolute path",
		"docker_compose_v2: { project_src: /opt/app, project_name: App }":                           "lowercase",
		"docker_compose_v2: { project_src: /opt/app, pull: sometimes }":                             "pull",
		"docker_compose_v2: { files: [compose.yaml] }":                                              "project_src",
	} {
		res := convertString(t, "- hosts: app\n  tasks:\n    - "+task+"\n")
		if res.Converted != 0 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, want) {
			t.Errorf("%s: converted %d, review %+v, want %q", task, res.Converted, res.Review, want)
		}
	}
}
