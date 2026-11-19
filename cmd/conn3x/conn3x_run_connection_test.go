// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"testing"

	"github.com/zclconf/go-cty/cty"
)

// ansible_connection picks how conn3x run reaches a host.
func TestRunAnsibleConnection(t *testing.T) {
	o := runOptions{}
	for name, c := range map[string]struct {
		vars map[string]string
		want map[string]cty.Value
	}{
		"local": {map[string]string{"ansible_connection": "local"}, map[string]cty.Value{"controller": cty.True}},
		"docker, inventory name": {map[string]string{"ansible_connection": "community.docker.docker"},
			map[string]cty.Value{"container": cty.StringVal("web1"), "container_engine": cty.StringVal("docker")}},
		"docker host and user win": {map[string]string{"ansible_connection": "docker", "ansible_host": "a", "ansible_docker_host": "b", "ansible_user": "u", "ansible_docker_user": "app"},
			map[string]cty.Value{"container": cty.StringVal("b"), "user": cty.StringVal("app")}},
		"podman": {map[string]string{"ansible_connection": "containers.podman.podman", "ansible_host": "c1", "ansible_become": "yes"},
			map[string]cty.Value{"container": cty.StringVal("c1"), "container_engine": cty.StringVal("podman"), "become": cty.True}},
	} {
		got := o.sshFor("web1", c.vars)
		for k, v := range c.want {
			if !got[k].RawEquals(v) {
				t.Errorf("%s: %s = %#v, want %#v", name, k, got[k], v)
			}
		}
	}
	if _, err := connectionOf(map[string]string{"ansible_connection": "winrm"}); err == nil {
		t.Error("winrm accepted")
	}
	if c, err := connectionOf(map[string]string{"ansible_connection": "ssh"}); err != nil || c != "" {
		t.Errorf("ssh: %q %v", c, err)
	}
}
