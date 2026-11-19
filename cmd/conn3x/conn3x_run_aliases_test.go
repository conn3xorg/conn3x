// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/conn3x/convert/ansible"
)

// Older and generated inventories use ansible_ssh_host, ansible_ssh_port,
// ansible_ssh_user and ansible_private_key_file. run reads them as Ansible's
// ssh plugin does: each alone, and when both names of a pair are set, the
// later one in the plugin's vars list wins.
func TestRunAnsibleSSHAliases(t *testing.T) {
	// What the inventory reader leaves for a vault-encrypted value.
	const vaulted = "{{ encrypted with Ansible Vault }}"
	if !ansible.Encrypted(vaulted) {
		t.Fatal("the inventory's mark for an encrypted value changed")
	}
	for _, c := range []struct {
		vars map[string]string
		key  string
		want cty.Value
	}{
		{map[string]string{"ansible_ssh_host": "10.0.0.5"}, "host", cty.StringVal("10.0.0.5")},
		{map[string]string{"ansible_ssh_port": "2299"}, "port", cty.NumberIntVal(2299)},
		{map[string]string{"ansible_ssh_user": "deploy"}, "user", cty.StringVal("deploy")},
		{map[string]string{"ansible_private_key_file": "/k"}, "private_key_file", cty.StringVal("/k")},
		{map[string]string{"ansible_host": "a", "ansible_ssh_host": "b"}, "host", cty.StringVal("b")},
		{map[string]string{"ansible_port": "22", "ansible_ssh_port": "2299"}, "port", cty.NumberIntVal(2299)},
		{map[string]string{"ansible_user": "a", "ansible_ssh_user": "b"}, "user", cty.StringVal("b")},
		{map[string]string{"ansible_private_key_file": "/a", "ansible_ssh_private_key_file": "/b"}, "private_key_file", cty.StringVal("/b")},
		// An encrypted later value counts as unset, so the other name is used.
		{map[string]string{"ansible_user": "a", "ansible_ssh_user": vaulted}, "user", cty.StringVal("a")},
	} {
		got, ok := (runOptions{}).sshFor("web1", c.vars)[c.key]
		if !ok || !got.RawEquals(c.want) {
			t.Errorf("%v: %s = %#v, want %#v", c.vars, c.key, got, c.want)
		}
	}
	// A flag still fills in what neither name sets.
	if got := (runOptions{user: "flag"}).sshFor("web1", map[string]string{"ansible_ssh_host": "h"})["user"]; !got.RawEquals(cty.StringVal("flag")) {
		t.Errorf("-user with no inventory user: %#v", got)
	}
}
