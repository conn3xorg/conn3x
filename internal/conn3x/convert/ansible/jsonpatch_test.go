// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"
)

func TestConvertJSONPatchChain(t *testing.T) {
	chain := func(patches string) string {
		return "- hosts: all\n  tasks:\n" +
			"    - name: read config\n      ansible.builtin.slurp:\n        src: /etc/app.json\n      register: app\n" +
			"    - name: edit config\n      ansible.builtin.copy:\n        dest: /etc/app.json\n" +
			"        content: \"{{ app.content | b64decode | from_json" + patches + " | to_nice_json(indent=2) }}\"\n"
	}
	res := convertString(t, chain(
		" | community.general.json_patch('add', '/server/port', 9090)"+
			" | community.general.json_patch('replace', '/upstreams/0/host', '10.0.0.5')"+
			" | community.general.json_patch('add', '/features', {'beta': true, 'tags': ['a', 'b'], 'none': None})"+
			" | community.general.json_patch('remove', '/debug')"+
			" | json_patch('add', '/a~1b', 1)"))
	if res.Converted != 2 || len(res.Review) != 0 {
		t.Fatalf("converted %d, review %+v", res.Converted, res.Review)
	}
	hcl := string(res.HCL)
	for _, w := range []string{
		`reads /etc/app.json for the next task`,
		`step "edit_config_server_port"`, `= "server.port"`, `= jsonencode(9090)`,
		`= "upstreams[0].host"`, `= jsonencode("10.0.0.5")`,
		`= "features"`, `beta = true`, `tags = ["a", "b"]`, `none = null`,
		`= "debug"`, `state = "absent"`,
		`= "a/b"`,
	} {
		if !strings.Contains(hcl, w) {
			t.Errorf("missing %s:\n%s", w, hcl)
		}
	}
	if strings.Count(hcl, "json_value {") != 5 {
		t.Errorf("want 5 json_value steps:\n%s", hcl)
	}

	for patch, reason := range map[string]string{
		" | community.general.json_patch('add', '/items/-', 4)":            "append",
		" | community.general.json_patch('add', '/items/1', 4)":            "inserts",
		" | community.general.json_patch('move', '/a', from='/b')":         "arguments",
		" | community.general.json_patch('copy', '/a', '/b')":              `"copy" operation`,
		" | community.general.json_patch('add', '/port', app_port)":        "set it by hand",
		" | community.general.json_patch('add', '/a.b', 1)":                "dot or a bracket",
		" | community.general.json_patch('add', '', 1)":                    "isn't a key",
		" | community.general.json_patch('add', '/port', 1) | combine({})": "more than to_json",
	} {
		res := convertString(t, chain(patch))
		if res.Converted != 0 || len(res.Review) != 2 {
			t.Errorf("%s: converted %d, review %+v", patch, res.Converted, res.Review)
			continue
		}
		if !strings.Contains(res.Review[1].Reason, reason) {
			t.Errorf("%s: reason %q, want %q", patch, res.Review[1].Reason, reason)
		}
	}

	// A copy of another file, or another variable, isn't the chain.
	other := strings.Replace(chain(" | community.general.json_patch('add', '/port', 1)"), "dest: /etc/app.json", "dest: /etc/other.json", 1)
	if res := convertString(t, other); res.Converted != 0 || strings.Contains(string(res.HCL), "json_value") {
		t.Errorf("converted a chain onto another file: %d\n%s", res.Converted, res.HCL)
	}
}
