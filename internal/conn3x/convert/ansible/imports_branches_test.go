// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"path/filepath"
	"strings"
	"testing"
)

// convertDir converts play.yml among files, all written to one directory.
func convertDir(t *testing.T, files map[string]string) Result {
	t.Helper()
	res, err := Convert(filepath.Join(writeRole(t, files), "play.yml"))
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func reasons(res Result) string {
	var out []string
	for _, r := range res.Review {
		out = append(out, r.Reason)
	}
	return strings.Join(out, "\n")
}

func TestImportsLeftForReview(t *testing.T) {
	dir := t.TempDir()
	abs := filepath.Join(dir, "abs.yml")
	writeFile(t, abs, "- copy: { dest: /abs, content: x }\n")
	for name, c := range map[string]struct {
		tasks string
		files map[string]string
		want  string
	}{
		"import_role":      {"- import_role: { name: web }", nil, "uses import_role, which runs another role here"},
		"include_role":     {"- include_role: { name: web }", nil, "uses include_role"},
		"Jinja file":       {"- import_tasks: '{{ f }}.yml'", nil, "names the file to import with a Jinja expression"},
		"no single file":   {"- import_tasks: { file: x.yml, other: y }", nil, "has an import_tasks without a single file to read"},
		"not a list":       {"- import_tasks: x.yml", map[string]string{"x.yml": "a: b\n"}, "imports x.yml, which isn't a list of tasks"},
		"bad YAML":         {"- import_tasks: x.yml", map[string]string{"x.yml": "- [\n"}, "imports x.yml, which can't be read as YAML"},
		"never block":      {"- block:\n        - copy: { dest: /a, content: x }\n      tags: [never]", nil, neverReason},
		"never import":     {"- import_tasks: x.yml\n      tags: never", map[string]string{"x.yml": "- copy: { dest: /a, content: x }\n"}, neverReason},
		"when, missing":    {"- import_tasks: gone.yml\n      when: ansible_os_family == 'Debian'", nil, "imports gone.yml, which wasn't found"},
		"when, a role":     {"- import_tasks: x.yml\n      when: x", map[string]string{"x.yml": "- import_role: { name: web }\n"}, "calls a role from a file imported with a when"},
		"when, unreadable": {"- import_tasks: x.yml\n      when: [{ a: b }]", map[string]string{"x.yml": "- copy: { dest: /a, content: x }\n"}, "is imported with a when the converter can't read"},
		"when, refused":    {"- import_tasks: x.yml\n      when: x", map[string]string{"x.yml": "- import_tasks: gone.yml\n"}, "imports gone.yml, which wasn't found beside x.yml"},
		"dynamic include":  {"- include_tasks: '{{ f }}.yml'", nil, "uses include_tasks, which Ansible reads only when the play reaches it"},
	} {
		files := map[string]string{"play.yml": "- hosts: all\n  tasks:\n    " + c.tasks + "\n"}
		for k, v := range c.files {
			files[k] = v
		}
		res := convertDir(t, files)
		if res.Converted != 0 || !strings.Contains(reasons(res), c.want) {
			t.Errorf("%s: converted %d, review:\n%s\nwant %q", name, res.Converted, reasons(res), c.want)
		}
	}

	// The old include, an absolute path and an empty file read as an import does.
	res := convertDir(t, map[string]string{
		"play.yml":  "- hosts: all\n  tasks:\n    - include: x.yml\n    - import_tasks: " + abs + "\n    - import_tasks: empty.yml\n",
		"x.yml":     "- copy: { dest: /x, content: x }\n",
		"empty.yml": "",
	})
	if res.Converted != 2 || len(res.Review) != 0 || !strings.Contains(string(res.HCL), `"/abs"`) || !strings.Contains(string(res.HCL), `"/x"`) {
		t.Errorf("converted %d, review %+v:\n%s", res.Converted, res.Review, res.HCL)
	}
}
