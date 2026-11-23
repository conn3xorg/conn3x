// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hashicorp/hcl/v2/hclparse"
)

// convertWithRepomdKey converts tasks beside files/shells.key, the key
// zypper imports with auto_import_keys, saved under the repository's name.
func convertWithRepomdKey(t *testing.T, tasks string) Result {
	t.Helper()
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "files"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "files", "shells.key"), []byte(armoredKey), 0o644); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "play.yml")
	if err := os.WriteFile(path, []byte("- hosts: all\n  tasks:\n"+tasks), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := Convert(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, diags := hclparse.NewParser().ParseHCL(res.HCL, "play.tf"); diags.HasErrors() {
		t.Fatalf("output is not valid HCL: %s\n%s", diags, res.HCL)
	}
	return res
}

// zypper_repository becomes a repository step only when zypper would have
// imported the repository's own key, and the step would do no more.
func TestConvertZypperRepository(t *testing.T) {
	const obs = "name: shells, repo: 'https://download.opensuse.org/repositories/shells/15.6/', auto_import_keys: true"
	for task, wants := range map[string][]string{
		"community.general.zypper_repository: {" + obs + "}": {
			`name = "shells"`, `url  = "https://download.opensuse.org/repositories/shells/15.6/"`,
			`key  = file("${path.module}/files/shells.key")`, "shells/15.6/repodata/repomd.xml.key",
		},
		"zypper_repository: {" + obs + ", description: Shells, enabled: true, autorefresh: true, priority: 90, runrefresh: true, disable_gpg_check: false}": {
			"priority = 90", "description dropped",
		},
		"zypper_repository: {" + obs + ", runrefresh: false, refresh: yes}": {`name = "shells"`},
	} {
		res := convertWithRepomdKey(t, "    - "+task+"\n")
		if res.Converted != 1 || len(res.Review) != 0 {
			t.Errorf("%q: converted %d, review %+v", task, res.Converted, res.Review)
			continue
		}
		for _, want := range wants {
			if !strings.Contains(string(res.HCL), want) {
				t.Errorf("%q: output lacks %q:\n%s", task, want, res.HCL)
			}
		}
	}
	for reason, task := range map[string]string{
		"auto_import_keys":   "zypper_repository: {name: shells, repo: 'https://download.opensuse.org/repositories/shells/15.6/'}",
		"as files/x.key":     "zypper_repository: {name: x, repo: 'https://example.com/r', auto_import_keys: true}",
		".repo file":         "zypper_repository: {repo: 'https://example.com/x.repo', auto_import_keys: true}",
		"disable_gpg_check":  "zypper_repository: {" + obs + ", disable_gpg_check: true}",
		"enabled: no":        "zypper_repository: {" + obs + ", enabled: false}",
		"autorefresh: no":    "zypper_repository: {" + obs + ", autorefresh: false}",
		`state "absent"`:     "zypper_repository: {" + obs + ", state: absent}",
		"overwrite_multiple": "zypper_repository: {" + obs + ", overwrite_multiple: true}",
		"remove_others":      "zypper_repository: {" + obs + ", remove_others: true}",
		"below 1":            "zypper_repository: {" + obs + ", priority: 0}",
		"must be an http":    "zypper_repository: {name: shells, repo: 'obs://shells/15.6', auto_import_keys: true}",
	} {
		res := convertWithRepomdKey(t, "    - "+task+"\n")
		if res.Converted != 0 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, reason) {
			t.Errorf("%q: converted %d, review %+v", task, res.Converted, res.Review)
		}
	}
	loop := "    - zypper_repository: {name: '{{ item }}', repo: 'https://example.com/{{ item }}', auto_import_keys: true}\n      loop: [a, b]\n"
	if res := convertWithRepomdKey(t, loop); res.Converted != 0 || !strings.Contains(reasons(res), "loops") {
		t.Errorf("loop: converted %d, review %q", res.Converted, reasons(res))
	}
}
