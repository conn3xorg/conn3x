// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"
)

func TestConvertWinChocolatey(t *testing.T) {
	for task, want := range map[string][]string{
		`chocolatey.chocolatey.win_chocolatey: {name: git, version: 2.44.0, source: 'https://nuget.example.com/v3/index.json', pinned: yes}`: {
			"windows_choco_package {", `name    = "git"`, `version = "2.44.0"`, `source  = "https://nuget.example.com/v3/index.json"`, "pinned  = true",
		},
		`win_chocolatey: {name: [git, 7zip]}`:                            {`name = "git"`, `name = "7zip"`, `step "win_chocolatey_git"`, `step "win_chocolatey_n_7zip"`},
		`win_chocolatey: {name: git, state: absent}`:                     {`state = "absent"`},
		`win_chocolatey: {name: git, version: 2.40.0, state: downgrade}`: {`version = "2.40.0"`},
	} {
		res := convertString(t, "- hosts: all\n  tasks:\n    - "+task+"\n")
		hcl := string(res.HCL)
		if res.Converted != 1 {
			t.Errorf("%s: converted %d, review %+v:\n%s", task, res.Converted, res.Review, hcl)
			continue
		}
		for _, w := range want {
			if !strings.Contains(hcl, w) {
				t.Errorf("%s: no %q in:\n%s", task, w, hcl)
			}
		}
	}
	for task, reason := range map[string]string{
		`win_chocolatey: {name: git, state: latest}`:            "follows the feed",
		`win_chocolatey: {name: git, state: upgrade}`:           "follows the feed",
		`win_chocolatey: {name: git, state: downgrade}`:         "without a version",
		`win_chocolatey: {name: git, state: reinstalled}`:       `state "reinstalled"`,
		`win_chocolatey: {name: git, install_args: /quiet}`:     "install_args",
		`win_chocolatey: {name: git, package_params: /NoShell}`: "package_params",
		`win_chocolatey: {name: git, source_username: u}`:       "source_username",
		`win_chocolatey: {state: present}`:                      "has no name",
	} {
		res := convertString(t, "- hosts: all\n  tasks:\n    - "+task+"\n")
		if res.Converted != 0 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, reason) {
			t.Errorf("%s: converted %d, review %+v", task, res.Converted, res.Review)
		}
	}
}
