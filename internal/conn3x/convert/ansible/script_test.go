// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// script becomes a command step that gets the script on stdin, saves it,
// runs it under the interpreter Ansible's would and deletes it. Another
// interpreter, no guard and a vaulted script stay for review (#1346).
func TestConvertScript(t *testing.T) {
	const sh, bash, py = "#!/bin/sh\necho hi\n", "#!/usr/bin/env bash\necho hi\n", "#!/usr/bin/python3\nprint(1)\n"
	run := func(interp string) string {
		return `command  = "conn3x_script=$(mktemp) && cat >\"$conn3x_script\" && ` + interp
	}
	for _, c := range []struct {
		task, script, review string
		want                 []string
	}{
		{task: "ansible.builtin.script: files/setup.sh --prefix /opt/app\n      args: { creates: /opt/app/bin/app }", script: sh,
			want: []string{"command {", run(`'/bin/sh' \"$conn3x_script\" --prefix /opt/app </dev/null; rc=$?; rm -f \"$conn3x_script\"; exit $rc"`),
				`creates  = "/opt/app/bin/app"`, `stdin_wo = file("${path.module}/files/setup.sh")`, "keeps only its HMAC in state"}},
		{task: "script: { cmd: setup.sh --prefix /opt/app, removes: /opt/old }", script: sh,
			want: []string{run(`'/bin/sh' \"$conn3x_script\" --prefix /opt/app </dev/null`), `removes  = "/opt/old"`}},
		{task: "script: { cmd: setup.sh, executable: /bin/bash, creates: /x }", script: "echo hi\n",
			want: []string{run(`'/bin/bash' \"$conn3x_script\" </dev/null`)}},
		{task: "script: { cmd: setup.sh, creates: /x }", script: bash,
			want: []string{run(`'/usr/bin/env' 'bash' \"$conn3x_script\" </dev/null`)}},
		{task: "script: { cmd: setup.sh, creates: /x }", script: "#!/bin/bash -e\necho hi\n",
			want: []string{run(`'/bin/bash' '-e' \"$conn3x_script\" </dev/null`)}},
		{task: "script: { cmd: setup.sh, chdir: /opt/src, creates: /x }", script: sh,
			want: []string{run(`cd '/opt/src' && '/bin/sh' \"$conn3x_script\" </dev/null`)}},
		{task: "script: { cmd: setup.sh, creates: /x }", script: py, review: `runs a script with "#!/usr/bin/python3"`},
		{task: "script: { cmd: setup.sh, executable: python3, creates: /x }", script: sh, review: "runs the script with executable python3"},
		{task: "script: { cmd: setup.sh, creates: /x }", script: "echo hi\n", review: "no #! line"},
		{task: "script: { cmd: setup.sh, creates: /x }", script: "$ANSIBLE_VAULT;1.1;AES256\n6162\n", review: "encrypted with Ansible Vault"},
		{task: "script: setup.sh", script: sh, review: "runs on every play"},
		{task: "script: setup.sh creates=/x", script: sh, review: "sets creates inside the script line"},
		{task: "script: { cmd: missing.sh, creates: /x }", script: sh, review: "missing.sh was not found"},
		{task: "script: { cmd: setup.sh, creates: '/opt/*.done' }", script: sh, review: "creates is a glob pattern"},
	} {
		dir := t.TempDir()
		if err := os.MkdirAll(filepath.Join(dir, "files"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "files", "setup.sh"), []byte(c.script), 0o644); err != nil {
			t.Fatal(err)
		}
		play := filepath.Join(dir, "site.yml")
		if err := os.WriteFile(play, []byte("- hosts: all\n  tasks:\n    - "+c.task+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		res, err := Convert(play)
		if err != nil {
			t.Fatal(err)
		}
		hcl := string(res.HCL)
		if c.review != "" {
			if res.Converted != 0 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, c.review) {
				t.Errorf("%s: converted %d, review %+v, want review %q", c.task, res.Converted, res.Review, c.review)
			}
			continue
		}
		if res.Converted != 1 || len(res.Review) != 0 {
			t.Errorf("%s: converted %d, review %+v:\n%s", c.task, res.Converted, res.Review, hcl)
			continue
		}
		for _, w := range c.want {
			if !strings.Contains(hcl, w) {
				t.Errorf("%s: missing %q in:\n%s", c.task, w, hcl)
			}
		}
	}
}

// A role's script is copied into the circuit's files/.
func TestRoleScript(t *testing.T) {
	res, err := ConvertRole(writeRole(t, map[string]string{
		"tasks/main.yml":    "- name: Run the installer\n  script: setup.sh\n  args: { creates: /opt/app/bin/app }\n",
		"files/setup.sh":    "#!/bin/sh\necho hi\n",
		"meta/main.yml":     "galaxy_info: {}\n",
		"defaults/main.yml": "{}\n",
	}))
	if err != nil {
		t.Fatal(err)
	}
	hcl := string(res.Files["main.circuit.hcl"])
	if res.Converted != 1 || len(res.Review) != 0 || !strings.Contains(hcl, `stdin_wo = file("${path.module}/files/setup.sh")`) {
		t.Fatalf("converted %d, review %+v:\n%s", res.Converted, res.Review, hcl)
	}
	if got := string(res.Files["files/setup.sh"]); got != "#!/bin/sh\necho hi\n" {
		t.Errorf("files/setup.sh in the circuit is %q", got)
	}
}
