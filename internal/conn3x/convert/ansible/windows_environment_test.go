// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"
)

func TestConvertWinEnvironment(t *testing.T) {
	for _, tc := range []struct {
		name, task string
		steps      int      // converted steps; 0 means the task stays for review
		want       []string // in the HCL, or in the review reason
		not        []string
	}{
		{
			name:  "issue task",
			task:  "ansible.windows.win_environment: {name: FOO, value: bar, level: machine, state: present}",
			steps: 1,
			want:  []string{"windows_environment {", `name  = "FOO"`, `value = "bar"`, `level = "machine"`},
			not:   []string{"state", "Review:"},
		},
		{
			name:  "state absent",
			task:  "win_environment: {name: FOO, level: machine, state: absent}",
			steps: 1,
			want:  []string{`state = "absent"`},
			not:   []string{"value"},
		},
		{
			name:  "no state and no value removes",
			task:  "win_environment: {name: FOO, level: machine}",
			steps: 1,
			want:  []string{`state = "absent"`},
		},
		{
			name:  "level user",
			task:  "win_environment: {name: FOO, value: bar, level: user}",
			steps: 1,
			want:  []string{`level = "user"`, "the become user under become"},
		},
		{
			name: "level user under become_user stays",
			task: "win_environment: {name: FOO, value: bar, level: user}\n      become_user: svc",
			want: []string{"become_user"},
		},
		{
			name: "level process stays",
			task: "win_environment: {name: FOO, value: bar, level: process}",
			want: []string{"level: process", "nothing for a step to keep"},
		},
		{
			name:  "variables",
			task:  "win_environment: {level: machine, variables: {JAVA_HOME: 'C:\\jdk', OLD_VAR: ''}}",
			steps: 2,
			want:  []string{`step "env_java_home"`, `value = "C:\\jdk"`, `step "env_old_var"`, `state = "absent"`},
		},
		{
			name: "variables with state",
			task: "win_environment: {level: machine, state: present, variables: {A: b}}",
			want: []string{"which Ansible refuses"},
		},
		{
			name:  "templated value",
			task:  "win_environment: {name: APP_HOME, value: '{{ app_dir }}\\bin', level: machine}",
			steps: 1,
			want:  []string{`value = "C:\\app\\bin"`},
		},
		{
			name: "templated key stays",
			task: "win_environment: {level: machine, variables: {'{{ other_name }}': x}}",
			want: []string{"builds a variable's name from a template"},
		},
		{
			name:  "templated key from a play var",
			task:  "win_environment: {level: machine, variables: {'{{ env_name }}': x, B: y}}",
			steps: 2,
			want:  []string{`name  = "APP_ENV"`},
			not:   []string{"{{"},
		},
		{
			name: "templated name stays",
			task: "win_environment: {name: '{{ other_name }}', value: x, level: machine}",
			want: []string{"builds a variable's name from a template"},
		},
		{
			name: "Path",
			task: "win_environment: {name: Path, value: 'C:\\x', level: machine}",
			want: []string{"windows_path"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := convertString(t, "- hosts: all\n  vars:\n    app_dir: 'C:\\app'\n    env_name: APP_ENV\n  tasks:\n    - name: env\n      "+tc.task+"\n")
			got := string(res.HCL)
			if tc.steps == 0 {
				if res.Converted != 0 || len(res.Review) != 1 {
					t.Fatalf("converted %d, review %+v", res.Converted, res.Review)
				}
				got = res.Review[0].Reason
			} else if res.Converted != 1 || len(res.Review) != 0 || strings.Count(got, "windows_environment {") != tc.steps {
				t.Fatalf("converted %d, review %+v:\n%s", res.Converted, res.Review, got)
			}
			for _, w := range tc.want {
				if !strings.Contains(got, w) {
					t.Errorf("missing %q in:\n%s", w, got)
				}
			}
			for _, n := range tc.not {
				if strings.Contains(got, n) {
					t.Errorf("unexpected %q in:\n%s", n, got)
				}
			}
		})
	}
}

// A play's become_user changes whose HKCU Ansible writes, not HKLM.
func TestConvertWinEnvironmentBecomeUser(t *testing.T) {
	res := convertString(t, "- hosts: all\n  become: true\n  become_user: svc\n  tasks:\n"+
		"    - win_environment: {name: A, value: b, level: machine}\n"+
		"    - win_environment: {name: A, value: b, level: user}\n")
	if res.Converted != 1 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, "become_user") {
		t.Fatalf("converted %d, review %+v:\n%s", res.Converted, res.Review, res.HCL)
	}
}
