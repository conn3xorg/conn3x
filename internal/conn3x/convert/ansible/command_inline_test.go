// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"
)

// Ansible's parse_kv pulls creates=, removes=, chdir= and the other command
// options out of a free-form command or shell line; every other word, k=v
// or not, stays in the command.
func TestConvertCommandInlineArgs(t *testing.T) {
	for _, tc := range []struct {
		task, review string
		want         []string
	}{
		{task: "command: make install creates=/usr/local/bin/x", want: []string{`command = "make install"`, `creates = "/usr/local/bin/x"`}},
		{task: "command: make install chdir=/src\n      args: { creates: /x }", want: []string{`command = "cd '/src' && make install"`, `creates = "/x"`}},
		{task: "command: make install creates=/usr/local/bin/x chdir=/src", want: []string{`command = "cd '/src' && make install"`, `creates = "/usr/local/bin/x"`}},
		{task: "ansible.builtin.command: tar xf a.tgz chdir=/opt removes=/opt/a.tgz", want: []string{`command = "cd '/opt' && tar xf a.tgz"`, `removes = "/opt/a.tgz"`}},
		{task: "shell: echo a=b creates=/x", want: []string{`command = "echo a=b"`, `creates = "/x"`}},
		{task: `shell: echo "creates=/y" > /x creates=/x`, want: []string{`command = "echo \"creates=/y\" > /x"`, `creates = "/x"`}},
		{task: `ansible.builtin.shell: make creates="/opt/my app/x" chdir='/src dir'`, want: []string{`command = "cd '/src dir' && make"`, `creates = "/opt/my app/x"`}},
		{task: "shell: '{{ join }} creates={{ conf }}'", want: []string{`command = "kubeadm join"`, `creates = "/etc/k.conf"`}},
		{task: "shell: \"make\\ncreates=/x\\nmake install\"", want: []string{`command = "make\nmake install"`}},
		{task: "shell: true creates=/x executable=/bin/bash", want: []string{`command = "'/bin/bash' -c 'true'"`}},
		{task: "command: make creates=~/out", review: "uses a path under ~"},
		{task: "command: make creates=/x/*", review: "creates is a glob pattern"},
		{task: "command: ls | wc creates=/x", review: "uses characters a shell reads"},
		{task: "command: make creates=/x strip_empty_ends=no", review: "strip_empty_ends"},
		{task: "command: \"make\\tcreates=/x\"", review: "sets creates inside the command line"},
	} {
		res := convertString(t, "- hosts: all\n  vars: { join: kubeadm join, conf: /etc/k.conf }\n  tasks:\n    - name: t\n      "+tc.task+"\n")
		if tc.review != "" {
			if res.Converted != 0 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, tc.review) {
				t.Errorf("%s: converted %d, review %+v, want %q", tc.task, res.Converted, res.Review, tc.review)
			}
			continue
		}
		if res.Converted != 1 {
			t.Errorf("%s: converted %d, review %+v", tc.task, res.Converted, res.Review)
			continue
		}
		for _, w := range tc.want {
			if !strings.Contains(string(res.HCL), w) {
				t.Errorf("%s: want %s in:\n%s", tc.task, w, res.HCL)
			}
		}
	}
}
