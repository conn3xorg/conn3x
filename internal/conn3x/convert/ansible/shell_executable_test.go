// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"
)

// A shell task's executable runs the command, as Ansible's shell runs
// executable -c; /bin/sh and the command module's executable change nothing.
func TestConvertShellExecutable(t *testing.T) {
	for task, want := range map[string]string{
		"shell: { cmd: 'echo $0', executable: /bin/bash, creates: /tmp/y }":         `command = "'/bin/bash' -c 'echo $0'"`,
		"shell: { cmd: 'ls', executable: /bin/bash, chdir: /srv, creates: /tmp/y }": `command = "'/bin/bash' -c 'cd '\\''/srv'\\'' && ls'"`,
		"shell: { cmd: 'echo hi', executable: /bin/sh, creates: /tmp/y }":           `command = "echo hi"`,
		"command: { cmd: '/usr/bin/true', executable: /bin/bash, creates: /tmp/y }": `command = "/usr/bin/true"`,
	} {
		res := convertString(t, "- hosts: all\n  tasks:\n    - "+task+"\n")
		if res.Converted != 1 || !strings.Contains(string(res.HCL), want) {
			t.Errorf("%s: converted %d, want %s in:\n%s", task, res.Converted, want, res.HCL)
		}
	}
}
