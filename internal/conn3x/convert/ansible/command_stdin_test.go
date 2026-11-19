// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"
)

// stdin becomes stdin_wo, with the newline Ansible adds unless
// stdin_add_newline is false.
func TestConvertCommandStdin(t *testing.T) {
	for task, want := range map[string]string{
		"command: { cmd: cat, stdin: hello, creates: /tmp/z }":                        `stdin_wo = "hello\n"`,
		"command: { cmd: cat, stdin: hello, stdin_add_newline: no, creates: /tmp/z }": `stdin_wo = "hello"`,
		"shell: { cmd: 'cat > /tmp/x', stdin: 'a b', creates: /tmp/x }":               `stdin_wo = "a b\n"`,
	} {
		res := convertString(t, "- hosts: all\n  tasks:\n    - "+task+"\n")
		if res.Converted != 1 || !strings.Contains(string(res.HCL), want) {
			t.Errorf("%s: converted %d, want %s in:\n%s", task, res.Converted, want, res.HCL)
		}
	}
	res := convertString(t, "- hosts: all\n  tasks:\n    - command: { cmd: cat, stdin: '', stdin_add_newline: no, creates: /tmp/z }\n")
	if res.Converted != 0 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, "empty stdin") {
		t.Errorf("empty stdin: converted %d, review %+v", res.Converted, res.Review)
	}
}
