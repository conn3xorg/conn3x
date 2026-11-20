// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"
)

func TestConvertWinLineinfile(t *testing.T) {
	for task, want := range map[string][]string{
		`community.windows.win_lineinfile: {path: 'C:\App\app.ini', regex: '^port=', line: 'port=8080'}`: {
			"windows_line {", `path   = "C:\\App\\app.ini"`, `line   = "port=8080"`, `regexp = "^port="`, "keeps the endings the file has",
		},
		`win_lineinfile: {dest: 'C:\App\app.ini', line: 'debug=0', insertbefore: '^\[server\]', create: true, newline: windows, encoding: auto}`: {
			`path          = "C:\\App\\app.ini"`, `insert_before = "^\\[server\\]"`, "create        = true",
		},
		`community.windows.win_lineinfile: {path: 'C:\App\app.ini', regex: '^debug=', state: absent}`: {`state  = "absent"`},
	} {
		res := convertString(t, "- hosts: all\n  tasks:\n    - "+task+"\n")
		for _, w := range want {
			if res.Converted != 1 || !strings.Contains(string(res.HCL), w) {
				t.Errorf("%s: converted %d, want %s in:\n%s", task, res.Converted, w, res.HCL)
			}
		}
	}
	for task, reason := range map[string]string{
		`community.windows.win_lineinfile: {path: 'C:\a.ini', line: x, newline: unix}`:            "rewrites every line ending",
		`community.windows.win_lineinfile: {path: 'C:\a.ini', line: x, encoding: utf-16-be}`:      "sets encoding",
		`community.windows.win_lineinfile: {path: 'C:\a.ini', line: x, backup: true}`:             "sets backup",
		`community.windows.win_lineinfile: {path: 'C:\a.ini', line: x, validate: 'check.exe %s'}`: "sets validate",
	} {
		res := convertString(t, "- hosts: all\n  tasks:\n    - "+task+"\n")
		if res.Converted != 0 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, reason) {
			t.Errorf("%s: converted %d, review %+v", task, res.Converted, res.Review)
		}
	}
}
