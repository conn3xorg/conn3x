// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"
)

// search_regex with path becomes contains; with port, or a pattern Go might
// read differently, it stays for review.
func TestConvertWaitForSearchRegex(t *testing.T) {
	res := convertString(t, "- hosts: all\n  tasks:\n    - wait_for: {path: /var/log/app.log, search_regex: started}\n")
	if res.Converted != 1 || !strings.Contains(string(res.HCL), `contains = "started"`) {
		t.Errorf("converted %d:\n%s", res.Converted, res.HCL)
	}
	for task, reason := range map[string]string{
		"wait_for: {port: 22, search_regex: OpenSSH}":            "on a port",
		`wait_for: {path: /x, search_regex: '(?P<v>\d+) ready'}`: "regexp using",
	} {
		res := convertString(t, "- hosts: all\n  tasks:\n    - "+task+"\n")
		if res.Converted != 0 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, reason) {
			t.Errorf("%s: converted %d, review %+v", task, res.Converted, res.Review)
		}
	}
}
