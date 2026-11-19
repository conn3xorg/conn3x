// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"
)

// stopped and absent both wait the other way; drained stays for review.
func TestConvertWaitForAbsent(t *testing.T) {
	for _, task := range []string{"wait_for: {port: 8080, state: stopped}", "wait_for: {path: /run/lock, state: absent}"} {
		res := convertString(t, "- hosts: all\n  tasks:\n    - "+task+"\n")
		if res.Converted != 1 || !strings.Contains(string(res.HCL), `state = "absent"`) {
			t.Errorf("%s: converted %d:\n%s", task, res.Converted, res.HCL)
		}
	}
	res := convertString(t, "- hosts: all\n  tasks:\n    - wait_for: {port: 8080, state: drained}\n")
	if res.Converted != 0 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, "open connections") {
		t.Errorf("drained: %+v", res.Review)
	}
}
