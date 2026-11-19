// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"
)

// after and before carry over, unless one has a | or a pattern Go might
// read differently.
func TestConvertReplaceAfterBefore(t *testing.T) {
	res := convertString(t, "- hosts: all\n  tasks:\n    - replace: {path: /etc/a, regexp: 'x', replace: 'y', after: 'start', before: 'end'}\n")
	if hcl := string(res.HCL); res.Converted != 1 || !strings.Contains(hcl, `after   = "start"`) || !strings.Contains(hcl, `before  = "end"`) {
		t.Errorf("converted %d:\n%s", res.Converted, hcl)
	}
	for task, reason := range map[string]string{
		"replace: {path: /etc/a, regexp: 'x', replace: 'y', after: 'a|b'}":      "has a | in after",
		`replace: {path: /etc/a, regexp: 'x', replace: 'y', before: '\d+ end'}`: "regexp using",
	} {
		res := convertString(t, "- hosts: all\n  tasks:\n    - "+task+"\n")
		if res.Converted != 0 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, reason) {
			t.Errorf("%s: converted %d, review %+v", task, res.Converted, res.Review)
		}
	}
}
