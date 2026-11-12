// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"
)

// delegate_to a host becomes the step's on; the controller and templated
// names go to review.
func TestConvertDelegateTo(t *testing.T) {
	res := convertString(t, `- hosts: web
  tasks:
    - name: drain
      file: { path: /var/lib/drained/web1, state: directory }
      delegate_to: lb1
`)
	if res.Converted != 1 || !strings.Contains(string(res.HCL), `on = "lb1"`) {
		t.Fatalf("converted %d, review %v:\n%s", res.Converted, res.Review, res.HCL)
	}
	for to, want := range map[string]string{
		"localhost":            "the controller",
		"127.0.0.1":            "the controller",
		`"{{ groups.lb[0] }}"`: "can't read",
	} {
		res := convertString(t, `- hosts: web
  tasks:
    - name: drain
      file: { path: /var/lib/drained/web1, state: directory }
      delegate_to: `+to+`
`)
		if res.Converted != 0 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, want) {
			t.Errorf("delegate_to %s: converted %d, review %v", to, res.Converted, res.Review)
		}
	}
}
