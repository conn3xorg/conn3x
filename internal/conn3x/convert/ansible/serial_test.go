// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"
)

// serial becomes batch_size on a per_host circuit; what Conn3x can't carry
// over goes to review.
func TestConvertSerial(t *testing.T) {
	play := func(keys string) string {
		return `- hosts: web
` + keys + `
  tasks:
    - name: motd
      file: { path: /etc/motd.d, state: directory }
`
	}
	for serial, want := range map[string]string{"2": "batch_size = 2", `"20%"`: `batch_size = "20%"`} {
		res := convertString(t, play("  serial: "+serial))
		out := string(res.HCL)
		if len(res.Review) != 0 || !strings.Contains(out, `strategy   = "per_host"`) || !strings.Contains(out, want) {
			t.Errorf("serial %s: review %v:\n%s", serial, res.Review, out)
		}
	}
	for keys, want := range map[string]string{
		"  serial: [1, 5]":                       "set batch_size and max_failures",
		`  serial: "{{ n }}"`:                    "set batch_size and max_failures",
		"  serial: 2\n  max_fail_percentage: 20": "counts failed hosts",
	} {
		res := convertString(t, play(keys))
		if len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, want) {
			t.Errorf("%s: review %v", keys, res.Review)
		}
	}
}
