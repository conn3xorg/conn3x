// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"
)

// password_lock becomes locked; expires, seconds since 1970, becomes the
// date it falls on in UTC, as Ansible compares it.
func TestConvertUserLockExpires(t *testing.T) {
	for task, want := range map[string]string{
		"user: {name: bob, password_lock: true}":   "locked = true",
		"user: {name: bob, password_lock: no}":     "locked = false",
		"user: {name: bob, expires: 1735689600}":   `expires = "2025-01-01"`,
		"user: {name: bob, expires: 1735689599.9}": `expires = "2024-12-31"`, // a moment before midnight UTC
		"user: {name: bob, expires: -1}":           `expires = ""`,
	} {
		res := convertString(t, "- hosts: all\n  tasks:\n    - "+task+"\n")
		hcl := strings.Join(strings.Fields(string(res.HCL)), " ")
		if res.Converted != 1 || len(res.Review) != 0 || !strings.Contains(hcl, want) {
			t.Errorf("%s: converted %d, review %+v, want %s:\n%s", task, res.Converted, res.Review, want, res.HCL)
		}
	}
	for task, reason := range map[string]string{
		"user: {name: bob, expires: soon}":             "isn't a number of seconds",
		"user: {name: bob, expires: '{{ leave_at }}'}": `refers to "leave_at"`,
	} {
		res := convertString(t, "- hosts: all\n  tasks:\n    - "+task+"\n")
		if res.Converted != 0 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, reason) {
			t.Errorf("%s: converted %d, review %+v, want %q", task, res.Converted, res.Review, reason)
		}
	}
}
