// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"
)

func TestConvertWinTimezone(t *testing.T) {
	for _, task := range []string{
		"community.windows.win_timezone: {timezone: Central Standard Time}",
		"win_timezone: {timezone: Central Standard Time}",
	} {
		res := convertString(t, "- hosts: all\n  tasks:\n    - "+task+"\n")
		if res.Converted != 1 || !strings.Contains(string(res.HCL), "windows_timezone {") || !strings.Contains(string(res.HCL), `name = "Central Standard Time"`) {
			t.Errorf("%s: converted %d:\n%s", task, res.Converted, res.HCL)
		}
	}
	for task, reason := range map[string]string{
		"community.windows.win_timezone: {timezone: Central Standard Time_dstoff}": "_dstoff",
		"community.windows.win_timezone: {}":                                       "has no timezone",
	} {
		res := convertString(t, "- hosts: all\n  tasks:\n    - "+task+"\n")
		if res.Converted != 0 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, reason) {
			t.Errorf("%s: converted %d, review %+v", task, res.Converted, res.Review)
		}
	}
}
