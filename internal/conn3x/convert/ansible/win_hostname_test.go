// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"
)

func TestConvertWinHostname(t *testing.T) {
	for _, task := range []string{"ansible.windows.win_hostname: {name: WEB01}", "win_hostname: {name: WEB01}"} {
		res := convertString(t, "- hosts: all\n  tasks:\n    - "+task+"\n")
		if res.Converted != 1 || !strings.Contains(string(res.HCL), "windows_hostname {") || !strings.Contains(string(res.HCL), `name = "WEB01"`) {
			t.Errorf("%s: converted %d:\n%s", task, res.Converted, res.HCL)
		}
	}
	res := convertString(t, "- hosts: all\n  tasks:\n    - ansible.windows.win_hostname: {}\n")
	if res.Converted != 0 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, "has no name") {
		t.Errorf("no name: converted %d, review %+v", res.Converted, res.Review)
	}
}
