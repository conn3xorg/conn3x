// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"
)

func TestConvertWinOptionalFeature(t *testing.T) {
	for task, want := range map[string][]string{
		"ansible.windows.win_optional_feature: {name: TelnetClient}": {"windows_optional_feature {", `name = "TelnetClient"`},
		"win_optional_feature: {name: NetFx3, include_parent: true, source: 'D:\\sources\\sxs'}": {
			`name           = "NetFx3"`, "include_parent = true", `source         = "D:\\sources\\sxs"`,
		},
		"ansible.windows.win_optional_feature: {name: TelnetClient, state: absent}": {`state = "absent"`},
		// A list is a step each.
		"ansible.windows.win_optional_feature: {name: [TelnetClient, TFTP]}": {`name = "TelnetClient"`, `name = "TFTP"`},
	} {
		res := convertString(t, "- hosts: all\n  tasks:\n    - "+task+"\n")
		for _, w := range want {
			if res.Converted != 1 || !strings.Contains(string(res.HCL), w) {
				t.Errorf("%s: converted %d, want %s in:\n%s", task, res.Converted, w, res.HCL)
			}
		}
	}
	res := convertString(t, "- hosts: all\n  tasks:\n    - ansible.windows.win_optional_feature: {name: [TelnetClient, TFTP]}\n")
	if n := strings.Count(string(res.HCL), "windows_optional_feature {"); n != 2 {
		t.Errorf("a list of two made %d steps:\n%s", n, res.HCL)
	}
	res = convertString(t, "- hosts: all\n  tasks:\n    - ansible.windows.win_optional_feature: {state: present}\n")
	if res.Converted != 0 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, "has no name") {
		t.Errorf("no name: converted %d, review %+v", res.Converted, res.Review)
	}
}
