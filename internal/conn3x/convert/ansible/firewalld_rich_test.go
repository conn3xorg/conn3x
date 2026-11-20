// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"
)

func TestConvertFirewalldRichRule(t *testing.T) {
	res := convertString(t, "- hosts: all\n  tasks:\n    - firewalld: {rich_rule: 'rule family=ipv4 source address=10.0.0.0/8 accept', zone: public, permanent: true, immediate: true, state: enabled}\n")
	hcl := strings.Join(strings.Fields(string(res.HCL)), " ")
	if res.Converted != 1 || len(res.Review) != 0 || !strings.Contains(hcl, `rich_rule = "rule family=ipv4 source address=10.0.0.0/8 accept"`) || !strings.Contains(hcl, `zone = "public"`) {
		t.Errorf("converted %d, review %+v:\n%s", res.Converted, res.Review, res.HCL)
	}
	// Only running or only permanent stays for review, as for a port.
	res = convertString(t, "- hosts: all\n  tasks:\n    - firewalld: {rich_rule: 'rule family=ipv4 accept', permanent: true, state: enabled}\n")
	if res.Converted != 0 || len(res.Review) != 1 {
		t.Errorf("permanent only: converted %d, review %+v", res.Converted, res.Review)
	}
}
