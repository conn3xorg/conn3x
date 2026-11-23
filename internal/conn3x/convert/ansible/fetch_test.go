// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"
)

// fetch becomes a fetch step, with Ansible's dest/<host>/<src> layout
// unless flat.
func TestConvertFetch(t *testing.T) {
	for task, want := range map[string][]string{
		"ansible.builtin.fetch: {src: /etc/ssl/certs/app.pem, dest: certs}":                            {"fetch {", `dest = "certs/${each.key}/etc/ssl/certs/app.pem"`},
		"fetch: {src: /etc/ssl/certs/app.pem, dest: certs/, flat: true}":                               {`dest = "certs/app.pem"`, "every host writes the same dest"},
		"fetch: {src: /root/.ssh/id_ed25519, dest: keys/web.key, flat: true}":                          {`dest = "keys/web.key"`},
		"fetch: {src: /var/log/app.log, dest: logs, fail_on_missing: false, validate_checksum: false}": {"fail_on_missing = false"},
	} {
		res := convertString(t, "- hosts: all\n  tasks:\n    - "+task+"\n")
		if res.Converted != 1 || len(res.Review) != 0 {
			t.Errorf("%s: converted %d, review %+v\n%s", task, res.Converted, res.Review, res.HCL)
			continue
		}
		for _, w := range want {
			if !strings.Contains(string(res.HCL), w) {
				t.Errorf("%s: missing %q:\n%s", task, w, res.HCL)
			}
		}
	}
	for task, reason := range map[string]string{
		"fetch: {src: app.log, dest: logs}":                       "relative src",
		"fetch: {src: /etc/x, dest: '{{ out_dir }}', flat: true}": "variable",
	} {
		res := convertString(t, "- hosts: all\n  tasks:\n    - "+task+"\n")
		if res.Converted != 0 || !strings.Contains(reasons(res), reason) {
			t.Errorf("%s: converted %d, review %q, want %q", task, res.Converted, reasons(res), reason)
		}
	}
}
