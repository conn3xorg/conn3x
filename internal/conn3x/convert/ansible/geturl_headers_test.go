// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"
)

const sum0 = "0000000000000000000000000000000000000000000000000000000000000000"

// get_url's headers become the download step's headers, and a credential
// becomes a TODO for headers_wo, never copied (#1181).
func TestConvertGetURLHeaders(t *testing.T) {
	base := "- hosts: all\n  vars: {accept: application/octet-stream}\n  tasks:\n    - get_url: {url: 'https://example.com/a.tgz', dest: /opt/a.tgz, checksum: 'sha256:" + sum0 + "', "
	for args, want := range map[string][]string{
		"headers: {Accept: '{{ accept }}'}}":                                           {`headers = {`, `Accept = "application/octet-stream"`},
		"headers: {Authorization: 'Bearer {{ token }}'}}":                              {"TODO(convert): Set headers_wo = { Authorization = ... }"},
		"headers: {PRIVATE-TOKEN: glpat-literal-secret, Accept: x}}":                   {"headers_wo = { PRIVATE-TOKEN = ... }", `Accept = "x"`},
		"headers: {Authorization: 'Bearer x'}, unredirected_headers: [Authorization]}": {"unredirected_headers dropped"},
	} {
		res := convertString(t, base+args+"\n")
		hcl := string(res.HCL)
		if res.Converted != 1 || len(res.Review) != 0 {
			t.Errorf("%s: converted %d, review %+v\n%s", args, res.Converted, res.Review, hcl)
			continue
		}
		for _, w := range want {
			if !strings.Contains(hcl, w) {
				t.Errorf("%s: missing %q:\n%s", args, w, hcl)
			}
		}
		for _, secret := range []string{"glpat-literal-secret", "Bearer"} {
			if strings.Contains(hcl, secret) {
				t.Errorf("%s: the secret %q is in the output:\n%s", args, secret, hcl)
			}
		}
	}
	res := convertString(t, base+"headers: '{{ my_headers }}'}\n")
	if !strings.Contains(reasons(res), "headers as an expression") {
		t.Errorf("headers as an expression: %q", reasons(res))
	}
}
