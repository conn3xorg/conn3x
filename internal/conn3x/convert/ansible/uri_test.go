// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"
)

func TestConvertURIWait(t *testing.T) {
	wait := func(until, extra string) string {
		return "- hosts: all\n  tasks:\n    - ansible.builtin.uri:\n        url: http://127.0.0.1:8080/healthz\n" + extra +
			"      register: health\n      until: " + until + "\n      retries: 30\n      delay: 2\n"
	}
	for play, want := range map[string][]string{
		wait("health.status == 200", ""):                                 {"wait_for {", `url     = "http://127.0.0.1:8080/healthz"`, `timeout = "60s"`},
		wait("health.status in [200, 204]", ""):                          {"status_codes = [200, 204]"},
		wait("health is succeeded", "        status_code: [200, 401]\n"): {"status_codes = [200, 401]"},
		wait("health.status == 200", "        validate_certs: false\n"):  {"skip_tls_verify = true"},
	} {
		res := convertString(t, play)
		if res.Converted != 1 || len(res.Review) != 0 {
			t.Errorf("%s: converted %d, review %v", play, res.Converted, res.Review)
		}
		for _, w := range want {
			if !strings.Contains(string(res.HCL), w) {
				t.Errorf("%s: missing %s:\n%s", play, w, res.HCL)
			}
		}
	}
	for play, reason := range map[string]string{
		wait("other.status == 200", ""):                                              "uses",
		wait("health.json.ready", ""):                                                "uses",
		wait("health.status == 200", "        method: POST\n"):                       "POST",
		"- hosts: all\n  tasks:\n    - uri: { url: http://x }\n":                     "only a uri task that retries",
		strings.Replace(wait("health.status == 200", ""), "delay: 2", "delay: 0", 1): "uses delay",
	} {
		res := convertString(t, play)
		if res.Converted != 0 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, reason) {
			t.Errorf("%s: %+v", play, res.Review)
		}
	}
}
