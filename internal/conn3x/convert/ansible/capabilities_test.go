package ansible

import (
	"strings"
	"testing"
)

// Each stays for review: Ansible keeps the file's other capabilities, and a
// file_capabilities step would take them off (#1262).
func TestLeavesCapabilitiesForReview(t *testing.T) {
	for reason, tasks := range map[string]string{
		`keeps any other capabilities /usr/bin/ping has`: "    - community.general.capabilities: {path: /usr/bin/ping, capability: cap_net_raw+ep, state: present}\n",
		`capabilities = ["cap_net_raw+ep"]`:              "    - capabilities: {path: /usr/bin/ping, capability: cap_net_raw+ep}\n",
		`state "absent"`:                                 "    - capabilities: {path: /usr/bin/ping, capability: cap_net_raw+ep, state: absent}\n",
		"several capabilities":                           "    - capabilities: {path: /usr/bin/ping, capability: cap_net_raw+ep}\n    - capabilities: {path: /usr/bin/ping, capability: cap_net_admin+ep}\n",
		"takes capabilities off":                         "    - capabilities: {path: /usr/bin/ping, capability: cap_net_raw-ep}\n",
		"loops over capabilities":                        "    - capabilities: {path: /usr/bin/ping, capability: '{{ item }}'}\n      loop: [cap_net_raw+ep]\n",
	} {
		res := convertWithKey(t, tasks)
		found := false
		for _, r := range res.Review {
			found = found || strings.Contains(r.Reason, reason)
		}
		if res.Converted != 0 || !found {
			t.Errorf("%s: converted %d, review %+v", reason, res.Converted, res.Review)
		}
	}
}
