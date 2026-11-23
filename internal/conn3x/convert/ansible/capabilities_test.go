package ansible

import (
	"strings"
	"testing"
)

func TestConvertsCapabilities(t *testing.T) {
	res := convertWithKey(t, "    - community.general.capabilities: {path: /usr/bin/ping, capability: cap_net_raw+ep, state: present}\n")
	if res.Converted != 1 || len(res.Review) != 0 {
		t.Fatalf("converted %d, review %+v", res.Converted, res.Review)
	}
	for _, want := range []string{`path         = "/usr/bin/ping"`, `capabilities = ["cap_net_raw+ep"]`, "owns every capability on /usr/bin/ping"} {
		if !strings.Contains(string(res.HCL), want) {
			t.Errorf("output lacks %q:\n%s", want, res.HCL)
		}
	}
}

func TestLeavesCapabilitiesItCantOwn(t *testing.T) {
	for reason, tasks := range map[string]string{
		`state "absent"`:          "    - capabilities: {path: /usr/bin/ping, capability: cap_net_raw+ep, state: absent}\n",
		"several capabilities":    "    - capabilities: {path: /usr/bin/ping, capability: cap_net_raw+ep}\n    - capabilities: {path: /usr/bin/ping, capability: cap_net_admin+ep}\n",
		"takes capabilities off":  "    - capabilities: {path: /usr/bin/ping, capability: cap_net_raw-ep}\n",
		"loops over capabilities": "    - capabilities: {path: /usr/bin/ping, capability: '{{ item }}'}\n      loop: [cap_net_raw+ep]\n",
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
