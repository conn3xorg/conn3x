// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package setcfg

import (
	"slices"
	"testing"
)

// In block mode an extra line goes at the highest node that holds nothing
// wanted (#833).
func TestBlockDeletesTheWholeUnwantedNode(t *testing.T) {
	for name, c := range map[string]struct {
		cfg  Config
		have string
		want []string
	}{
		// VyOS rolling: deleting only the distance left the hop routing.
		"vyos next hop": {
			Config{Prefix: "protocols static route 10.20.0.0/16", Lines: []string{"set protocols static route 10.20.0.0/16 next-hop 192.0.2.1"}, Match: MatchBlock},
			"set protocols static route 10.20.0.0/16 next-hop 192.0.2.1 distance 10\nset protocols static route 10.20.0.0/16 next-hop 192.0.2.2 distance 10\n",
			[]string{
				"delete protocols static route 10.20.0.0/16 next-hop 192.0.2.1 distance",
				"delete protocols static route 10.20.0.0/16 next-hop 192.0.2.2",
				"set protocols static route 10.20.0.0/16 next-hop 192.0.2.1",
			},
		},
		// vJunos-switch 26.2: "delete ... preference 10" left an empty
		// preference, and commit check refused it.
		"junos preference": {
			Config{Prefix: "routing-options static route 10.20.0.0/16", Lines: []string{"set routing-options static route 10.20.0.0/16 next-hop 192.0.2.1"}, Match: MatchBlock},
			"set routing-options static route 10.20.0.0/16 next-hop 192.0.2.1\nset routing-options static route 10.20.0.0/16 preference 10\n",
			[]string{"delete routing-options static route 10.20.0.0/16 preference"},
		},
		// A list keeps the values that are wanted: only the extra one goes.
		"list member": {
			Config{Prefix: "interfaces ge-0/0/1", Lines: []string{"set interfaces ge-0/0/1 unit 0 family ethernet-switching vlan members 10"}, Match: MatchBlock},
			"set interfaces ge-0/0/1 unit 0 family ethernet-switching vlan members 10\nset interfaces ge-0/0/1 unit 0 family ethernet-switching vlan members 20\n",
			[]string{"delete interfaces ge-0/0/1 unit 0 family ethernet-switching vlan members 20"},
		},
		// Two extras under one node make one delete.
		"one delete per node": {
			Config{Prefix: "service ntp", Lines: []string{"set service ntp server 10.0.0.1"}, Match: MatchBlock},
			"set service ntp server 10.0.0.1\nset service ntp allow-client address 10.0.0.0/8\nset service ntp allow-client address 192.0.2.0/24\n",
			[]string{"delete service ntp allow-client"},
		},
	} {
		if got := c.cfg.Commands(c.have); !slices.Equal(got, c.want) {
			t.Errorf("%s: %q, want %q", name, got, c.want)
		}
	}
}

func TestSplitWords(t *testing.T) {
	got := splitWords(`interfaces eth0 description "a b \"c\" d" mtu 1500`)
	if !slices.Equal(got, []string{"interfaces", "eth0", "description", `"a b \"c\" d"`, "mtu", "1500"}) {
		t.Errorf("%q", got)
	}
}
