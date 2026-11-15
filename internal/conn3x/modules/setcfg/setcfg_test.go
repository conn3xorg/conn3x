// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package setcfg

import (
	"slices"
	"strings"
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

func TestConfigSecrets(t *testing.T) {
	for line, want := range map[string]string{
		"set protocols bgp neighbor 192.0.2.1 password 'x'":                              "set protocols bgp neighbor 192.0.2.1 password",
		`set system login user bob authentication encrypted-password "$6$salt$hash"`:     "set system login user bob authentication encrypted-password",
		`set protocols ospf area 0 interface ge-0/0/0 authentication md5 1 key "$9$abc"`: "set protocols ospf area 0 interface ge-0/0/0 authentication md5 1 key",
		`set security ike policy p pre-shared-key ascii-text "two words"`:                "set security ike policy p pre-shared-key ascii-text",
		"set vpn ipsec authentication psk peer1 secret 's3cret'":                         "set vpn ipsec authentication psk peer1 secret",
		"set protocols bgp 65000 neighbor 192.0.2.1 password 'two words'":                "set protocols bgp 65000 neighbor 192.0.2.1 password",
		"set protocols bgp 65000 neighbor 192.0.2.1 password 'my secret pw'":             "set protocols bgp 65000 neighbor 192.0.2.1 password",
		`set security ike policy P pre-shared-key ascii-text "my secret phrase"`:         "set security ike policy P pre-shared-key ascii-text",
	} {
		if got, err := SecretPath(line); err != nil || got != want {
			t.Errorf("SecretPath(%q) = %q, %v; want %q", line, got, err, want)
		}
	}
	for _, bad := range []string{
		"set system host-name r1",
		"set system login user bob authentication plaintext-password 'x'",
		"set service snmp community s3cret authorization ro",
		"set service snmp community key",
		"set protocols bgp neighbor 192.0.2.1 password 'unclosed secret",
	} {
		if _, err := SecretPath(bad); err == nil {
			t.Errorf("SecretPath(%q) took it", bad)
		}
	}

	running := "set protocols bgp neighbor 192.0.2.1 password 'old'\nset protocols bgp neighbor 192.0.2.1 remote-as 65001\nset protocols bgp neighbor 192.0.2.2 password 'theirs'\n"
	path := "set protocols bgp neighbor 192.0.2.1 password"
	c := Config{Prefix: "protocols bgp neighbor 192.0.2.1", Match: MatchBlock, Lines: []string{"set protocols bgp neighbor 192.0.2.1 remote-as 65001"},
		Secrets: []string{path + " 'new'"}, Paths: []string{path}}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	// Present by path: in sync whatever the secret, and block mode keeps it.
	if !c.InSync(running) || c.Commands(running) != nil {
		t.Errorf("in sync %v, commands %v", c.InSync(running), c.Commands(running))
	}
	c.Resend = true
	if cmds := c.Commands(running); !slices.Equal(cmds, []string{"delete protocols bgp neighbor 192.0.2.1 password", path + " 'new'"}) {
		t.Errorf("resend: %v", cmds)
	}
	if rm := c.RemoveCommands(running); !slices.Equal(rm, []string{"delete protocols bgp neighbor 192.0.2.1 remote-as 65001", "delete protocols bgp neighbor 192.0.2.1 password"}) {
		t.Errorf("remove: %v", rm)
	}
	gone := "set protocols bgp neighbor 192.0.2.1 remote-as 65001\n"
	c.Resend = false
	if c.InSync(gone) {
		t.Error("in sync without the password")
	}
	if cmds := c.Commands(gone); !slices.Equal(cmds, []string{path + " 'new'"}) {
		t.Errorf("missing: %v", cmds)
	}
	// A block delete never takes the node that holds the secret.
	wide := Config{Prefix: "protocols bgp", Match: MatchBlock, Secrets: []string{path + " 'new'"}, Paths: []string{path}}
	for _, d := range wide.Commands(running) {
		if strings.HasPrefix(path, "set "+strings.TrimPrefix(d, "delete ")+" ") {
			t.Errorf("block delete %q takes the secret", d)
		}
	}

	for _, bad := range []Config{
		{Secrets: []string{"set system host-name r1"}},
		{Secrets: []string{path + " 'a'", path + " 'b'"}},
		{Secrets: []string{path + " 'a'"}, Lines: []string{path + " 'b'"}},
		{Prefix: "system", Match: MatchBlock, Secrets: []string{path + " 'a'"}},
		{Secrets: []string{path + " 'a | b"}},
	} {
		err := bad.Validate()
		if err == nil {
			t.Errorf("accepted %+v", bad)
			continue
		}
		for _, l := range bad.Secrets {
			if v := splitWords(l); strings.Contains(err.Error(), v[len(v)-1]) && len(v[len(v)-1]) > 3 {
				t.Errorf("error quotes a secret: %v", err)
			}
		}
	}
	if !LooksSecret(path+" 'x'") || LooksSecret("set system host-name r1") {
		t.Error("LooksSecret")
	}
}
