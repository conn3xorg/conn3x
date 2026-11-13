// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package nm

import (
	"strings"
	"testing"
)

func TestKeyfile(t *testing.T) {
	c := Connection{Name: "lan", Type: "ethernet", Ifname: "eth1", IP4: []string{"192.0.2.10/24"}, GW4: "192.0.2.1", DNS4: []string{"192.0.2.53", "192.0.2.54"}, DNSSearch: []string{"example.com"}, IP6: []string{"disabled"}, MTU: 9000, Autoconnect: true}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	want := `# Written by Conn3x. Changes made here or with nmcli are put back on the next apply.
[connection]
id=lan
type=ethernet
interface-name=eth1
autoconnect=true

[ethernet]
mtu=9000

[ipv4]
method=manual
address1=192.0.2.10/24
gateway=192.0.2.1
dns=192.0.2.53;192.0.2.54;
dns-search=example.com;

[ipv6]
method=disabled
`
	if got := c.Keyfile(); got != want {
		t.Errorf("keyfile:\n%s\nwant:\n%s", got, want)
	}
	if c.Path() != "/etc/NetworkManager/system-connections/lan.nmconnection" || !strings.Contains(c.Activate(), "nmcli connection up id 'lan'") {
		t.Errorf("path %s, activate %s", c.Path(), c.Activate())
	}
}

func TestKeyfileBondAndVLAN(t *testing.T) {
	bond := Connection{Name: "bond0", Type: "bond", Ifname: "bond0", BondMode: "802.3ad", BondOptions: map[string]string{"miimon": "100", "lacp_rate": "fast"}, Autoconnect: true}
	port := Connection{Name: "bond0-eth2", Type: "ethernet", Ifname: "eth2", Controller: "bond0", Autoconnect: true}
	vlan := Connection{Name: "vlan10", Type: "vlan", Ifname: "bond0.10", VLANParent: "bond0", VLANID: 10, IP4: []string{"auto"}, Autoconnect: true}
	for _, c := range []Connection{bond, port, vlan} {
		if err := c.Validate(); err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
	}
	if k := bond.Keyfile(); !strings.Contains(k, "[bond]\nmode=802.3ad\nlacp_rate=fast\nmiimon=100\n") || !strings.Contains(k, "[ipv4]\nmethod=auto\n") {
		t.Errorf("bond:\n%s", k)
	}
	if k := port.Keyfile(); !strings.Contains(k, "master=bond0\nslave-type=bond\n") || strings.Contains(k, "[ipv4]") {
		t.Errorf("port:\n%s", k)
	}
	if k := vlan.Keyfile(); !strings.Contains(k, "[vlan]\nid=10\nparent=bond0\n") {
		t.Errorf("vlan:\n%s", k)
	}
}

func TestValidate(t *testing.T) {
	for _, c := range []Connection{
		{Name: "lan;rm", Type: "ethernet", Ifname: "eth0"},
		{Name: "lan", Type: "wifi", Ifname: "wlan0"},
		{Name: "lan", Type: "ethernet", Ifname: "an-interface-name-too-long"},
		{Name: "lan", Type: "ethernet", Ifname: "eth0", IP4: []string{"192.0.2.10"}},
		{Name: "lan", Type: "ethernet", Ifname: "eth0", IP4: []string{"2001:db8::1/64"}},
		{Name: "lan", Type: "ethernet", Ifname: "eth0", GW4: "2001:db8::1"},
		{Name: "lan", Type: "ethernet", Ifname: "eth0", DNS4: []string{"dns.example"}},
		{Name: "p", Type: "ethernet", Ifname: "eth2", Controller: "bond0", IP4: []string{"192.0.2.2/24"}},
		{Name: "v", Type: "vlan", Ifname: "eth0.5000", VLANParent: "eth0", VLANID: 5000},
		{Name: "b", Type: "bond", Ifname: "bond0", BondMode: "fastest"},
		{Name: "b", Type: "bond", Ifname: "bond0", BondOptions: map[string]string{"miimon": "100; reboot"}},
		{Name: "e", Type: "ethernet", Ifname: "eth0", VLANID: 5},
		{Name: "e", Type: "ethernet", Ifname: "eth0", MTU: 100},
	} {
		if c.Validate() == nil {
			t.Errorf("%+v should be refused", c)
		}
	}
}

func TestInSync(t *testing.T) {
	c := Connection{Name: "lan", Type: "ethernet", Ifname: "eth1", Autoconnect: true}
	if !c.InSync(Actual{Content: c.Keyfile(), Active: true}) || c.InSync(Actual{Content: c.Keyfile()}) || c.InSync(Actual{Content: "edited", Active: true}) {
		t.Error("in sync needs Conn3x's keyfile and, with autoconnect, the connection up")
	}
	c.Autoconnect = false
	if !c.InSync(Actual{Content: c.Keyfile()}) || strings.Contains(c.Activate(), "up") {
		t.Error("without autoconnect, Conn3x only reloads")
	}
}
