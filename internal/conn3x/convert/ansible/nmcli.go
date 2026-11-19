// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"cmp"
	"slices"

	"github.com/zclconf/go-cty/cty"
)

// nmcliModule converts community.general.nmcli for the ethernet, bond,
// bond port and VLAN profiles nm_connection writes. Ansible changes only
// the settings a task names and leaves the rest of a profile as it is;
// nm_connection writes the whole keyfile, which a note says. Anything the
// step can't hold exactly stays for review; arguments left unread are
// flagged by the converter.
func nmcliModule(in *input) ([]step, string) {
	if st := in.str("state"); st != "present" {
		return nil, "has state " + cmp.Or(st, "(none)") + "; only state: present writes a profile an nm_connection step can own"
	}
	name := in.str("conn_name")
	typ := in.str("type")
	port := in.has("master") || typ == "bond-slave"
	switch {
	case port:
		if st := in.str("slave_type"); typ != "bond-slave" && st != "bond" {
			return nil, "makes a port of a " + cmp.Or(st, "controller of unknown type") + "; an nm_connection step makes bond ports only"
		}
		if typ != "bond-slave" && typ != "ethernet" {
			return nil, "makes a " + typ + " port; an nm_connection step's bond ports are ethernet"
		}
		typ = "ethernet"
	case !slices.Contains([]string{"ethernet", "bond", "vlan"}, typ):
		return nil, "makes a " + cmp.Or(typ, "(none)") + " connection; an nm_connection step makes ethernet, bond and vlan ones"
	}
	attrs := []attr{s("name", name), s("ifname", cmp.Or(in.str("ifname"), name)), s("type", typ)}
	if port {
		for _, k := range []string{"ip4", "ip6", "gw4", "gw6", "dns4", "dns6", "dns4_search", "dns6_search", "method4", "method6"} {
			if in.has(k) {
				return nil, "sets " + k + " on a bond port, which has no addresses of its own"
			}
		}
		attrs = append(attrs, s("controller", in.str("master")))
		in.ignore("slave_type")
	}
	for _, fam := range []string{"4", "6"} {
		ips, why := nmcliIPs(in, fam)
		if why != "" {
			return nil, why
		}
		if ips != nil {
			attrs = append(attrs, attr{key: "ip" + fam, val: strList(ips)})
		}
		attrs = in.optional(attrs, "gw"+fam, "gw"+fam)
		if dns := in.list("dns" + fam); len(dns) > 0 {
			attrs = append(attrs, attr{key: "dns" + fam, val: strList(dns)})
		}
	}
	s4, s6 := in.list("dns4_search"), in.list("dns6_search")
	switch {
	case len(s4) > 0 && len(s6) > 0 && !slices.Equal(s4, s6):
		return nil, "sets dns4_search and dns6_search differently; an nm_connection step has one dns_search for both"
	case len(s4) > 0:
		attrs = append(attrs, attr{key: "dns_search", val: strList(s4)})
	case len(s6) > 0:
		attrs = append(attrs, attr{key: "dns_search", val: strList(s6)})
	}
	if in.has("mtu") {
		attrs = append(attrs, in.number("mtu"))
	}
	if in.has("autoconnect") {
		attrs = append(attrs, attr{key: "autoconnect", val: cty.BoolVal(in.bool("autoconnect", true))})
	}
	attrs = in.optional(attrs, "bond_mode", "mode")
	if in.has("vlanid") {
		n := in.number("vlanid")
		n.key = "vlan_id"
		attrs = append(attrs, n)
	}
	attrs = in.optional(attrs, "vlan_parent", "vlandev")
	// Defaults that change nothing.
	for _, k := range []string{"never_default4", "gw4_ignore_auto", "gw6_ignore_auto", "conn_reload", "ignore_unsupported_suboptions"} {
		if in.has(k) && !in.bool(k, false) {
			in.ignore(k)
		}
	}
	return one("nm_connection", attrs, "Ansible's nmcli changes only the settings a task names; an nm_connection step writes the whole profile, so a setting made on the host outside this task goes.")
}

// nmcliIPs is a family's addresses for the step: the task's, or "auto" or
// "disabled" from its method. nil leaves the step's default, auto.
func nmcliIPs(in *input, fam string) ([]string, string) {
	ips, method := in.list("ip"+fam), in.str("method"+fam)
	switch {
	case method == "" || method == "manual":
		if method == "manual" && len(ips) == 0 {
			return nil, "sets method" + fam + ": manual with no ip" + fam
		}
		if len(ips) == 0 {
			return nil, ""
		}
		return ips, ""
	case len(ips) > 0:
		return nil, "sets ip" + fam + " with method" + fam + ": " + method + "; an nm_connection step's addresses are either static or one method"
	case method == "auto" || method == "disabled":
		return []string{method}, ""
	}
	return nil, "sets method" + fam + ": " + method + "; an nm_connection step has auto, disabled or static addresses"
}
