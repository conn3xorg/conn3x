// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package nm keeps a NetworkManager connection profile: a keyfile in
// /etc/NetworkManager/system-connections that Conn3x writes whole, then
// reloads and brings up. Changing the connection Conn3x logs in over is the
// classic lockout, so the provider guards the change with a revert the
// host runs by itself (see package confirm).
package nm

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/opentofu/opentofu/internal/conn3x/modules"
	"github.com/opentofu/opentofu/internal/conn3x/modules/file"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// Dir is where NetworkManager reads keyfiles.
const Dir = "/etc/NetworkManager/system-connections"

// Connection is one profile.
type Connection struct {
	Name, Type, Ifname string
	// IP4 and IP6 are addresses with prefixes, or one of "auto" (DHCP or
	// SLAAC) and "disabled". Empty means "auto", except on a bond port,
	// which has no IP settings of its own.
	IP4, IP6    []string
	GW4, GW6    string
	DNS4, DNS6  []string
	MTU         int
	Autoconnect bool
	Controller  string // the bond this connection is a port of
	VLANParent  string
	VLANID      int
	BondMode    string
	BondOptions map[string]string
	DNSSearch   []string
}

var (
	nameRe      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
	ifnameRe    = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,15}$`)
	optKeyRe    = regexp.MustCompile(`^[a-z_]{1,32}$`)
	optValueRe  = regexp.MustCompile(`^[A-Za-z0-9_.,:-]{1,64}$`)
	domainRe    = regexp.MustCompile(`^[A-Za-z0-9.-]{1,253}$`)
	types       = []string{"ethernet", "bond", "vlan"}
	bondModes   = []string{"balance-rr", "active-backup", "balance-xor", "broadcast", "802.3ad", "balance-tlb", "balance-alb"}
	methodWords = []string{"auto", "disabled"}
)

// Path is the profile's keyfile.
func (c Connection) Path() string { return Dir + "/" + c.Name + ".nmconnection" }

func (c Connection) port() bool { return c.Controller != "" }

// Validate checks a Connection before anything reaches the host.
func (c Connection) Validate() error {
	if !nameRe.MatchString(c.Name) {
		return fmt.Errorf("name %q must start with a letter or digit and hold only letters, digits and _ . -", c.Name)
	}
	if !slices.Contains(types, c.Type) {
		return fmt.Errorf("type %q must be one of %s", c.Type, strings.Join(types, ", "))
	}
	if !ifnameRe.MatchString(c.Ifname) {
		return fmt.Errorf("ifname %q must be an interface name of 15 characters or fewer", c.Ifname)
	}
	if c.MTU != 0 && (c.MTU < 576 || c.MTU > 65535) {
		return fmt.Errorf("mtu %d must be from 576 to 65535", c.MTU)
	}
	if c.port() {
		if !nameRe.MatchString(c.Controller) {
			return fmt.Errorf("controller %q must be the name of a bond connection", c.Controller)
		}
		if c.Type != "ethernet" {
			return fmt.Errorf("only an ethernet connection can be a bond port, not a %s one", c.Type)
		}
		if len(c.IP4) > 0 || len(c.IP6) > 0 || c.GW4 != "" || c.GW6 != "" || len(c.DNS4) > 0 || len(c.DNS6) > 0 {
			return fmt.Errorf("a bond port has no addresses of its own; set them on the bond %q", c.Controller)
		}
	}
	if err := validIPs("ip4", c.IP4, false); err != nil {
		return err
	}
	if err := validIPs("ip6", c.IP6, true); err != nil {
		return err
	}
	for label, gw := range map[string]string{"gw4": c.GW4, "gw6": c.GW6} {
		if gw == "" {
			continue
		}
		a, err := netip.ParseAddr(gw)
		if err != nil || a.Is4() != (label == "gw4") {
			return fmt.Errorf("%s %q must be an IPv%s address", label, gw, label[2:])
		}
	}
	for label, list := range map[string][]string{"dns4": c.DNS4, "dns6": c.DNS6} {
		for _, d := range list {
			a, err := netip.ParseAddr(d)
			if err != nil || a.Is4() != (label == "dns4") {
				return fmt.Errorf("%s %q must be an IPv%s address", label, d, label[3:])
			}
		}
	}
	for _, d := range c.DNSSearch {
		if !domainRe.MatchString(d) {
			return fmt.Errorf("dns_search %q must be a domain name", d)
		}
	}
	switch c.Type {
	case "vlan":
		if !ifnameRe.MatchString(c.VLANParent) || c.VLANID < 1 || c.VLANID > 4094 {
			return fmt.Errorf("a vlan connection needs vlan_parent, an interface name, and vlan_id from 1 to 4094")
		}
	case "bond":
		if c.BondMode != "" && !slices.Contains(bondModes, c.BondMode) {
			return fmt.Errorf("bond_mode %q must be one of %s", c.BondMode, strings.Join(bondModes, ", "))
		}
	}
	if c.Type != "vlan" && (c.VLANParent != "" || c.VLANID != 0) {
		return fmt.Errorf("vlan_parent and vlan_id are for a vlan connection, not a %s one", c.Type)
	}
	if c.Type != "bond" && (c.BondMode != "" || len(c.BondOptions) > 0) {
		return fmt.Errorf("bond_mode and bond_options are for a bond connection, not a %s one", c.Type)
	}
	for k, v := range c.BondOptions {
		if !optKeyRe.MatchString(k) || !optValueRe.MatchString(v) || k == "mode" {
			return fmt.Errorf("bond_options %s = %q must be a bonding option and value, such as miimon = \"100\"; set the mode with bond_mode", k, v)
		}
	}
	return nil
}

func validIPs(label string, list []string, six bool) error {
	if len(list) == 1 && slices.Contains(methodWords, list[0]) {
		return nil
	}
	for _, p := range list {
		pfx, err := netip.ParsePrefix(p)
		if err != nil || pfx.Addr().Is4() == six {
			return fmt.Errorf("%s %q must be an address with its prefix, such as %s, or one of \"auto\" and \"disabled\" on its own", label, p, map[bool]string{false: "192.0.2.10/24", true: "2001:db8::10/64"}[six])
		}
	}
	return nil
}

// method is the keyfile's method for a list of addresses.
func method(list []string) string {
	switch {
	case len(list) == 0 || list[0] == "auto":
		return "auto"
	case list[0] == "disabled":
		return "disabled"
	}
	return "manual"
}

// Keyfile is the profile as Conn3x writes it.
func (c Connection) Keyfile() string {
	var b strings.Builder
	line := func(k, v string) { fmt.Fprintf(&b, "%s=%s\n", k, v) }
	b.WriteString("# Written by Conn3x. Changes made here or with nmcli are put back on the next apply.\n[connection]\n")
	line("id", c.Name)
	line("type", c.Type)
	line("interface-name", c.Ifname)
	line("autoconnect", strconv.FormatBool(c.Autoconnect))
	if c.port() {
		line("master", c.Controller)
		line("slave-type", "bond")
	}
	// NetworkManager takes the MTU from the ethernet setting for every type.
	if c.MTU != 0 {
		b.WriteString("\n[ethernet]\n")
		line("mtu", strconv.Itoa(c.MTU))
	}
	if c.Type == "vlan" {
		b.WriteString("\n[vlan]\n")
		line("id", strconv.Itoa(c.VLANID))
		line("parent", c.VLANParent)
	}
	if c.Type == "bond" {
		b.WriteString("\n[bond]\n")
		mode := c.BondMode
		if mode == "" {
			mode = "balance-rr"
		}
		line("mode", mode)
		keys := make([]string, 0, len(c.BondOptions))
		for k := range c.BondOptions {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			line(k, c.BondOptions[k])
		}
	}
	if c.port() {
		return b.String()
	}
	for _, fam := range []struct {
		section string
		addrs   []string
		gw      string
		dns     []string
	}{{"ipv4", c.IP4, c.GW4, c.DNS4}, {"ipv6", c.IP6, c.GW6, c.DNS6}} {
		fmt.Fprintf(&b, "\n[%s]\n", fam.section)
		m := method(fam.addrs)
		line("method", m)
		if m == "manual" {
			for i, a := range fam.addrs {
				line("address"+strconv.Itoa(i+1), a)
			}
		}
		if fam.gw != "" {
			line("gateway", fam.gw)
		}
		if len(fam.dns) > 0 {
			line("dns", strings.Join(fam.dns, ";")+";")
		}
		if fam.section == "ipv4" && len(c.DNSSearch) > 0 {
			line("dns-search", strings.Join(c.DNSSearch, ";")+";")
		}
	}
	return b.String()
}

// Activate is the command that makes NetworkManager read the keyfile and,
// with autoconnect, bring the connection up.
func (c Connection) Activate() string {
	cmd := "nmcli connection reload"
	if c.Autoconnect {
		cmd += " && nmcli connection up id " + ssh.Quote(c.Name) + " >/dev/null"
	}
	return cmd
}

// Actual is what the host has.
type Actual struct {
	Content string // the keyfile, or "" when there's none
	Active  bool
}

// InSync reports whether the keyfile is Conn3x's and, with autoconnect,
// the connection is up.
func (c Connection) InSync(a Actual) bool {
	return a.Content == c.Keyfile() && (!c.Autoconnect || a.Active)
}

const needNM = `command -v nmcli >/dev/null 2>&1 || { echo "NetworkManager isn't installed on this host: nmcli isn't there" >&2; exit 1; }
`

// Read reads the keyfile and whether NetworkManager has the connection up.
func Read(ctx context.Context, r modules.Runner, c Connection) (Actual, error) {
	if err := c.Validate(); err != nil {
		return Actual{}, err
	}
	f, err := file.Read(ctx, r, c.Path())
	if err != nil {
		return Actual{}, err
	}
	res, err := r.Run(ctx, needNM+"nmcli -t -f NAME connection show --active", nil)
	if err != nil {
		return Actual{}, err
	}
	if res.ExitCode != 0 {
		return Actual{}, errors.New(strings.TrimSpace(string(res.Stderr)))
	}
	a := Actual{Active: slices.Contains(strings.Split(strings.TrimSpace(string(res.Stdout)), "\n"), c.Name)}
	if f.Exists {
		a.Content = f.Content
	}
	return a, nil
}

// Write writes the keyfile, as NetworkManager wants it: root's, and
// readable by nobody else.
func Write(ctx context.Context, r modules.Runner, c Connection) error {
	if err := c.Validate(); err != nil {
		return err
	}
	return file.Apply(ctx, r, file.Desired{Path: c.Path(), Content: c.Keyfile(), Mode: "0600", Owner: "root", Group: "root"})
}

// Delete removes the profile, which takes the connection down.
func Delete(ctx context.Context, r modules.Runner, c Connection) error {
	res, err := r.Run(ctx, needNM+"if nmcli -t -f NAME connection show | grep -qxF -- "+ssh.Quote(c.Name)+"; then nmcli connection delete id "+ssh.Quote(c.Name)+" >/dev/null; fi; rm -f -- "+ssh.Quote(c.Path()), nil)
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return errors.New(strings.TrimSpace(string(res.Stderr)))
	}
	return nil
}
