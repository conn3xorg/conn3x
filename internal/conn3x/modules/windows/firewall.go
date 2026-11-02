// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package windows

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/opentofu/opentofu/internal/conn3x/modules/windows/ps"
)

// A rule's name is its ID. Get-NetFirewallRule -Name expands wildcards, so
// they're kept out, along with anything else a person wouldn't type.
var firewallName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._()-]{0,127}$`)

var firewallProfiles = map[string]int{"domain": 1, "private": 2, "public": 4}

// FirewallRule is a Windows Firewall rule. Empty lists mean any.
type FirewallRule struct {
	Name            string
	DisplayName     string // left as it is when empty; the name for a new rule
	Description     *string
	Direction       string // inbound or outbound
	Action          string // allow or block
	Protocol        string // tcp, udp, icmpv4, icmpv6 or any
	LocalPorts      []string
	RemoteAddresses []string
	Profiles        []string
	Enabled         bool
}

// WithDefaults fills in what an unset setting means.
func (f FirewallRule) WithDefaults() FirewallRule {
	if f.Direction == "" {
		f.Direction = "inbound"
	}
	if f.Action == "" {
		f.Action = "allow"
	}
	if f.Protocol == "" {
		f.Protocol = "any"
	}
	return f
}

func parsePort(p string) (lo, hi int, err error) {
	a, b, isRange := strings.Cut(p, "-")
	if !isRange {
		b = a
	}
	lo, err1 := strconv.Atoi(a)
	hi, err2 := strconv.Atoi(b)
	if err1 != nil || err2 != nil || lo < 1 || hi > 65535 || lo > hi || strings.ContainsAny(p, "+ ") {
		return 0, 0, fmt.Errorf("port %q must be a number from 1 to 65535, or a range such as 8000-8100", p)
	}
	return lo, hi, nil
}

// canonicalAddress is an address as Windows reports it back: a subnet with its
// prefix length, a single host without one.
func canonicalAddress(s string) (string, error) {
	if strings.EqualFold(s, "LocalSubnet") {
		return "LocalSubnet", nil
	}
	if a, b, ok := strings.Cut(s, "-"); ok {
		lo, err1 := netip.ParseAddr(a)
		hi, err2 := netip.ParseAddr(b)
		if err1 != nil || err2 != nil || lo.Is4() != hi.Is4() || hi.Less(lo) {
			return "", fmt.Errorf("address range %q must be two addresses of one family, low to high", s)
		}
		return lo.String() + "-" + hi.String(), nil
	}
	if ip, mask, ok := strings.Cut(s, "/"); ok {
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			return "", fmt.Errorf("address %q isn't an IP address, a subnet, a range or LocalSubnet", s)
		}
		bits, err := strconv.Atoi(mask)
		if err != nil && addr.Is4() {
			// Windows writes an IPv4 subnet with a dotted mask.
			m, perr := netip.ParseAddr(mask)
			if perr != nil || !m.Is4() {
				return "", fmt.Errorf("address %q has a mask that isn't valid", s)
			}
			v := uint32(m.As4()[0])<<24 | uint32(m.As4()[1])<<16 | uint32(m.As4()[2])<<8 | uint32(m.As4()[3])
			bits = 0
			for v&0x80000000 != 0 {
				bits, v = bits+1, v<<1
			}
			if v != 0 {
				return "", fmt.Errorf("address %q has a mask that isn't contiguous", s)
			}
		} else if err != nil {
			return "", fmt.Errorf("address %q has a prefix length that isn't a number", s)
		}
		p, err := addr.Prefix(bits)
		if err != nil || p.Addr() != addr {
			return "", fmt.Errorf("subnet %q has host bits set; write the network address, such as 10.0.0.0/8", s)
		}
		if bits == addr.BitLen() {
			return addr.String(), nil
		}
		return p.String(), nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil || addr.Zone() != "" {
		return "", fmt.Errorf("address %q isn't an IP address, a subnet, a range or LocalSubnet", s)
	}
	return addr.String(), nil
}

// Validate checks a rule, with its defaults, before anything reaches a host.
func (f FirewallRule) Validate() error {
	if !firewallName.MatchString(f.Name) {
		return fmt.Errorf("rule name %q must start with a letter or digit and use only letters, digits, spaces and . _ ( ) -", f.Name)
	}
	if strings.ContainsFunc(f.DisplayName, func(r rune) bool { return r < 0x20 || r == 0x7f }) || len(f.DisplayName) > 256 {
		return fmt.Errorf("display_name %q must be up to 256 characters, with no control characters", f.DisplayName)
	}
	if f.Description != nil && strings.ContainsFunc(*f.Description, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return errors.New("description must not contain control characters")
	}
	if f.Direction != "inbound" && f.Direction != "outbound" {
		return fmt.Errorf(`direction %q must be "inbound" or "outbound"`, f.Direction)
	}
	if f.Action != "allow" && f.Action != "block" {
		return fmt.Errorf(`action %q must be "allow" or "block"`, f.Action)
	}
	switch f.Protocol {
	case "tcp", "udp":
	case "any", "icmpv4", "icmpv6":
		if len(f.LocalPorts) > 0 {
			return fmt.Errorf(`local_ports needs protocol "tcp" or "udp", not %q`, f.Protocol)
		}
	default:
		return fmt.Errorf(`protocol %q must be "tcp", "udp", "icmpv4", "icmpv6" or "any"`, f.Protocol)
	}
	for _, p := range f.LocalPorts {
		if _, _, err := parsePort(p); err != nil {
			return err
		}
	}
	for _, a := range f.RemoteAddresses {
		if _, err := canonicalAddress(a); err != nil {
			return err
		}
	}
	for _, p := range f.Profiles {
		if _, ok := firewallProfiles[p]; !ok {
			return fmt.Errorf(`profile %q must be "domain", "private" or "public"`, p)
		}
	}
	return nil
}

// SSHConn is the connection Conn3x is on, as sshd saw it.
type SSHConn struct {
	Client netip.Addr // not valid when unknown: apply then refuses anything near the port
	Port   int        // sshd's own port, which NAT or a load balancer can hide
}

func (c SSHConn) String() string {
	if c.Client.IsValid() {
		return fmt.Sprintf("%s to port %d", c.Client, c.Port)
	}
	return fmt.Sprintf("an unknown address to port %d", c.Port)
}

// ReadSSHConn asks the host which connection this is, from SSH_CONNECTION.
// Without it, the client is unknown and the port is port.
func ReadSSHConn(ctx context.Context, r ps.Runner, port int) (SSHConn, error) {
	res, err := ps.Read(ctx, r, script("read_ssh_connection.ps1"), nil)
	if err != nil {
		return SSHConn{}, err
	}
	var s string
	_ = json.Unmarshal(res.Value, &s)
	c := SSHConn{Port: port}
	if f := strings.Fields(s); len(f) == 4 {
		if ip, err := netip.ParseAddr(f[0]); err == nil {
			// A rule's address never has a zone, so a link-local client's must go.
			c.Client = ip.Unmap().WithZone("")
		}
		if p, err := strconv.Atoi(f[3]); err == nil && p > 0 && p < 65536 {
			c.Port = p
		}
	}
	return c, nil
}

var (
	allV4 = netip.AddrFrom4([4]byte{255, 255, 255, 255})
	allV6 = netip.AddrFrom16([16]byte{0: 0xff, 1: 0xff, 2: 0xff, 3: 0xff, 4: 0xff, 5: 0xff, 6: 0xff, 7: 0xff, 8: 0xff, 9: 0xff, 10: 0xff, 11: 0xff, 12: 0xff, 13: 0xff, 14: 0xff, 15: 0xff})
)

// coversClient reports whether addresses take in client. With no client,
// only everything does. Loose, for a rule that might block or already lets
// the client in, LocalSubnet and forms it can't read count; strict, for a
// rule that must keep letting it in, they don't: Conn3x may come through a
// VPN, NAT or a jump host from outside the host's subnet.
func coversClient(addresses []string, client netip.Addr, strict bool) bool {
	if len(addresses) == 0 {
		return true
	}
	for _, a := range addresses {
		if strings.EqualFold(a, "Any") {
			return true
		}
		c, err := canonicalAddress(a)
		if err != nil || c == "LocalSubnet" {
			if !strict {
				return true
			}
			continue
		}
		if lo, hi, ok := strings.Cut(c, "-"); ok {
			l, h := netip.MustParseAddr(lo), netip.MustParseAddr(hi)
			if !client.IsValid() {
				if l.IsUnspecified() && (h == allV4 || h == allV6) {
					return true
				}
			} else if l.Is4() == client.Is4() && !client.Less(l) && !h.Less(client) {
				return true
			}
			continue
		}
		if p, err := netip.ParsePrefix(c); err == nil {
			if (!client.IsValid() && p.Bits() == 0) || (client.IsValid() && p.Contains(client)) {
				return true
			}
			continue
		}
		if client.IsValid() && netip.MustParseAddr(c) == client {
			return true
		}
	}
	return false
}

// reachesPort reports whether an enabled inbound rule covers TCP to the port,
// whatever the address.
func (f FirewallRule) reachesPort(port int) bool {
	if !f.Enabled || f.Direction != "inbound" || (f.Protocol != "tcp" && f.Protocol != "any") {
		return false
	}
	if len(f.LocalPorts) == 0 {
		return true
	}
	for _, p := range f.LocalPorts {
		if strings.EqualFold(p, "Any") {
			return true
		}
		if lo, hi, err := parsePort(p); err == nil && lo <= port && port <= hi {
			return true
		}
	}
	return false
}

// BlocksSSH reports whether the rule would block the connection: block rules
// beat allow rules in Windows Firewall. With no client known, only a block
// from everywhere counts; that is the early check at plan.
func (f FirewallRule) BlocksSSH(c SSHConn) bool {
	return f.Action == "block" && f.reachesPort(c.Port) && coversClient(f.RemoteAddresses, c.Client, false)
}

// AllowsSSH reports whether the rule may be letting the connection in.
func (f FirewallRule) AllowsSSH(c SSHConn) bool {
	return f.Action == "allow" && f.reachesPort(c.Port) && coversClient(f.RemoteAddresses, c.Client, false)
}

// keepsSSH reports whether the rule surely lets the connection in.
func (f FirewallRule) keepsSSH(c SSHConn) bool {
	return f.Action == "allow" && f.reachesPort(c.Port) && coversClient(f.RemoteAddresses, c.Client, true)
}

// Rule is the host's rule in the form a configured one takes.
func (a ActualFirewallRule) Rule() FirewallRule {
	return FirewallRule{
		Direction: strings.ToLower(a.Direction), Action: strings.ToLower(a.Action), Protocol: strings.ToLower(a.Protocol),
		LocalPorts: a.LocalPorts, RemoteAddresses: a.RemoteAddresses, Enabled: a.Enabled,
	}
}

// SSHGuard returns why setting want, or deleting the rule when want is nil,
// could cut Conn3x off from the host. It only sees this rule: another rule
// that also lets SSH in isn't counted, so it errs on the side of refusing.
// When the host doesn't say where Conn3x connects from, it refuses any block
// on the SSH port and any change to a rule that lets that port in.
func SSHGuard(c SSHConn, have ActualFirewallRule, want *FirewallRule) error {
	if !c.Client.IsValid() {
		const why = "sshd didn't report which address Conn3x connects from (SSH_CONNECTION), so"
		if want != nil && want.WithDefaults().Action == "block" && want.WithDefaults().reachesPort(c.Port) {
			return fmt.Errorf("%s a block on inbound TCP port %d could cut Conn3x off", why, c.Port)
		}
		if have.Exists && have.Rule().Action == "allow" && have.Rule().reachesPort(c.Port) {
			return fmt.Errorf("%s changing a rule that lets inbound TCP port %d in could cut Conn3x off", why, c.Port)
		}
		return nil
	}
	if want != nil && want.WithDefaults().BlocksSSH(c) {
		return fmt.Errorf("this rule blocks inbound TCP from %s, the connection Conn3x is using; block rules beat allow rules, so it would cut Conn3x off", c)
	}
	if !have.Exists || !have.Rule().AllowsSSH(c) {
		return nil
	}
	if want == nil {
		return fmt.Errorf("this rule lets Conn3x's SSH connection in (%s), and deleting it could cut Conn3x off. Set on_remove = \"forget\" to keep it when the step goes", c)
	}
	w := want.WithDefaults()
	old, mask := have.Profile, w.profileMask()
	if old == 7 {
		old = 0
	}
	if !w.keepsSSH(c) || (mask != 0 && (old == 0 || mask&old != old)) {
		return fmt.Errorf("this rule lets Conn3x's SSH connection in (%s), and this change would stop it, which could cut Conn3x off", c)
	}
	return nil
}

func (f FirewallRule) profileMask() int {
	m := 0
	for _, p := range f.Profiles {
		m |= firewallProfiles[p]
	}
	if m == 7 {
		return 0 // all three is Windows' Any
	}
	return m
}

// set is a list as a sorted set, with Windows' "Any" as empty.
func set(list []string, canon func(string) (string, error)) []string {
	out := []string{}
	for _, s := range list {
		if strings.EqualFold(s, "Any") {
			continue
		}
		if c, err := canon(s); err == nil {
			s = c
		}
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	slices.Sort(out)
	return out
}

func samePort(s string) (string, error) {
	lo, hi, err := parsePort(s)
	if err != nil || lo == hi {
		return strconv.Itoa(lo), err
	}
	return fmt.Sprintf("%d-%d", lo, hi), nil
}

// ActualFirewallRule is a rule as the host has it.
type ActualFirewallRule struct {
	Exists          bool     `json:"exists"`
	DisplayName     string   `json:"display_name"`
	Description     string   `json:"description"`
	Direction       string   `json:"direction"`
	Action          string   `json:"action"`
	Enabled         bool     `json:"enabled"`
	Profile         int      `json:"profile"`
	Protocol        string   `json:"protocol"`
	LocalPorts      []string `json:"local_ports"`
	RemoteAddresses []string `json:"remote_addresses"`
}

// ReadFirewallRule reads a rule by its name.
func ReadFirewallRule(ctx context.Context, r ps.Runner, name string) (ActualFirewallRule, error) {
	res, err := ps.Read(ctx, r, script("read_firewall_rule.ps1"), map[string]any{"name": name})
	if err != nil {
		return ActualFirewallRule{}, err
	}
	var a ActualFirewallRule
	if err := json.Unmarshal(res.Value, &a); err != nil {
		return ActualFirewallRule{}, fmt.Errorf("reading firewall rule %s: the host's answer wasn't valid", name)
	}
	return a, nil
}

// Matches reports whether the host has the rule as configured.
func (f FirewallRule) Matches(a ActualFirewallRule) bool {
	f = f.WithDefaults()
	profile := a.Profile
	if profile == 7 {
		profile = 0
	}
	return a.Exists && (f.DisplayName == "" || a.DisplayName == f.DisplayName) && (f.Description == nil || *f.Description == a.Description) &&
		strings.EqualFold(a.Direction, f.Direction) && strings.EqualFold(a.Action, f.Action) && a.Enabled == f.Enabled &&
		profile == f.profileMask() && strings.EqualFold(a.Protocol, f.Protocol) &&
		slices.Equal(set(a.LocalPorts, samePort), set(f.LocalPorts, samePort)) &&
		slices.Equal(set(a.RemoteAddresses, canonicalAddress), set(f.RemoteAddresses, canonicalAddress))
}

var protocolNames = map[string]string{"tcp": "TCP", "udp": "UDP", "icmpv4": "ICMPv4", "icmpv6": "ICMPv6", "any": "Any"}

// ApplyFirewallRule creates a rule, or sets every setting of an existing one.
func ApplyFirewallRule(ctx context.Context, r ps.Runner, f FirewallRule) error {
	f = f.WithDefaults()
	if err := f.Validate(); err != nil {
		return err
	}
	profiles := []string{}
	for _, p := range f.Profiles {
		profiles = append(profiles, strings.ToUpper(p[:1])+p[1:])
	}
	addresses := []string{}
	for _, a := range f.RemoteAddresses {
		c, _ := canonicalAddress(a)
		addresses = append(addresses, c)
	}
	var displayName any // null leaves it as it is
	if f.DisplayName != "" {
		displayName = f.DisplayName
	}
	_, err := ps.Apply(ctx, r, script("apply_firewall_rule.ps1"), map[string]any{
		"name": f.Name, "display_name": displayName, "description": f.Description,
		"direction": strings.ToUpper(f.Direction[:1]) + f.Direction[1:], "action": strings.ToUpper(f.Action[:1]) + f.Action[1:],
		"protocol": protocolNames[f.Protocol], "local_ports": append([]string{}, f.LocalPorts...), "remote_addresses": addresses,
		"profiles": profiles, "enabled": f.Enabled,
	}, 2*time.Minute)
	return err
}

// ApplyFirewallRuleRemove deletes a rule, if it's there.
func ApplyFirewallRuleRemove(ctx context.Context, r ps.Runner, name string) error {
	if !firewallName.MatchString(name) {
		return errors.New("not a rule name")
	}
	_, err := ps.Apply(ctx, r, script("apply_firewall_rule_remove.ps1"), map[string]any{"name": name}, 2*time.Minute)
	return err
}
