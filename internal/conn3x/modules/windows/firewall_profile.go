// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package windows

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/opentofu/opentofu/internal/conn3x/modules/windows/ps"
)

// FirewallProfile is one Windows Firewall profile's settings. Nil and empty
// leave a setting as it is.
type FirewallProfile struct {
	Name            string // domain, private or public
	Enabled         *bool
	DefaultInbound  string // allow or block
	DefaultOutbound string
}

// ProfileState is a profile as the host has it, and with ReadFirewallProfile's
// rules set, what the lockout check needs.
type ProfileState struct {
	Enabled           bool
	Inbound, Outbound string // allow or block
	Rules             []ProfileRule
	ConnProfile       string // the profile the SSH connection came in on, or empty
}

// ProfileRule is an enabled inbound rule in force.
type ProfileRule struct {
	Name            string   `json:"name"`
	Action          string   `json:"action"`
	Profile         int      `json:"profile"` // 0 is any
	Protocol        string   `json:"protocol"`
	LocalPorts      []string `json:"local_ports"`
	RemoteAddresses []string `json:"remote_addresses"`
	// Whether the rule's program and service can be sshd: any, or sshd itself.
	SSHDProgram bool `json:"sshd_program"`
	SSHDService bool `json:"sshd_service"`
}

// Validate checks a profile step before anything runs.
func (p FirewallProfile) Validate() error {
	if _, ok := firewallProfiles[p.Name]; !ok {
		return fmt.Errorf("profile %q must be domain, private or public", p.Name)
	}
	for what, v := range map[string]string{"default_inbound": p.DefaultInbound, "default_outbound": p.DefaultOutbound} {
		if v != "" && v != "allow" && v != "block" {
			return fmt.Errorf("%s must be allow or block, not %q", what, v)
		}
	}
	if p.Enabled == nil && p.DefaultInbound == "" && p.DefaultOutbound == "" {
		return errors.New("set at least one of enabled, default_inbound and default_outbound")
	}
	return nil
}

// ReadFirewallProfile reads a profile. With conn, it also reads the rules and
// the connection's own profile, for LockoutGuard.
func ReadFirewallProfile(ctx context.Context, r ps.Runner, name string, conn *SSHConn) (ProfileState, error) {
	args := map[string]any{"name": name, "rules": conn != nil, "client": "", "port": 0}
	if conn != nil {
		args["port"] = conn.Port
		if conn.Client.IsValid() {
			args["client"] = conn.Client.String()
		}
	}
	res, err := ps.Read(ctx, r, script("read_firewall_profile.ps1"), args)
	if err != nil {
		return ProfileState{}, err
	}
	var a struct {
		Enabled, Inbound, Outbound string
		Rules                      []ProfileRule
		ConnProfile                string `json:"conn_profile"`
	}
	if err := json.Unmarshal(res.Value, &a); err != nil {
		return ProfileState{}, fmt.Errorf("reading firewall profile %s: %w", name, err)
	}
	// NotConfigured is Windows' default: on, inbound blocked, outbound allowed.
	st := ProfileState{
		Enabled:  !strings.EqualFold(a.Enabled, "False"),
		Inbound:  "block",
		Outbound: "allow",
		Rules:    a.Rules,
	}
	if strings.EqualFold(a.Inbound, "Allow") {
		st.Inbound = "allow"
	}
	if strings.EqualFold(a.Outbound, "Block") {
		st.Outbound = "block"
	}
	switch strings.ToLower(a.ConnProfile) {
	case "public":
		st.ConnProfile = "public"
	case "private":
		st.ConnProfile = "private"
	case "domainauthenticated":
		st.ConnProfile = "domain"
	}
	return st, nil
}

// Matches reports whether the profile has every setting p sets.
func (p FirewallProfile) Matches(st ProfileState) bool {
	return (p.Enabled == nil || *p.Enabled == st.Enabled) &&
		(p.DefaultInbound == "" || p.DefaultInbound == st.Inbound) &&
		(p.DefaultOutbound == "" || p.DefaultOutbound == st.Outbound)
}

// LockoutGuard returns why applying p could cut Conn3x off: when it leaves
// the profile on with inbound blocked, where it wasn't, unless the connection
// is over loopback, which Windows Firewall doesn't filter, or came in on
// another profile's network, or a rule in this profile surely lets it in and
// no block rule, which beats any allow rule, matches it. st must come from
// ReadFirewallProfile with conn.
func (p FirewallProfile) LockoutGuard(st ProfileState, conn SSHConn) error {
	on, in := st.Enabled, st.Inbound
	if p.Enabled != nil {
		on = *p.Enabled
	}
	if p.DefaultInbound != "" {
		in = p.DefaultInbound
	}
	if !on || in != "block" || (st.Enabled && st.Inbound == "block") {
		return nil
	}
	if conn.Client.IsValid() && conn.Client.IsLoopback() {
		return nil
	}
	if st.ConnProfile != "" && st.ConnProfile != p.Name {
		return nil
	}
	bit := firewallProfiles[p.Name]
	kept := ""
	for _, r := range st.Rules {
		if (r.Profile != 0 && r.Profile&bit == 0) || !r.SSHDProgram || !r.SSHDService {
			continue
		}
		f := FirewallRule{Direction: "inbound", Action: strings.ToLower(r.Action), Protocol: strings.ToLower(r.Protocol), LocalPorts: r.LocalPorts, RemoteAddresses: r.RemoteAddresses, Enabled: true}
		if f.Protocol == "" {
			f.Protocol = "any"
		}
		if f.BlocksSSH(conn) {
			return fmt.Errorf("rule %s blocks inbound TCP from %s, the connection Conn3x is using, in the %s profile; block rules beat allow rules, so turning the profile on with inbound blocked would cut Conn3x off", r.Name, conn, p.Name)
		}
		if kept == "" && f.keepsSSH(conn) {
			kept = r.Name
		}
	}
	if kept != "" {
		return nil
	}
	if !conn.Client.IsValid() {
		return fmt.Errorf("no enabled rule in the %s profile lets inbound TCP to port %d in from everywhere, and sshd didn't report which address Conn3x connects from (SSH_CONNECTION), so turning the profile on with inbound blocked could cut Conn3x off; add a windows_firewall_rule that allows port %d first", p.Name, conn.Port, conn.Port)
	}
	return fmt.Errorf("no enabled rule in the %s profile surely lets in %s, the connection Conn3x is using, so turning the profile on with inbound blocked would cut Conn3x off; add a windows_firewall_rule that allows it first", p.Name, conn)
}

// ApplyFirewallProfile sets what p sets, and nothing else.
func ApplyFirewallProfile(ctx context.Context, r ps.Runner, p FirewallProfile) error {
	if err := p.Validate(); err != nil {
		return err
	}
	cap1 := func(s string) string {
		if s == "" {
			return ""
		}
		return strings.ToUpper(s[:1]) + s[1:]
	}
	var enabled any
	if p.Enabled != nil {
		enabled = *p.Enabled
	}
	_, err := ps.Apply(ctx, r, script("apply_firewall_profile.ps1"), map[string]any{
		"name": cap1(p.Name), "enabled": enabled, "inbound": cap1(p.DefaultInbound), "outbound": cap1(p.DefaultOutbound),
	}, 2*time.Minute)
	return err
}
