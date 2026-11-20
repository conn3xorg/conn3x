// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/conn3x/modules/windows"
	"github.com/opentofu/opentofu/internal/providers"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

func winFirewallRuleSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "A Windows Firewall rule, found by its name.",
		Attributes: map[string]*configschema.Attribute{
			"id":               {Type: cty.String, Computed: true},
			"revision":         revisionAttr(),
			"name":             {Type: cty.String, Required: true, Description: "The rule's name, which is its ID: letters, digits, spaces and . _ ( ) -."},
			"display_name":     {Type: cty.String, Optional: true, Description: "Name shown in Windows' tools. A new rule gets name; an existing one keeps its own when unset."},
			"description":      {Type: cty.String, Optional: true, Description: "Description. Left as it is when unset."},
			"direction":        {Type: cty.String, Optional: true, Description: "\"inbound\" (default) or \"outbound\"."},
			"action":           {Type: cty.String, Optional: true, Description: "\"allow\" (default) or \"block\"."},
			"protocol":         {Type: cty.String, Optional: true, Description: "\"tcp\", \"udp\", \"icmpv4\", \"icmpv6\" or \"any\" (default). An inbound allow rule with no local_ports and no remote_addresses must set it, so a rule that lets everything in is never made by leaving settings out."},
			"local_ports":      {Type: cty.List(cty.String), Optional: true, Description: "Ports on this host, such as \"443\" or \"8000-8100\". Needs protocol \"tcp\" or \"udp\". Unset means any."},
			"remote_addresses": {Type: cty.List(cty.String), Optional: true, Description: "Addresses the traffic comes from or goes to: IP addresses, subnets such as 10.0.0.0/8, ranges such as 10.0.0.1-10.0.0.9, or LocalSubnet. Unset means any."},
			"profiles":         {Type: cty.List(cty.String), Optional: true, Description: "Network profiles the rule applies in: \"domain\", \"private\", \"public\". Unset means all."},
			"enabled":          {Type: cty.Bool, Optional: true, Description: "Whether the rule is on. Defaults to true."},
			"on_remove":        {Type: cty.String, Optional: true, Computed: true, Description: "\"delete\" (default) deletes the rule when the step is removed or replaced, \"forget\" leaves it."},
			"in_sync":          {Type: cty.Bool, Computed: true, Description: "Whether the rule matched at the last refresh."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func winStringList(v cty.Value) []string {
	if !known(v) {
		return nil
	}
	var out []string
	for it := v.ElementIterator(); it.Next(); {
		_, e := it.Element()
		out = append(out, e.AsString())
	}
	return out
}

func winFirewallRuleFrom(v cty.Value) windows.FirewallRule {
	enabled := true
	if e := v.GetAttr("enabled"); known(e) {
		enabled = e.True()
	}
	var desc *string
	if d := v.GetAttr("description"); known(d) {
		s := d.AsString()
		desc = &s
	}
	return windows.FirewallRule{
		Name: stringOr(v.GetAttr("name"), ""), DisplayName: stringOr(v.GetAttr("display_name"), ""), Description: desc,
		Direction: stringOr(v.GetAttr("direction"), ""), Action: stringOr(v.GetAttr("action"), ""), Protocol: stringOr(v.GetAttr("protocol"), ""),
		LocalPorts: winStringList(v.GetAttr("local_ports")), RemoteAddresses: winStringList(v.GetAttr("remote_addresses")), Profiles: winStringList(v.GetAttr("profiles")),
		Enabled: enabled,
	}.WithDefaults()
}

// sshPort is the port Conn3x reaches a host on.
func sshPort(conn cty.Value) int {
	if conn.IsNull() || !conn.IsKnown() {
		return 22
	}
	if p := conn.GetAttr("port"); known(p) {
		n, _ := p.AsBigFloat().Int64()
		return portOr22(int(n))
	}
	return 22
}

// winFirewallLockout is the early check, at plan: a rule that blocks the SSH
// port from everywhere. Apply checks again against the connection the host
// sees, which also catches a narrower block that still takes in Conn3x.
func winFirewallLockout(v cty.Value, f windows.FirewallRule) error {
	if p := sshPort(v.GetAttr("ssh")); f.BlocksSSH(windows.SSHConn{Port: p}) {
		return fmt.Errorf("this rule blocks inbound TCP port %d from anywhere, which cuts Conn3x off from the host. Narrow it with remote_addresses or local_ports", p)
	}
	return nil
}

// winFirewallGuard checks a change, or a delete when f is nil, against the
// connection Conn3x is on, as the host sees it.
func winFirewallGuard(ctx context.Context, h *hostConn, conn cty.Value, name string, f *windows.FirewallRule) error {
	c, err := windows.ReadSSHConn(ctx, h.raw(), sshPort(conn))
	if err != nil {
		return err
	}
	a, err := windows.ReadFirewallRule(ctx, h.raw(), name)
	if err != nil {
		return err
	}
	return windows.SSHGuard(c, a, f)
}

func validateWinFirewallRule(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() {
		return diags
	}
	diags = diags.Append(validateOnRemove(cfg))
	for _, a := range []string{"name", "display_name", "description", "direction", "action", "protocol", "local_ports", "remote_addresses", "profiles", "enabled"} {
		if !cfg.GetAttr(a).IsWhollyKnown() {
			return diags
		}
	}
	f := winFirewallRuleFrom(cfg)
	if err := f.Validate(); err != nil {
		return diags.Append(attrError("name", err.Error()))
	}
	// With nothing but a name, Windows makes a rule that lets everything in.
	if f.Direction == "inbound" && f.Action == "allow" && cfg.GetAttr("protocol").IsNull() && len(f.LocalPorts) == 0 && len(f.RemoteAddresses) == 0 {
		return diags.Append(attrError("protocol", `this rule would allow all inbound traffic from anywhere. Set protocol and local_ports, or remote_addresses. To allow everything on purpose, set protocol = "any"`))
	}
	if err := winFirewallLockout(cfg, f); err != nil {
		diags = diags.Append(attrError("action", err.Error()))
	}
	return diags
}

var winFirewallSettings = []string{"display_name", "description", "direction", "action", "protocol", "local_ports", "remote_addresses", "profiles", "enabled"}

func planWinFirewallRule(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	return planSyncedFold(deleteByDefault(req), "windows_firewall_rule", []string{"name"}, winFirewallSettings)
}

func readWinFirewallRule(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	resp := providers.ReadResourceResponse{NewState: req.PriorState}
	if req.PriorState.IsNull() {
		return resp
	}
	h, err := winHost(ctx, req.PriorState.GetAttr("ssh"))
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(attrError("ssh", err.Error()))
		return resp
	}
	f := winFirewallRuleFrom(req.PriorState)
	a, err := windows.ReadFirewallRule(ctx, h.raw(), f.Name)
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(err)
		return resp
	}
	resp.NewState = withSync(req.PriorState, f.Matches(a))
	return resp
}

func applyWinFirewallRule(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	var resp providers.ApplyResourceChangeResponse
	fail := func(err error) providers.ApplyResourceChangeResponse {
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("windows_firewall_rule: %w", err))
		return resp
	}
	if req.PlannedState.IsNull() {
		resp.NewState = req.PlannedState
		if req.PriorState.IsNull() || req.PriorState.GetAttr("on_remove").AsString() != onRemoveDelete {
			return resp
		}
		h, err := winHost(ctx, req.PriorState.GetAttr("ssh"))
		if err != nil {
			return fail(err)
		}
		name := stringOr(req.PriorState.GetAttr("name"), "")
		if err := winFirewallGuard(ctx, h, req.PriorState.GetAttr("ssh"), name, nil); err != nil {
			return fail(fmt.Errorf("rule %s: %w", name, err))
		}
		if err := windows.ApplyFirewallRuleRemove(ctx, h.raw(), name); err != nil {
			return fail(err)
		}
		return resp
	}
	f := winFirewallRuleFrom(req.PlannedState)
	if err := f.Validate(); err != nil {
		return fail(err)
	}
	if err := winFirewallLockout(req.PlannedState, f); err != nil {
		return fail(err)
	}
	h, err := winHost(ctx, req.PlannedState.GetAttr("ssh"))
	if err != nil {
		return fail(err)
	}
	a, err := windows.ReadFirewallRule(ctx, h.raw(), f.Name)
	if err != nil {
		return fail(err)
	}
	if !f.Matches(a) {
		if err := winFirewallGuard(ctx, h, req.PlannedState.GetAttr("ssh"), f.Name, &f); err != nil {
			return fail(fmt.Errorf("rule %s: %w", f.Name, err))
		}
		if err := windows.ApplyFirewallRule(ctx, h.raw(), f); err != nil {
			return fail(fmt.Errorf("rule %s: %w", f.Name, err))
		}
		if a, err = windows.ReadFirewallRule(ctx, h.raw(), f.Name); err != nil {
			return fail(err)
		}
		if !f.Matches(a) {
			return fail(fmt.Errorf("rule %s doesn't match what was set; a group policy may own it", f.Name))
		}
	}
	resp.NewState = withSync(req.PlannedState, true)
	return resp
}

func winFirewallProfileSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "One Windows Firewall profile's settings: whether it's on, and its default inbound and outbound actions. Settings left unset are left as they are. Turning a profile on with inbound blocked is refused unless a rule in it surely lets Conn3x's SSH connection in.",
		Attributes: map[string]*configschema.Attribute{
			"id":               {Type: cty.String, Computed: true},
			"revision":         revisionAttr(),
			"name":             {Type: cty.String, Required: true, Description: "\"domain\", \"private\" or \"public\"."},
			"enabled":          {Type: cty.Bool, Optional: true, Description: "Whether the profile is on."},
			"default_inbound":  {Type: cty.String, Optional: true, Description: "\"allow\" or \"block\": what happens to inbound traffic no rule matches."},
			"default_outbound": {Type: cty.String, Optional: true, Description: "\"allow\" or \"block\": what happens to outbound traffic no rule matches."},
			"in_sync":          {Type: cty.Bool, Computed: true, Description: "Whether the profile had every setting at the last refresh."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func winFirewallProfileFrom(v cty.Value) windows.FirewallProfile {
	p := windows.FirewallProfile{Name: stringOr(v.GetAttr("name"), ""), DefaultInbound: stringOr(v.GetAttr("default_inbound"), ""), DefaultOutbound: stringOr(v.GetAttr("default_outbound"), "")}
	if e := v.GetAttr("enabled"); known(e) {
		b := e.True()
		p.Enabled = &b
	}
	return p
}

func validateWinFirewallProfile(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() || !cfg.IsWhollyKnown() {
		return diags
	}
	if err := winFirewallProfileFrom(cfg).Validate(); err != nil {
		diags = diags.Append(attrError("name", err.Error()))
	}
	return diags
}

func planWinFirewallProfile(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	return planSynced(req, "windows_firewall_profile", []string{"name"}, []string{"enabled", "default_inbound", "default_outbound"})
}

func readWinFirewallProfile(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	resp := providers.ReadResourceResponse{NewState: req.PriorState}
	if req.PriorState.IsNull() {
		return resp
	}
	h, err := winHost(ctx, req.PriorState.GetAttr("ssh"))
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(attrError("ssh", err.Error()))
		return resp
	}
	p := winFirewallProfileFrom(req.PriorState)
	st, err := windows.ReadFirewallProfile(ctx, h.raw(), p.Name, nil)
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("windows_firewall_profile: %w", err))
		return resp
	}
	resp.NewState = withSync(req.PriorState, p.Matches(st))
	return resp
}

func applyWinFirewallProfile(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	var resp providers.ApplyResourceChangeResponse
	// Removing the step leaves the profile as it is.
	if req.PlannedState.IsNull() {
		resp.NewState = req.PlannedState
		return resp
	}
	fail := func(err error) providers.ApplyResourceChangeResponse {
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("windows_firewall_profile: %w", err))
		return resp
	}
	p := winFirewallProfileFrom(req.PlannedState)
	if err := p.Validate(); err != nil {
		return fail(err)
	}
	h, err := winHost(ctx, req.PlannedState.GetAttr("ssh"))
	if err != nil {
		return fail(err)
	}
	conn, err := windows.ReadSSHConn(ctx, h.raw(), sshPort(req.PlannedState.GetAttr("ssh")))
	if err != nil {
		return fail(err)
	}
	st, err := windows.ReadFirewallProfile(ctx, h.raw(), p.Name, &conn)
	if err != nil {
		return fail(err)
	}
	if !p.Matches(st) {
		if err := p.LockoutGuard(st, conn); err != nil {
			return fail(err)
		}
		if err := windows.ApplyFirewallProfile(ctx, h.raw(), p); err != nil {
			return fail(fmt.Errorf("setting the %s profile: %w", p.Name, err))
		}
		if st, err = windows.ReadFirewallProfile(ctx, h.raw(), p.Name, nil); err != nil {
			return fail(err)
		}
		if !p.Matches(st) {
			return fail(fmt.Errorf("the %s profile doesn't have the settings after the change; Group Policy may set them", p.Name))
		}
	}
	resp.NewState = withSync(req.PlannedState, true)
	return resp
}
