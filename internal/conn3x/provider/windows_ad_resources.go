// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/conn3x/modules/windows"
	"github.com/opentofu/opentofu/internal/providers"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

func winDNSClientSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "Experimental. The DNS servers one network interface on a Windows host asks, in order. Removing the step leaves them as they are.",
		Attributes: map[string]*configschema.Attribute{
			"id":        {Type: cty.String, Computed: true},
			"revision":  revisionAttr(),
			"interface": {Type: cty.String, Optional: true, Description: "Interface alias, such as Ethernet. Unset picks the interface with the IPv4 default route."},
			"servers":   {Type: cty.List(cty.String), Required: true, Description: "IPv4 and IPv6 addresses of DNS servers, in the order to ask them. Only the address families listed are set: IPv4 servers alone leave IPv6 as it is."},
			"in_sync":   {Type: cty.Bool, Computed: true, Description: "Whether the interface matched at the last refresh."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func winDNSClientFrom(v cty.Value) windows.DNSClient {
	d := windows.DNSClient{Interface: stringOr(v.GetAttr("interface"), "")}
	if s := v.GetAttr("servers"); known(s) {
		for it := s.ElementIterator(); it.Next(); {
			_, e := it.Element()
			d.Servers = append(d.Servers, e.AsString())
		}
	}
	return d
}

func validateWinDNSClient(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() {
		return diags
	}
	for _, a := range []string{"interface", "servers"} {
		if !cfg.GetAttr(a).IsWhollyKnown() {
			return diags
		}
	}
	if attr, err := winDNSClientFrom(cfg).Check(); err != nil {
		diags = diags.Append(attrError(attr, err.Error()))
	}
	return diags
}

func planWinDNSClient(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	return planSyncedFold(req, "windows_dns_client", []string{"interface"}, []string{"servers"})
}

func readWinDNSClient(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	resp := providers.ReadResourceResponse{NewState: req.PriorState}
	if req.PriorState.IsNull() {
		return resp
	}
	h, err := winHost(ctx, req.PriorState.GetAttr("ssh"))
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(attrError("ssh", err.Error()))
		return resp
	}
	d := winDNSClientFrom(req.PriorState)
	a, err := windows.ReadDNSClient(ctx, h.client, d)
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(err)
		return resp
	}
	resp.NewState = withSync(req.PriorState, d.Matches(a))
	return resp
}

func applyWinDNSClient(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	var resp providers.ApplyResourceChangeResponse
	if req.PlannedState.IsNull() {
		resp.NewState = req.PlannedState
		return resp
	}
	fail := func(err error) providers.ApplyResourceChangeResponse {
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("windows_dns_client: %w", err))
		return resp
	}
	d := winDNSClientFrom(req.PlannedState)
	if err := d.Validate(); err != nil {
		return fail(err)
	}
	h, err := winHost(ctx, req.PlannedState.GetAttr("ssh"))
	if err != nil {
		return fail(err)
	}
	a, err := windows.ReadDNSClient(ctx, h.client, d)
	if err != nil {
		return fail(err)
	}
	if !d.Matches(a) {
		if err := windows.ApplyDNSClient(ctx, h.client, d); err != nil {
			return fail(err)
		}
		if a, err = windows.ReadDNSClient(ctx, h.client, d); err != nil {
			return fail(err)
		}
		if !d.Matches(a) {
			return fail(fmt.Errorf("the DNS servers on %s don't match what was set: IPv4 %v, IPv6 %v", a.Alias, a.IPv4, a.IPv6))
		}
	}
	resp.NewState = withSync(req.PlannedState, true)
	return resp
}

const defaultForestTimeout = 30 * time.Minute

func winForestSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "Experimental. A new Active Directory forest, with this Windows host as its first domain controller and DNS server. It never reboots: reboot_required says Windows wants one, and windows_reboot does it. Removing the step leaves the forest; nothing is demoted.",
		Attributes: map[string]*configschema.Attribute{
			"id":            {Type: cty.String, Computed: true},
			"revision":      revisionAttr(),
			"domain_name":   {Type: cty.String, Required: true, Description: "DNS name of the forest root domain, such as lab.example.com."},
			"netbios_name":  {Type: cty.String, Optional: true, Description: "NetBIOS name of the domain, up to 15 characters, such as LAB. Unset lets Windows take it from the first label. Used only when the forest is made."},
			"database_path": {Type: cty.String, Optional: true, Description: "Folder for the AD database. Windows' default is C:\\Windows\\NTDS. Used only when the forest is made."},
			"log_path":      {Type: cty.String, Optional: true, Description: "Folder for the AD logs. Used only when the forest is made."},
			"sysvol_path":   {Type: cty.String, Optional: true, Description: "Folder for SYSVOL. Used only when the forest is made."},
			"safe_mode_password_wo": {
				Type: cty.String, Optional: true, WriteOnly: true, Sensitive: true,
				Description: "Directory Services Restore Mode password, kept out of plan and state. Needed to make the forest, and used only then: changing it later changes nothing on the host.",
			},
			"timeout":         {Type: cty.String, Optional: true, Description: "How long promotion may take. Defaults to \"30m\"."},
			"reboot_required": {Type: cty.Bool, Computed: true, Description: "Whether Windows reported wanting a reboot after the last change. Promotion always does."},
			"in_sync":         {Type: cty.Bool, Computed: true, Description: "Whether the host was a domain controller in this forest at the last refresh."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func winForestFrom(v cty.Value) windows.Forest {
	return windows.Forest{
		DomainName: stringOr(v.GetAttr("domain_name"), ""), NetBIOSName: stringOr(v.GetAttr("netbios_name"), ""),
		DatabasePath: stringOr(v.GetAttr("database_path"), ""), LogPath: stringOr(v.GetAttr("log_path"), ""), SysvolPath: stringOr(v.GetAttr("sysvol_path"), ""),
	}
}

// forestLockout returns why promoting would lock Conn3x out, or "". A DC has
// no local accounts, so a login named HOST\user or .\user stops working; the
// bare name, or the new domain's, keeps working (S3 in the Windows plan's
// ledger). Windows may not take the NetBIOS name from the first label, so a
// prefix that isn't the DNS name needs netbios_name to compare with. host is
// the host's name, known at apply; at validate it's "" and a prefix that may
// be either waits for apply.
func forestLockout(v cty.Value, f windows.Forest, host string) string {
	conn := v.GetAttr("ssh")
	if conn.IsNull() || !conn.IsKnown() {
		return ""
	}
	u := conn.GetAttr("user")
	if !known(u) {
		return ""
	}
	prefix, _, ok := strings.Cut(u.AsString(), `\`)
	short := host
	if len(short) > 15 {
		short = short[:15]
	}
	local := fmt.Sprintf(`ssh user %q names a local account, and a domain controller has none: after promotion that login fails. Use the bare name, or the domain's form`, u.AsString())
	switch {
	case !ok || strings.EqualFold(prefix, f.DomainName) || (f.NetBIOSName != "" && strings.EqualFold(prefix, f.NetBIOSName)):
		return ""
	case prefix == "." || (host != "" && (strings.EqualFold(prefix, host) || strings.EqualFold(prefix, short))):
		return local
	case f.NetBIOSName != "":
		return local
	case host == "":
		return ""
	}
	return fmt.Sprintf(`ssh user %q names a domain, and a domain controller has no local accounts. Set netbios_name, so Conn3x can check it's this domain's, or use the bare name`, u.AsString())
}

// forestAction decides what apply does with what the host is now: nothing,
// promote it, or refuse.
func forestAction(f windows.Forest, a windows.ActualForest) (promote bool, err error) {
	switch {
	case f.Matches(a):
		return false, nil
	case a.Forest != "":
		return false, fmt.Errorf("this host is already a domain controller in %s; Conn3x never demotes one, so it can't make %s here", a.Forest, f.DomainName)
	case a.Member != "":
		return false, fmt.Errorf("this host is a member of %s; a new forest needs a server that isn't in a domain", a.Member)
	}
	return true, nil
}

func validateWinForest(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() {
		return diags
	}
	if pw := cfg.GetAttr("safe_mode_password_wo"); known(pw) && (pw.AsString() == "" || strings.ContainsRune(pw.AsString(), 0)) {
		diags = diags.Append(attrError("safe_mode_password_wo", "safe_mode_password_wo must not be empty or contain NUL"))
	}
	if t := cfg.GetAttr("timeout"); t.IsKnown() {
		if _, err := durationOr(t, defaultForestTimeout); err != nil {
			diags = diags.Append(attrError("timeout", err.Error()))
		}
	}
	for _, a := range []string{"domain_name", "netbios_name", "database_path", "log_path", "sysvol_path"} {
		if !cfg.GetAttr(a).IsKnown() {
			return diags
		}
	}
	f := winForestFrom(cfg)
	if attr, err := f.Check(); err != nil {
		return diags.Append(attrError(attr, err.Error()))
	}
	if why := forestLockout(cfg, f, ""); why != "" {
		diags = diags.Append(attrError("ssh", why))
	}
	return diags
}

func planWinForest(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	resp := planSyncedFold(req, "windows_ad_forest", []string{"domain_name"}, nil)
	if resp.PlannedState.IsNull() {
		return resp
	}
	vals := resp.PlannedState.AsValueMap()
	vals["safe_mode_password_wo"] = cty.NullVal(cty.String)
	if vals["in_sync"].IsKnown() {
		vals["reboot_required"] = req.PriorState.GetAttr("reboot_required")
	} else {
		vals["reboot_required"] = cty.UnknownVal(cty.Bool)
	}
	resp.PlannedState = cty.ObjectVal(vals)
	return resp
}

func readWinForest(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	resp := providers.ReadResourceResponse{NewState: req.PriorState}
	if req.PriorState.IsNull() {
		return resp
	}
	h, err := winHost(ctx, req.PriorState.GetAttr("ssh"))
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(attrError("ssh", err.Error()))
		return resp
	}
	a, err := windows.ReadForest(ctx, h.client)
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(err)
		return resp
	}
	resp.NewState = withSync(req.PriorState, winForestFrom(req.PriorState).Matches(a))
	return resp
}

func applyWinForest(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	var resp providers.ApplyResourceChangeResponse
	if req.PlannedState.IsNull() {
		resp.NewState = req.PlannedState // forget: demoting a DC is never automatic
		return resp
	}
	fail := func(err error) providers.ApplyResourceChangeResponse {
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("windows_ad_forest: %w", err))
		return resp
	}
	f := winForestFrom(req.PlannedState)
	if err := f.Validate(); err != nil {
		return fail(err)
	}
	timeout, err := durationOr(req.PlannedState.GetAttr("timeout"), defaultForestTimeout)
	if err != nil {
		return fail(err)
	}
	h, err := winHost(ctx, req.PlannedState.GetAttr("ssh"))
	if err != nil {
		return fail(err)
	}
	// Promotion adds the DNS role, and Windows servicing takes one change at a time.
	defer lockHost(h, "windows_feature")()
	a, err := windows.ReadForest(ctx, h.client)
	if err != nil {
		return fail(err)
	}
	restart := a.Pending
	promote, err := forestAction(f, a)
	if err != nil {
		return fail(err)
	}
	if promote {
		facts, err := windows.Gather(ctx, h.client)
		if err != nil {
			return fail(err)
		}
		if why := forestLockout(req.PlannedState, f, facts.Hostname); why != "" {
			return fail(fmt.Errorf("%s", why))
		}
		pw := req.Config.GetAttr("safe_mode_password_wo")
		if !known(pw) {
			return fail(fmt.Errorf("safe_mode_password_wo is needed to make forest %s", f.DomainName))
		}
		if restart, err = windows.ApplyForest(ctx, h.client, f, pw.AsString(), timeout); err != nil {
			return fail(fmt.Errorf("making forest %s: %w", f.DomainName, err))
		}
		if a, err = windows.ReadForest(ctx, h.client); err != nil {
			return fail(err)
		}
		if !f.Matches(a) {
			return fail(fmt.Errorf("Install-ADDSForest reported success, but the host doesn't show forest %s", f.DomainName))
		}
	}
	vals := withSync(req.PlannedState, true).AsValueMap()
	vals["safe_mode_password_wo"] = cty.NullVal(cty.String)
	vals["reboot_required"] = cty.BoolVal(restart)
	resp.NewState = cty.ObjectVal(vals)
	return resp
}
