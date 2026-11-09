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
	return planWinPromotion(req, "windows_ad_forest", "domain_name", "safe_mode_password_wo")
}

// planWinPromotion plans a step that changes what the host is in AD, once:
// keyed on the domain, write-only passwords null, and reboot_required kept
// from the last change unless this plan changes something.
func planWinPromotion(req providers.PlanResourceChangeRequest, kind, key string, writeOnly ...string) providers.PlanResourceChangeResponse {
	resp := planSyncedFold(req, kind, []string{key}, nil)
	if resp.PlannedState.IsNull() {
		return resp
	}
	vals := resp.PlannedState.AsValueMap()
	for _, a := range writeOnly {
		vals[a] = cty.NullVal(cty.String)
	}
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

const defaultJoinTimeout = 10 * time.Minute

func winMembershipSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "Experimental. This Windows host joined to an Active Directory domain as a member. It never reboots: reboot_required says Windows wants one, and windows_reboot does it. Removing the step leaves the host in the domain; nothing is unjoined.",
		Attributes: map[string]*configschema.Attribute{
			"id":       {Type: cty.String, Computed: true},
			"revision": revisionAttr(),
			"domain":   {Type: cty.String, Required: true, Description: "DNS name of the domain to join, such as lab.example.com."},
			"ou":       {Type: cty.String, Optional: true, Description: "Distinguished name of the OU for the computer's account, such as OU=Servers,DC=lab,DC=example,DC=com. Unset uses the domain's default. Used only when joining."},
			"username": {Type: cty.String, Required: true, Description: "Domain account that may join computers, such as LAB\\joiner or joiner@lab.example.com. Used only when joining."},
			"password_wo": {
				Type: cty.String, Optional: true, WriteOnly: true, Sensitive: true,
				Description: "Password for username, kept out of plan and state. Needed to join, and used only then.",
			},
			"timeout":         {Type: cty.String, Optional: true, Description: "How long joining may take. Defaults to \"10m\"."},
			"reboot_required": {Type: cty.Bool, Computed: true, Description: "Whether Windows reported wanting a reboot after the last change. Joining always does."},
			"in_sync":         {Type: cty.Bool, Computed: true, Description: "Whether the host was in this domain at the last refresh."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func winMembershipFrom(v cty.Value) windows.Membership {
	return windows.Membership{Domain: stringOr(v.GetAttr("domain"), ""), OU: stringOr(v.GetAttr("ou"), ""), Username: stringOr(v.GetAttr("username"), "")}
}

// validatePromotion checks what a join and a promotion share: passwords, the
// timeout, and Check once its attributes are known.
func validatePromotion(cfg cty.Value, passwords, attrs []string, check func() (string, error)) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() {
		return diags
	}
	for _, a := range passwords {
		if pw := cfg.GetAttr(a); known(pw) && (pw.AsString() == "" || strings.ContainsRune(pw.AsString(), 0)) {
			diags = diags.Append(attrError(a, a+" must not be empty or contain NUL"))
		}
	}
	if t := cfg.GetAttr("timeout"); t.IsKnown() {
		if _, err := durationOr(t, time.Minute); err != nil {
			diags = diags.Append(attrError("timeout", err.Error()))
		}
	}
	for _, a := range attrs {
		if !cfg.GetAttr(a).IsKnown() {
			return diags
		}
	}
	if attr, err := check(); err != nil {
		diags = diags.Append(attrError(attr, err.Error()))
	}
	return diags
}

func validateWinMembership(cfg cty.Value) tfdiags.Diagnostics {
	return validatePromotion(cfg, []string{"password_wo"}, []string{"domain", "ou", "username"}, func() (string, error) {
		return winMembershipFrom(cfg).Check()
	})
}

func planWinMembership(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	return planWinPromotion(req, "windows_domain_membership", "domain", "password_wo")
}

// membershipAction decides what apply does with what the host is now.
func membershipAction(m windows.Membership, a windows.ActualForest) (join bool, err error) {
	switch {
	case m.Matches(a):
		return false, nil
	case a.Joined != "":
		return false, fmt.Errorf("this host is already in %s; Conn3x never takes a host out of a domain, so it can't join %s", a.Joined, m.Domain)
	}
	return true, nil
}

func readWinADStep(ctx context.Context, req providers.ReadResourceRequest, matches func(windows.ActualForest) bool) providers.ReadResourceResponse {
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
	resp.NewState = withSync(req.PriorState, matches(a))
	return resp
}

func readWinMembership(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	if req.PriorState.IsNull() {
		return providers.ReadResourceResponse{NewState: req.PriorState}
	}
	return readWinADStep(ctx, req, winMembershipFrom(req.PriorState).Matches)
}

// promotedState is the new state after a join or promotion: in sync, passwords
// null, and whether Windows wants a reboot.
func promotedState(planned cty.Value, restart bool, writeOnly ...string) cty.Value {
	vals := withSync(planned, true).AsValueMap()
	for _, a := range writeOnly {
		vals[a] = cty.NullVal(cty.String)
	}
	vals["reboot_required"] = cty.BoolVal(restart)
	return cty.ObjectVal(vals)
}

func applyWinMembership(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	var resp providers.ApplyResourceChangeResponse
	if req.PlannedState.IsNull() {
		resp.NewState = req.PlannedState // forget: leaving a domain is never automatic
		return resp
	}
	fail := func(err error) providers.ApplyResourceChangeResponse {
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("windows_domain_membership: %w", err))
		return resp
	}
	m := winMembershipFrom(req.PlannedState)
	if _, err := m.Check(); err != nil {
		return fail(err)
	}
	timeout, err := durationOr(req.PlannedState.GetAttr("timeout"), defaultJoinTimeout)
	if err != nil {
		return fail(err)
	}
	h, err := winHost(ctx, req.PlannedState.GetAttr("ssh"))
	if err != nil {
		return fail(err)
	}
	a, err := windows.ReadForest(ctx, h.client)
	if err != nil {
		return fail(err)
	}
	// Joined but not rebooted yet reads the same as joined, so a reboot still
	// wanted shows only through the marker, which windows_reboot checks.
	restart := !req.PriorState.IsNull() && known(req.PriorState.GetAttr("reboot_required")) && req.PriorState.GetAttr("reboot_required").True()
	join, err := membershipAction(m, a)
	if err != nil {
		return fail(err)
	}
	if join {
		pw := req.Config.GetAttr("password_wo")
		if !known(pw) {
			return fail(fmt.Errorf("password_wo is needed to join %s", m.Domain))
		}
		if restart, err = windows.ApplyMembership(ctx, h.client, m, pw.AsString(), timeout); err != nil {
			return fail(fmt.Errorf("joining %s: %w", m.Domain, err))
		}
		if a, err = windows.ReadForest(ctx, h.client); err != nil {
			return fail(err)
		}
		if !m.Matches(a) {
			return fail(fmt.Errorf("Add-Computer reported success, but the host doesn't show domain %s", m.Domain))
		}
	}
	resp.NewState = promotedState(req.PlannedState, restart, "password_wo")
	return resp
}

func winDCSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "Experimental. This Windows host as another domain controller, and DNS server, in an Active Directory domain that exists. It never reboots: reboot_required says Windows wants one, and windows_reboot does it. Removing the step leaves the domain controller; nothing is demoted.",
		Attributes: map[string]*configschema.Attribute{
			"id":            {Type: cty.String, Computed: true},
			"revision":      revisionAttr(),
			"domain_name":   {Type: cty.String, Required: true, Description: "DNS name of the domain, such as lab.example.com."},
			"username":      {Type: cty.String, Required: true, Description: "Domain account that may add domain controllers, such as LAB\\admin, a member of Domain Admins. Used only when promoting."},
			"database_path": {Type: cty.String, Optional: true, Description: "Folder for the AD database. Windows' default is C:\\Windows\\NTDS. Used only when promoting."},
			"log_path":      {Type: cty.String, Optional: true, Description: "Folder for the AD logs. Used only when promoting."},
			"sysvol_path":   {Type: cty.String, Optional: true, Description: "Folder for SYSVOL. Used only when promoting."},
			"password_wo": {
				Type: cty.String, Optional: true, WriteOnly: true, Sensitive: true,
				Description: "Password for username, kept out of plan and state. Needed to promote, and used only then.",
			},
			"safe_mode_password_wo": {
				Type: cty.String, Optional: true, WriteOnly: true, Sensitive: true,
				Description: "Directory Services Restore Mode password for this domain controller, kept out of plan and state. Needed to promote, and used only then: changing it later changes nothing on the host.",
			},
			"timeout":         {Type: cty.String, Optional: true, Description: "How long promotion may take. Defaults to \"30m\"."},
			"reboot_required": {Type: cty.Bool, Computed: true, Description: "Whether Windows reported wanting a reboot after the last change. Promotion always does."},
			"in_sync":         {Type: cty.Bool, Computed: true, Description: "Whether the host was a domain controller in this domain at the last refresh."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func winDCFrom(v cty.Value) windows.DomainController {
	return windows.DomainController{
		DomainName: stringOr(v.GetAttr("domain_name"), ""), Username: stringOr(v.GetAttr("username"), ""),
		DatabasePath: stringOr(v.GetAttr("database_path"), ""), LogPath: stringOr(v.GetAttr("log_path"), ""), SysvolPath: stringOr(v.GetAttr("sysvol_path"), ""),
	}
}

// dcLockout returns why promoting would lock Conn3x out, or "". A domain
// controller has no local accounts, so a login named .\user or HOST\user stops
// working. Any other prefix names a domain, and since the login works now, the
// host is already in it, so it keeps working. host is "" at validate.
func dcLockout(v cty.Value, host string) string {
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
	if ok && (prefix == "." || (host != "" && (strings.EqualFold(prefix, host) || strings.EqualFold(prefix, short)))) {
		return fmt.Sprintf(`ssh user %q names a local account, and a domain controller has none: after promotion that login fails. Use the bare name, or the domain's form`, u.AsString())
	}
	return ""
}

func validateWinDC(cfg cty.Value) tfdiags.Diagnostics {
	diags := validatePromotion(cfg, []string{"password_wo", "safe_mode_password_wo"}, []string{"domain_name", "username", "database_path", "log_path", "sysvol_path"}, func() (string, error) {
		return winDCFrom(cfg).Check()
	})
	if !cfg.IsNull() {
		if why := dcLockout(cfg, ""); why != "" {
			diags = diags.Append(attrError("ssh", why))
		}
	}
	return diags
}

func planWinDC(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	return planWinPromotion(req, "windows_ad_domain_controller", "domain_name", "password_wo", "safe_mode_password_wo")
}

// dcAction decides what apply does with what the host is now.
func dcAction(d windows.DomainController, a windows.ActualForest) (promote bool, err error) {
	switch {
	case d.Matches(a):
		return false, nil
	case a.Forest != "":
		return false, fmt.Errorf("this host is already a domain controller in %s; Conn3x never demotes one, so it can't make it one in %s", a.Joined, d.DomainName)
	case a.Joined != "" && !strings.EqualFold(a.Joined, d.DomainName):
		return false, fmt.Errorf("this host is a member of %s; Conn3x never takes a host out of a domain, so it can't make it a domain controller in %s", a.Joined, d.DomainName)
	}
	return true, nil
}

func readWinDC(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	if req.PriorState.IsNull() {
		return providers.ReadResourceResponse{NewState: req.PriorState}
	}
	return readWinADStep(ctx, req, winDCFrom(req.PriorState).Matches)
}

func applyWinDC(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	var resp providers.ApplyResourceChangeResponse
	if req.PlannedState.IsNull() {
		resp.NewState = req.PlannedState // forget: demoting a DC is never automatic
		return resp
	}
	fail := func(err error) providers.ApplyResourceChangeResponse {
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("windows_ad_domain_controller: %w", err))
		return resp
	}
	d := winDCFrom(req.PlannedState)
	if _, err := d.Check(); err != nil {
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
	promote, err := dcAction(d, a)
	if err != nil {
		return fail(err)
	}
	if promote {
		facts, err := windows.Gather(ctx, h.client)
		if err != nil {
			return fail(err)
		}
		if why := dcLockout(req.PlannedState, facts.Hostname); why != "" {
			return fail(fmt.Errorf("%s", why))
		}
		pw, dsrm := req.Config.GetAttr("password_wo"), req.Config.GetAttr("safe_mode_password_wo")
		if !known(pw) || !known(dsrm) {
			return fail(fmt.Errorf("password_wo and safe_mode_password_wo are needed to promote this host in %s", d.DomainName))
		}
		if restart, err = windows.ApplyDomainController(ctx, h.client, d, pw.AsString(), dsrm.AsString(), timeout); err != nil {
			return fail(fmt.Errorf("promoting in %s: %w", d.DomainName, err))
		}
		if a, err = windows.ReadForest(ctx, h.client); err != nil {
			return fail(err)
		}
		if !d.Matches(a) {
			return fail(fmt.Errorf("Install-ADDSDomainController reported success, but the host doesn't show it's a domain controller in %s", d.DomainName))
		}
	}
	resp.NewState = promotedState(req.PlannedState, restart, "password_wo", "safe_mode_password_wo")
	return resp
}

func winChildDomainSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "Experimental. A new child domain in an Active Directory forest that exists, with this Windows host as its first domain controller and DNS server. It never reboots: reboot_required says Windows wants one, and windows_reboot does it. Removing the step leaves the domain; nothing is demoted.",
		Attributes: map[string]*configschema.Attribute{
			"id":            {Type: cty.String, Computed: true},
			"revision":      revisionAttr(),
			"domain_name":   {Type: cty.String, Required: true, Description: "Full DNS name of the new domain, such as emea.lab.example.com. Everything after the first label is the parent domain, which must exist."},
			"netbios_name":  {Type: cty.String, Optional: true, Description: "NetBIOS name of the new domain, up to 15 characters, such as EMEA. Unset lets Windows take it from the first label. Used only when the domain is made."},
			"username":      {Type: cty.String, Required: true, Description: "Account in the forest that may add a domain, a member of Enterprise Admins, named by its domain's DNS name: admin@lab.example.com or lab.example.com\\admin, not LAB\\admin. Its domain is the new domain's parent or another domain above it. Used only when the domain is made."},
			"database_path": {Type: cty.String, Optional: true, Description: "Folder for the AD database. Windows' default is C:\\Windows\\NTDS. Used only when the domain is made."},
			"log_path":      {Type: cty.String, Optional: true, Description: "Folder for the AD logs. Used only when the domain is made."},
			"sysvol_path":   {Type: cty.String, Optional: true, Description: "Folder for SYSVOL. Used only when the domain is made."},
			"password_wo": {
				Type: cty.String, Optional: true, WriteOnly: true, Sensitive: true,
				Description: "Password for username, kept out of plan and state. Needed to make the domain, and used only then.",
			},
			"safe_mode_password_wo": {
				Type: cty.String, Optional: true, WriteOnly: true, Sensitive: true,
				Description: "Directory Services Restore Mode password for this domain controller, kept out of plan and state. Needed to make the domain, and used only then: changing it later changes nothing on the host.",
			},
			"timeout":         {Type: cty.String, Optional: true, Description: "How long promotion may take. Defaults to \"30m\"."},
			"reboot_required": {Type: cty.Bool, Computed: true, Description: "Whether Windows reported wanting a reboot after the last change. Promotion always does."},
			"in_sync":         {Type: cty.Bool, Computed: true, Description: "Whether the host was a domain controller in this domain, or promoted into it and waiting for its reboot, at the last refresh."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func winChildDomainFrom(v cty.Value) windows.ChildDomain {
	return windows.ChildDomain{
		DomainName: stringOr(v.GetAttr("domain_name"), ""), NetBIOSName: stringOr(v.GetAttr("netbios_name"), ""), Username: stringOr(v.GetAttr("username"), ""),
		DatabasePath: stringOr(v.GetAttr("database_path"), ""), LogPath: stringOr(v.GetAttr("log_path"), ""), SysvolPath: stringOr(v.GetAttr("sysvol_path"), ""),
	}
}

// childLockout is forestLockout for the new domain: the same rules about which
// login still works once the host has no local accounts.
func childLockout(v cty.Value, c windows.ChildDomain, host string) string {
	return forestLockout(v, windows.Forest{DomainName: c.DomainName, NetBIOSName: c.NetBIOSName}, host)
}

func validateWinChildDomain(cfg cty.Value) tfdiags.Diagnostics {
	diags := validatePromotion(cfg, []string{"password_wo", "safe_mode_password_wo"}, []string{"domain_name", "netbios_name", "username", "database_path", "log_path", "sysvol_path"}, func() (string, error) {
		return winChildDomainFrom(cfg).Check()
	})
	if !cfg.IsNull() && !diags.HasErrors() {
		for _, a := range []string{"domain_name", "netbios_name"} {
			if !cfg.GetAttr(a).IsKnown() {
				return diags
			}
		}
		if why := childLockout(cfg, winChildDomainFrom(cfg), ""); why != "" {
			diags = diags.Append(attrError("ssh", why))
		}
	}
	return diags
}

func planWinChildDomain(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	return planWinPromotion(req, "windows_ad_domain", "domain_name", "password_wo", "safe_mode_password_wo")
}

// childDomainAction decides what apply does with what the host is now.
func childDomainAction(c windows.ChildDomain, a windows.ActualForest) (promote bool, err error) {
	switch {
	case c.Matches(a):
		return false, nil
	case a.Forest != "":
		return false, fmt.Errorf("this host is already a domain controller in %s; Conn3x never demotes one, so it can't make %s here", firstNonEmpty(a.Joined, a.Promoted, a.Forest), c.DomainName)
	case a.Joined != "":
		return false, fmt.Errorf("this host is a member of %s; a new domain needs a server that isn't in a domain, and Conn3x never takes a host out of one", a.Joined)
	}
	return true, nil
}

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}

func readWinChildDomain(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	if req.PriorState.IsNull() {
		return providers.ReadResourceResponse{NewState: req.PriorState}
	}
	return readWinADStep(ctx, req, winChildDomainFrom(req.PriorState).Matches)
}

func applyWinChildDomain(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	var resp providers.ApplyResourceChangeResponse
	if req.PlannedState.IsNull() {
		resp.NewState = req.PlannedState // forget: demoting a DC is never automatic
		return resp
	}
	fail := func(err error) providers.ApplyResourceChangeResponse {
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("windows_ad_domain: %w", err))
		return resp
	}
	c := winChildDomainFrom(req.PlannedState)
	if _, err := c.Check(); err != nil {
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
	promote, err := childDomainAction(c, a)
	if err != nil {
		return fail(err)
	}
	if promote {
		facts, err := windows.Gather(ctx, h.client)
		if err != nil {
			return fail(err)
		}
		if why := childLockout(req.PlannedState, c, facts.Hostname); why != "" {
			return fail(fmt.Errorf("%s", why))
		}
		pw, dsrm := req.Config.GetAttr("password_wo"), req.Config.GetAttr("safe_mode_password_wo")
		if !known(pw) || !known(dsrm) {
			return fail(fmt.Errorf("password_wo and safe_mode_password_wo are needed to make domain %s", c.DomainName))
		}
		if restart, err = windows.ApplyChildDomain(ctx, h.client, c, pw.AsString(), dsrm.AsString(), timeout); err != nil {
			return fail(fmt.Errorf("making domain %s under %s: %w", c.DomainName, c.Parent(), err))
		}
		if a, err = windows.ReadForest(ctx, h.client); err != nil {
			return fail(err)
		}
		if !c.Matches(a) {
			return fail(fmt.Errorf("Install-ADDSDomain reported success, but the host doesn't show it's a domain controller in %s", c.DomainName))
		}
	}
	resp.NewState = promotedState(req.PlannedState, restart, "password_wo", "safe_mode_password_wo")
	return resp
}
