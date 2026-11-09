// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package windows

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/opentofu/opentofu/internal/conn3x/modules/windows/ps"
)

var (
	dnsLabel    = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)
	allDigits   = regexp.MustCompile(`^[0-9]+$`)
	netbiosName = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,13}[A-Za-z0-9])?$`)
)

// Forest is a new Active Directory forest, made by promoting this host to its
// first domain controller.
type Forest struct {
	DomainName   string // DNS name of the forest root domain, such as lab.example.com
	NetBIOSName  string // empty lets Windows derive it from the first label
	DatabasePath string
	LogPath      string
	SysvolPath   string
}

// ValidateDomainName checks a DNS name for a domain: two labels or more, as a
// single-label domain is a known source of trouble, and no all-number top label.
func ValidateDomainName(attr, name string) error {
	labels := strings.Split(name, ".")
	if len(name) > 253 || len(labels) < 2 || allDigits.MatchString(labels[len(labels)-1]) {
		return fmt.Errorf("%s %q must be a DNS name with two labels or more, such as lab.example.com", attr, name)
	}
	for _, l := range labels {
		if !dnsLabel.MatchString(l) {
			return fmt.Errorf("%s %q must be a DNS name: letters, digits and hyphens between dots, such as lab.example.com", attr, name)
		}
	}
	return nil
}

// Validate checks a Forest before anything reaches a host.
func (f Forest) Validate() error {
	_, err := f.Check()
	return err
}

// Check is Validate, also naming the attribute at fault.
func (f Forest) Check() (attr string, err error) {
	if err := ValidateDomainName("domain_name", f.DomainName); err != nil {
		return "domain_name", err
	}
	if f.NetBIOSName != "" && !netbiosName.MatchString(f.NetBIOSName) {
		return "netbios_name", fmt.Errorf("netbios_name %q must be up to 15 letters, digits and hyphens, such as LAB", f.NetBIOSName)
	}
	for _, p := range []struct{ attr, v string }{{"database_path", f.DatabasePath}, {"log_path", f.LogPath}, {"sysvol_path", f.SysvolPath}} {
		if p.v != "" {
			c, err := CleanLocalPath(p.attr, p.v)
			if err != nil {
				return p.attr, err
			}
			if len(c) == 3 {
				return p.attr, fmt.Errorf("%s %q is the top of a drive; give a folder on it, such as %sNTDS", p.attr, p.v, c)
			}
		}
	}
	return "", nil
}

// ActualForest is what the host is now.
type ActualForest struct {
	// Forest is the forest root domain this host is a domain controller in,
	// once promoted, and before the reboot that finishes it too.
	Forest string
	// Pending means promoted by Conn3x, and waiting for the reboot.
	Pending bool
	// Member is the domain this host has joined as a member, if it has.
	Member string
	// Joined is the domain this host is in, as a member or a domain
	// controller, or "" in a workgroup.
	Joined string
	// Promoted is the domain Conn3x promoted this host into, while the
	// reboot that finishes it is still to come.
	Promoted string
}

// DomainRole values from Win32_ComputerSystem.
const (
	roleMemberWorkstation = 1
	roleMemberServer      = 3
	roleBackupDC          = 4
)

// ReadForest reads what the host is. It needs no AD tools, so a host without
// AD DS reads as no forest, not an error.
func ReadForest(ctx context.Context, r ps.Runner) (ActualForest, error) {
	res, err := ps.Read(ctx, r, script("read_ad_forest.ps1"), nil)
	if err != nil {
		return ActualForest{}, err
	}
	var a struct {
		Role   int    `json:"role"`
		Domain string `json:"domain"`
		RootDN string `json:"root_dn"`
		Marker bool   `json:"marker"`
		Part   bool   `json:"part"`
		// Promoted is what the reboot marker names, if anything.
		Promoted string `json:"promoted"`
	}
	if err := json.Unmarshal(res.Value, &a); err != nil {
		return ActualForest{}, errors.New("reading the forest: the host's answer wasn't valid")
	}
	var f ActualForest
	if a.Part {
		f.Joined = strings.TrimSuffix(a.Domain, ".")
	}
	switch {
	case a.Role >= roleBackupDC && a.RootDN != "":
		f.Forest = dnToName(a.RootDN)
	case a.Role >= roleBackupDC:
		f.Forest = a.Domain
	// Promoted, before the reboot: the role changes only with it. The root
	// domain alone could be left over from a promotion rolled back by hand,
	// so it counts only with the reboot marker promotion leaves.
	case a.RootDN != "" && a.Marker:
		f.Forest, f.Pending, f.Promoted = dnToName(a.RootDN), true, a.Promoted
	case a.Role == roleMemberWorkstation || a.Role == roleMemberServer:
		f.Member = a.Domain
	}
	return f, nil
}

// dnToName turns DC=lab,DC=example,DC=com into lab.example.com.
func dnToName(dn string) string {
	var labels []string
	for _, part := range strings.Split(dn, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok && strings.EqualFold(k, "DC") {
			labels = append(labels, v)
		}
	}
	return strings.Join(labels, ".")
}

// Matches reports whether the host is a domain controller in this forest.
func (f Forest) Matches(a ActualForest) bool {
	return a.Forest != "" && strings.EqualFold(strings.TrimSuffix(a.Forest, "."), f.DomainName)
}

// ApplyForest promotes the host to the first domain controller of a new forest,
// with DNS, and never reboots it: it reports whether Windows wants a reboot,
// which it always does. The password travels on stdin only, and errors have
// it blanked.
func ApplyForest(ctx context.Context, r ps.Runner, f Forest, safeModePassword string, timeout time.Duration) (restart bool, err error) {
	if safeModePassword == "" || strings.ContainsRune(safeModePassword, 0) {
		return false, errors.New("safe_mode_password_wo must not be empty or contain NUL")
	}
	clean := func(p string) string {
		if p == "" {
			return ""
		}
		c, _ := CleanLocalPath("", p)
		return c
	}
	res, err := ps.Apply(ctx, r, script("apply_ad_forest.ps1"), map[string]any{
		"domain_name": f.DomainName, "netbios_name": f.NetBIOSName, "password": safeModePassword,
		"database_path": clean(f.DatabasePath), "log_path": clean(f.LogPath), "sysvol_path": clean(f.SysvolPath),
	}, timeout)
	if err != nil {
		return false, errors.New(Scrub(err.Error(), []string{safeModePassword}))
	}
	var a struct {
		Restart bool `json:"restart"`
	}
	if err := json.Unmarshal(res.Value, &a); err != nil {
		return false, fmt.Errorf("reading the result for forest %s: %w", f.DomainName, err)
	}
	return a.Restart, nil
}

// badUsername catches what an account name, DOMAIN\user or user@domain,
// can't hold: control characters and the ones Windows refuses in a name.
var badUsername = regexp.MustCompile(`[\x00-\x1f\x7f"/\[\]:;|=,+*?<>]`)

func checkUsername(attr, u string) error {
	if u == "" || len(u) > 256 || badUsername.MatchString(u) || strings.Count(u, `\`) > 1 || strings.HasPrefix(u, `\`) || strings.HasSuffix(u, `\`) {
		return fmt.Errorf(`%s %q must be an account name, such as LAB\joiner or joiner@lab.example.com`, attr, u)
	}
	return nil
}

// checkPassword is for passwords sent to a host: some text, and no NUL.
func checkPassword(attr, p string) error {
	if p == "" || strings.ContainsRune(p, 0) {
		return fmt.Errorf("%s must not be empty or contain NUL", attr)
	}
	return nil
}

// Membership is this host joined to a domain as a member.
type Membership struct {
	Domain   string // DNS name of the domain
	OU       string // distinguished name of the OU for a new computer account; "" for Windows' default
	Username string // account the join uses, such as LAB\joiner
}

// Check validates a Membership, naming the attribute at fault.
func (m Membership) Check() (attr string, err error) {
	if err := ValidateDomainName("domain", m.Domain); err != nil {
		return "domain", err
	}
	if m.OU != "" && (len(m.OU) > 1024 || !strings.Contains(m.OU, "=") || strings.ContainsFunc(m.OU, func(r rune) bool { return r < 0x20 || r == 0x7f })) {
		return "ou", fmt.Errorf("ou %q must be a distinguished name, such as OU=Servers,DC=lab,DC=example,DC=com", m.OU)
	}
	if err := checkUsername("username", m.Username); err != nil {
		return "username", err
	}
	return "", nil
}

// Matches reports whether the host is in this domain, as a member or a
// domain controller.
func (m Membership) Matches(a ActualForest) bool {
	return a.Joined != "" && strings.EqualFold(a.Joined, m.Domain)
}

// ApplyMembership joins the host to the domain with Add-Computer, and never
// reboots it: the join always wants one. The password travels on stdin only,
// and errors have it blanked.
func ApplyMembership(ctx context.Context, r ps.Runner, m Membership, password string, timeout time.Duration) (restart bool, err error) {
	if err := checkPassword("password_wo", password); err != nil {
		return false, err
	}
	res, err := ps.Apply(ctx, r, script("apply_domain_membership.ps1"), map[string]any{
		"domain": m.Domain, "ou": m.OU, "username": m.Username, "password": password,
	}, timeout)
	if err != nil {
		return false, errors.New(Scrub(err.Error(), []string{password}))
	}
	return restartFrom(res.Value, "joining "+m.Domain)
}

// DomainController is this host as another domain controller in a domain
// that exists.
type DomainController struct {
	DomainName   string
	Username     string // account the promotion uses, such as LAB\admin
	DatabasePath string
	LogPath      string
	SysvolPath   string
}

// Check validates a DomainController, naming the attribute at fault.
func (d DomainController) Check() (attr string, err error) {
	if attr, err := (Forest{DomainName: d.DomainName, DatabasePath: d.DatabasePath, LogPath: d.LogPath, SysvolPath: d.SysvolPath}).Check(); err != nil {
		return attr, err
	}
	if err := checkUsername("username", d.Username); err != nil {
		return "username", err
	}
	return "", nil
}

// Matches reports whether the host is a domain controller in this domain, or
// promoted and waiting for its reboot.
func (d DomainController) Matches(a ActualForest) bool {
	return a.Forest != "" && strings.EqualFold(a.Joined, d.DomainName)
}

// ApplyDomainController promotes the host with Install-ADDSDomainController,
// DNS included, and never reboots it. Both passwords travel on stdin only, and
// errors have them blanked.
func ApplyDomainController(ctx context.Context, r ps.Runner, d DomainController, password, safeModePassword string, timeout time.Duration) (restart bool, err error) {
	if err := checkPassword("password_wo", password); err != nil {
		return false, err
	}
	if err := checkPassword("safe_mode_password_wo", safeModePassword); err != nil {
		return false, err
	}
	clean := func(p string) string {
		if p == "" {
			return ""
		}
		c, _ := CleanLocalPath("", p)
		return c
	}
	res, err := ps.Apply(ctx, r, script("apply_ad_domain_controller.ps1"), map[string]any{
		"domain_name": d.DomainName, "username": d.Username, "password": password, "safe_mode_password": safeModePassword,
		"database_path": clean(d.DatabasePath), "log_path": clean(d.LogPath), "sysvol_path": clean(d.SysvolPath),
	}, timeout)
	if err != nil {
		return false, errors.New(Scrub(err.Error(), []string{password, safeModePassword}))
	}
	return restartFrom(res.Value, "domain controller in "+d.DomainName)
}

// ChildDomain is a new domain in a forest that exists, with this host as its
// first domain controller.
type ChildDomain struct {
	DomainName   string // DNS name of the new domain, such as emea.lab.example.com
	NetBIOSName  string // empty lets Windows derive it from the first label
	Username     string // account in the forest that may add a domain, by DNS name, such as admin@lab.example.com
	DatabasePath string
	LogPath      string
	SysvolPath   string
}

// Parent is the domain the new one goes under: its name without the first label.
func (c ChildDomain) Parent() string {
	_, parent, _ := strings.Cut(c.DomainName, ".")
	return parent
}

// Check validates a ChildDomain, naming the attribute at fault.
func (c ChildDomain) Check() (attr string, err error) {
	if attr, err := (Forest{DomainName: c.DomainName, NetBIOSName: c.NetBIOSName, DatabasePath: c.DatabasePath, LogPath: c.LogPath, SysvolPath: c.SysvolPath}).Check(); err != nil {
		return attr, err
	}
	if strings.Count(c.DomainName, ".") < 2 {
		return "domain_name", fmt.Errorf("domain_name %q must be the new domain's full name, its own label in front of its parent's, such as emea.%s", c.DomainName, c.DomainName)
	}
	if err := checkUsername("username", c.Username); err != nil {
		return "username", err
	}
	// Seen on Azure: Install-ADDSDomain refuses LAB\admin, as the host can't
	// find a NetBIOS name in DNS before it's in the forest.
	// The account's domain is the parent or one above it, never the new
	// domain itself, which doesn't exist yet.
	domain, _, qualified := strings.Cut(c.Username, `\`)
	if !qualified {
		_, domain, qualified = strings.Cut(c.Username, "@")
	}
	if !qualified || strings.Count(c.Username, "@") > 1 || !strings.HasSuffix(strings.ToLower(c.DomainName), "."+strings.ToLower(domain)) {
		return "username", fmt.Errorf(`username %q must be an account in %s or a domain above it, named by the domain's DNS name, such as admin@%s or %s\admin: the new domain controller finds the forest through DNS`, c.Username, c.Parent(), c.Parent(), c.Parent())
	}
	return "", nil
}

// Matches reports whether the host is a domain controller in this domain, or
// promoted into it by Conn3x and waiting for its reboot. Until that reboot,
// Windows still says the host is in a workgroup.
func (c ChildDomain) Matches(a ActualForest) bool {
	return a.Forest != "" && (strings.EqualFold(a.Joined, c.DomainName) || a.Pending && strings.EqualFold(a.Promoted, c.DomainName))
}

// ApplyChildDomain promotes the host with Install-ADDSDomain, DNS included,
// and never reboots it. Both passwords travel on stdin only, and errors have
// them blanked.
func ApplyChildDomain(ctx context.Context, r ps.Runner, c ChildDomain, password, safeModePassword string, timeout time.Duration) (restart bool, err error) {
	if err := checkPassword("password_wo", password); err != nil {
		return false, err
	}
	if err := checkPassword("safe_mode_password_wo", safeModePassword); err != nil {
		return false, err
	}
	clean := func(p string) string {
		if p == "" {
			return ""
		}
		c, _ := CleanLocalPath("", p)
		return c
	}
	label, parent, _ := strings.Cut(c.DomainName, ".")
	res, err := ps.Apply(ctx, r, script("apply_ad_domain.ps1"), map[string]any{
		"domain_name": c.DomainName, "label": label, "parent": parent, "netbios_name": c.NetBIOSName,
		"username": c.Username, "password": password, "safe_mode_password": safeModePassword,
		"database_path": clean(c.DatabasePath), "log_path": clean(c.LogPath), "sysvol_path": clean(c.SysvolPath),
	}, timeout)
	if err != nil {
		return false, errors.New(Scrub(err.Error(), []string{password, safeModePassword}))
	}
	return restartFrom(res.Value, "new domain "+c.DomainName)
}

func restartFrom(v json.RawMessage, what string) (bool, error) {
	var a struct {
		Restart bool `json:"restart"`
	}
	if err := json.Unmarshal(v, &a); err != nil {
		return false, fmt.Errorf("reading the result for %s: %w", what, err)
	}
	return a.Restart, nil
}
