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
	}
	if err := json.Unmarshal(res.Value, &a); err != nil {
		return ActualForest{}, errors.New("reading the forest: the host's answer wasn't valid")
	}
	var f ActualForest
	switch {
	case a.Role >= roleBackupDC && a.RootDN != "":
		f.Forest = dnToName(a.RootDN)
	case a.Role >= roleBackupDC:
		f.Forest = a.Domain
	// Promoted, before the reboot: the role changes only with it. The root
	// domain alone could be left over from a promotion rolled back by hand,
	// so it counts only with the reboot marker promotion leaves.
	case a.RootDN != "" && a.Marker:
		f.Forest, f.Pending = dnToName(a.RootDN), true
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
