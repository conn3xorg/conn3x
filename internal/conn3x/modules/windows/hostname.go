// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package windows

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/opentofu/opentofu/internal/conn3x/modules/windows/ps"
)

// ValidateHostname checks a Windows computer name before anything runs,
// with ad.go's netbiosName: one Windows takes as both its NetBIOS and DNS
// host name.
func ValidateHostname(name string) error {
	switch {
	case strings.Contains(name, "."):
		return fmt.Errorf("computer name %q has a dot; give the host name alone, without its domain", name)
	case len(name) > 15:
		return fmt.Errorf("computer name %q is longer than 15 characters, the most Windows takes", name)
	case !netbiosName.MatchString(name):
		return fmt.Errorf("computer name %q isn't letters, digits and hyphens, not starting or ending with a hyphen", name)
	case allDigits.MatchString(name):
		return fmt.Errorf("computer name %q is all digits, which Windows refuses", name)
	}
	return nil
}

// HostnameState is the host's computer name, now and after a reboot.
type HostnameState struct {
	Running, Pending string
	DomainMember     bool
	Domain           string
}

// InSync reports whether the host has, or will have after its reboot,
// name. Windows compares computer names without case.
func (s HostnameState) InSync(name string) bool { return strings.EqualFold(s.Pending, name) }

// RebootRequired reports whether a rename is waiting for a reboot.
func (s HostnameState) RebootRequired() bool { return !strings.EqualFold(s.Running, s.Pending) }

// ReadHostname reads the host's computer name.
func ReadHostname(ctx context.Context, r ps.Runner) (HostnameState, error) {
	res, err := ps.Read(ctx, r, script("read_hostname.ps1"), nil)
	if err != nil {
		return HostnameState{}, err
	}
	var a struct {
		Running      string `json:"running"`
		Pending      string `json:"pending"`
		DomainMember bool   `json:"domain_member"`
		Domain       string `json:"domain"`
	}
	if err := json.Unmarshal(res.Value, &a); err != nil {
		return HostnameState{}, fmt.Errorf("reading the computer name: %w", err)
	}
	if a.Running == "" || a.Pending == "" {
		return HostnameState{}, fmt.Errorf("reading the computer name: Windows gave %q now and %q after a reboot", a.Running, a.Pending)
	}
	return HostnameState{Running: a.Running, Pending: a.Pending, DomainMember: a.DomainMember, Domain: a.Domain}, nil
}

// ApplyHostname renames a workgroup host, for its next boot. It never
// reboots, and refuses a domain member, whose account in AD would have
// to be renamed too.
func ApplyHostname(ctx context.Context, r ps.Runner, st HostnameState, name string) error {
	if st.DomainMember {
		return fmt.Errorf("this host is a member of %s; windows_hostname only renames a workgroup host, since renaming a member renames its account in the domain too", st.Domain)
	}
	res, err := ps.Apply(ctx, r, script("apply_hostname.ps1"), map[string]any{"name": name}, 2*time.Minute)
	if err != nil {
		return err
	}
	var a struct {
		Pending string `json:"pending"`
	}
	if err := json.Unmarshal(res.Value, &a); err != nil {
		return fmt.Errorf("reading the computer name after the rename: %w", err)
	}
	if !strings.EqualFold(a.Pending, name) {
		return fmt.Errorf("the computer name for the next boot is %q after renaming it to %q", a.Pending, name)
	}
	return nil
}
