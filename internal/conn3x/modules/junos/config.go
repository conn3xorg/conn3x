// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package junos

import (
	"fmt"
	"regexp"
	"slices"

	"github.com/opentofu/opentofu/internal/conn3x/modules/setcfg"
)

// The set-statement model is setcfg's, shared with VyOS.
type (
	Config = setcfg.Config
	Leaf   = setcfg.Leaf
)

const (
	MatchLines = setcfg.MatchLines
	MatchBlock = setcfg.MatchBlock
)

var (
	SetLines  = setcfg.SetLines
	CheckLine = setcfg.CheckLine
	WithLines = setcfg.WithLines
	under     = setcfg.Under
	checkText = setcfg.CheckText
	haveLeaf  = setcfg.HaveLeaf
)

var hostnameRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,62}[A-Za-z0-9])?$`)

// ValidateHostname checks a name Junos takes as it is, without quotes.
func ValidateHostname(name string) error {
	if !hostnameRe.MatchString(name) {
		return fmt.Errorf("hostname %q must be letters, digits, hyphens and dots, starting and ending with a letter or digit, at most 64 characters", name)
	}
	return nil
}

// Hostname is the device's name, a single-valued statement.
func Hostname(name string) Leaf { return Leaf{Path: "system host-name", Value: name} }

// VLAN is one VLAN on an ELS switch, keyed by name as Junos keys them.
type VLAN struct {
	Name string
	ID   int
}

var vlanNameRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]{0,63}$`)

// Validate checks the name and ID.
func (v VLAN) Validate() error {
	if !vlanNameRe.MatchString(v.Name) {
		return fmt.Errorf("name %q must start with a letter and be letters, digits, hyphens, underscores and dots, at most 64 characters", v.Name)
	}
	if v.ID < 1 || v.ID > 4094 {
		return fmt.Errorf("vlan_id must be between 1 and 4094, not %d", v.ID)
	}
	return nil
}

// Config owns the VLAN's ID only, so interfaces and descriptions set on it
// elsewhere are left alone.
func (v VLAN) Config() Config {
	return Config{Lines: []string{fmt.Sprintf("set vlans %s vlan-id %d", v.Name, v.ID)}, Match: MatchLines}
}

// InSync reports whether the VLAN is there with this ID.
func (v VLAN) InSync(config string) bool { return v.Config().InSync(config) }

// Commands are what makes config have the VLAN, or nil.
func (v VLAN) Commands(config string) []string { return v.Config().Commands(config) }

// RemoveCommands delete the whole VLAN, when it's there.
func (v VLAN) RemoveCommands(config string) []string {
	if !slices.ContainsFunc(SetLines(config), func(l string) bool { return under(l, "vlans "+v.Name) }) {
		return nil
	}
	return []string{"delete vlans " + v.Name}
}
