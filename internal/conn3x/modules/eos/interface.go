// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package eos

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// Interface is the settings eos_interface owns on one interface. Each one
// left unset is left alone, and every other line under the interface, such
// as its IP address, is never touched.
type Interface struct {
	Name         string
	Description  *string
	Enabled      *bool
	Mode         string // "access", "trunk" or "" to leave
	AccessVLAN   int    // 0 to leave
	AllowedVLANs []int  // nil to leave
	MTU          int    // 0 to leave
}

var interfaceName = regexp.MustCompile(`^(Ethernet[0-9]+(/[0-9]+)*|Port-Channel[0-9]+|Vlan[0-9]+|Loopback[0-9]+|Management[0-9]+)$`)

// Validate checks an Interface before anything reaches the switch.
func (i Interface) Validate() error {
	if !interfaceName.MatchString(i.Name) {
		return fmt.Errorf("name %q is not an interface name as running-config prints it, such as Ethernet1, Port-Channel10, Vlan20 or Loopback0", i.Name)
	}
	if i.Description != nil {
		if err := checkLine("description " + *i.Description); err != nil || *i.Description == "" {
			return errors.New("description must be one line, without leading or trailing spaces")
		}
	}
	switch i.Mode {
	case "", "access", "trunk":
	default:
		return fmt.Errorf("mode must be \"access\" or \"trunk\", not %q", i.Mode)
	}
	switchport := i.Mode != "" || i.AccessVLAN != 0 || i.AllowedVLANs != nil
	if switchport && !strings.HasPrefix(i.Name, "Ethernet") && !strings.HasPrefix(i.Name, "Port-Channel") {
		return fmt.Errorf("mode, access_vlan and allowed_vlans are switchport settings, which %s doesn't have", i.Name)
	}
	if i.AccessVLAN != 0 && i.Mode == "trunk" {
		return errors.New("access_vlan is for mode \"access\"; a trunk takes allowed_vlans")
	}
	if i.AllowedVLANs != nil && i.Mode == "access" {
		return errors.New("allowed_vlans is for mode \"trunk\"; an access port takes access_vlan")
	}
	for _, v := range append([]int{i.AccessVLAN}, i.AllowedVLANs...) {
		if v != 0 && (v < 1 || v > 4094) {
			return fmt.Errorf("VLAN %d must be between 1 and 4094", v)
		}
	}
	if i.AllowedVLANs != nil && len(i.AllowedVLANs) == 0 {
		return errors.New("allowed_vlans must name at least one VLAN; leave it unset to leave the trunk's list alone")
	}
	if i.MTU != 0 && (i.MTU < 68 || i.MTU > 9214) {
		return fmt.Errorf("mtu must be between 68 and 9214, not %d", i.MTU)
	}
	return nil
}

// setting is one thing eos_interface owns: the line running-config shows
// for it, found by prefix, and the line wanted ("" for none).
type setting struct {
	prefix, want string
}

func (i Interface) settings() []setting {
	var s []setting
	if i.Description != nil {
		s = append(s, setting{"description ", "description " + *i.Description})
	}
	if i.Enabled != nil {
		want := "shutdown"
		if *i.Enabled {
			want = ""
		}
		s = append(s, setting{"shutdown", want})
	}
	switch i.Mode {
	case "trunk":
		s = append(s, setting{"switchport mode ", "switchport mode trunk"})
	case "access": // EOS's default, which running-config doesn't print
		s = append(s, setting{"switchport mode ", ""})
	}
	if i.AccessVLAN != 0 {
		want := "switchport access vlan " + strconv.Itoa(i.AccessVLAN)
		if i.AccessVLAN == 1 {
			want = "" // the default, not printed either
		}
		s = append(s, setting{"switchport access vlan ", want})
	}
	if i.AllowedVLANs != nil {
		s = append(s, setting{"switchport trunk allowed vlan ", "switchport trunk allowed vlan " + vlanRanges(i.AllowedVLANs)})
	}
	if i.MTU != 0 {
		s = append(s, setting{"mtu ", "mtu " + strconv.Itoa(i.MTU)})
	}
	return s
}

// vlanRanges writes VLANs the way EOS prints them: sorted, with runs as
// ranges, as in 10,20-22.
func vlanRanges(vlans []int) string {
	v := slices.Clone(vlans)
	sort.Ints(v)
	v = slices.Compact(v)
	var parts []string
	for n := 0; n < len(v); {
		end := n
		for end+1 < len(v) && v[end+1] == v[end]+1 {
			end++
		}
		if end > n {
			parts = append(parts, fmt.Sprintf("%d-%d", v[n], v[end]))
		} else {
			parts = append(parts, strconv.Itoa(v[n]))
		}
		n = end + 1
	}
	return strings.Join(parts, ",")
}

func (i Interface) parents() []string { return []string{"interface " + i.Name} }

// have is the line under the interface that matches prefix, or "".
func have(lines []string, prefix string) string {
	for _, l := range lines {
		if l == prefix || strings.HasPrefix(l, prefix) {
			return l
		}
	}
	return ""
}

// InSync reports whether the interface has every setting i owns.
func (i Interface) InSync(config string) bool {
	lines, found := Section(config, i.parents())
	if !found {
		return false
	}
	for _, s := range i.settings() {
		if have(lines, s.prefix) != s.want {
			return false
		}
	}
	return true
}

// Commands are what makes the interface have what i owns, or nil.
func (i Interface) Commands(config string) []string {
	lines, found := Section(config, i.parents())
	var cmds []string
	for _, s := range i.settings() {
		got := have(lines, s.prefix)
		switch {
		case got == s.want:
		case s.want == "":
			cmds = append(cmds, negate(got))
		default:
			cmds = append(cmds, s.want)
		}
	}
	if found && len(cmds) == 0 {
		return nil
	}
	return append(i.parents(), cmds...)
}

// RemoveCommands take the settings i owns back to EOS's defaults, for
// on_remove = "delete". The interface itself stays.
func (i Interface) RemoveCommands(config string) []string {
	lines, found := Section(config, i.parents())
	if !found {
		return nil
	}
	var cmds []string
	for _, s := range i.settings() {
		if got := have(lines, s.prefix); got != "" && got == s.want {
			cmds = append(cmds, negate(got))
		}
	}
	if len(cmds) == 0 {
		return nil
	}
	return append(i.parents(), cmds...)
}

// Guard refuses shutting down the interface that holds address, the one
// Conn3x reaches the switch at. The revert timer would undo it, but only
// after the full wait.
func (i Interface) Guard(config, address string) error {
	if i.Enabled == nil || *i.Enabled {
		return nil
	}
	lines, _ := Section(config, i.parents())
	for _, l := range lines {
		if ip, ok := strings.CutPrefix(l, "ip address "); ok && strings.SplitN(ip, "/", 2)[0] == address {
			return fmt.Errorf("Conn3x reaches this switch at %s, which is %s's address, so shutting %s down would cut it off. Change it from another address, or by hand", address, i.Name, i.Name)
		}
	}
	return nil
}
