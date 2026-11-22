// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ios

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Interface is the settings ios_interface owns on one interface. Each one
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

var (
	interfaceName = regexp.MustCompile(`^((Fast|Gigabit|TenGigabit|FortyGigabit)?Ethernet|TwentyFiveGigE|HundredGigE)[0-9]+(/[0-9]+)*$|^(Port-channel|Vlan|Loopback)[0-9]+$`)
	switchported  = regexp.MustCompile(`^((Fast|Gigabit|TenGigabit|FortyGigabit)?Ethernet|TwentyFiveGigE|HundredGigE|Port-channel)[0-9]`)
)

// Validate checks an Interface before anything reaches the device.
func (i Interface) Validate() error {
	if !interfaceName.MatchString(i.Name) {
		return fmt.Errorf("name %q is not an interface name as show running-config prints it, such as GigabitEthernet1/0/1, Port-channel10, Vlan20 or Loopback0", i.Name)
	}
	if i.Description != nil {
		if *i.Description == "" || checkLine("description "+*i.Description) != nil {
			return errors.New("description must be one line, without leading or trailing spaces")
		}
	}
	switch i.Mode {
	case "", "access", "trunk":
	default:
		return fmt.Errorf("mode must be \"access\" or \"trunk\", not %q", i.Mode)
	}
	if (i.Mode != "" || i.AccessVLAN != 0 || i.AllowedVLANs != nil) && !switchported.MatchString(i.Name) {
		return fmt.Errorf("mode, access_vlan and allowed_vlans are switchport settings, which %s doesn't have", i.Name)
	}
	if i.AccessVLAN != 0 && i.Mode == "trunk" {
		return errors.New("access_vlan is for mode \"access\"; a trunk takes allowed_vlans")
	}
	if i.AllowedVLANs != nil && i.Mode == "access" {
		return errors.New("allowed_vlans is for mode \"trunk\"; an access port takes access_vlan")
	}
	if i.AllowedVLANs != nil && len(i.AllowedVLANs) == 0 {
		return errors.New("allowed_vlans must name at least one VLAN; leave it unset to leave the trunk's list alone")
	}
	for _, v := range append([]int{i.AccessVLAN}, i.AllowedVLANs...) {
		if v != 0 && (v < 1 || v > 4094) {
			return fmt.Errorf("VLAN %d must be between 1 and 4094", v)
		}
	}
	if i.MTU != 0 && (i.MTU < 64 || i.MTU > 9216) {
		return fmt.Errorf("mtu must be between 64 and 9216, not %d", i.MTU)
	}
	return nil
}

// setting is one thing ios_interface owns: the prefix of the line show
// running-config prints for it, and the line wanted ("" for none). Its
// "no" form, "no " and the prefix, takes it back to IOS's default.
type setting struct {
	prefix, want string
}

const allowedPrefix = "switchport trunk allowed vlan "

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
	if i.Mode != "" {
		s = append(s, setting{"switchport mode ", "switchport mode " + i.Mode})
	}
	if i.AccessVLAN != 0 {
		want := "switchport access vlan " + strconv.Itoa(i.AccessVLAN)
		if i.AccessVLAN == 1 {
			want = "" // the default, which show running-config leaves out
		}
		s = append(s, setting{"switchport access vlan ", want})
	}
	if i.AllowedVLANs != nil {
		s = append(s, setting{allowedPrefix, allowedPrefix + vlanRanges(i.AllowedVLANs)})
	}
	if i.MTU != 0 {
		s = append(s, setting{"mtu ", "mtu " + strconv.Itoa(i.MTU)})
	}
	return s
}

func (s setting) reset() string { return "no " + strings.TrimSpace(s.prefix) }

// got is what the interface has for s, written as s.want would be. A trunk
// list longer than a line goes on over "switchport trunk allowed vlan add"
// lines, so the list is read across them and compared as a set.
func (s setting) got(lines []string) string {
	if s.prefix == allowedPrefix {
		vlans, seen, err := trunkVLANs(lines)
		switch {
		case err != nil:
			return err.Error() // not a list Conn3x writes, so never in sync
		case !seen:
			return ""
		}
		return allowedPrefix + vlanRanges(vlans)
	}
	for _, l := range lines {
		if l == s.prefix || strings.HasPrefix(l, s.prefix) {
			return l
		}
	}
	return ""
}

// vlanRanges writes VLANs sorted, with runs as ranges, as in 10,20-22.
func vlanRanges(vlans []int) string {
	v := slices.Clone(vlans)
	slices.Sort(v)
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

// trunkVLANs reads a trunk's list across its add lines. seen is false when
// there's no list line, which IOS takes as every VLAN.
func trunkVLANs(lines []string) (vlans []int, seen bool, err error) {
	for _, l := range lines {
		list, ok := strings.CutPrefix(l, allowedPrefix)
		if !ok {
			continue
		}
		list = strings.TrimPrefix(list, "add ")
		seen = true
		if list == "none" {
			continue
		}
		v, err := parseVLANs(list)
		if err != nil {
			return nil, true, fmt.Errorf("unread %q", l)
		}
		vlans = append(vlans, v...)
	}
	return vlans, seen, nil
}

// trunkLine is how much of a VLAN list one command carries, since IOS's
// input limit isn't known.
const trunkLine = 200

// trunkCommands bring a trunk's list to want. A list that fits one command
// replaces the old one at once. A longer one can't, since IOS applies each
// line as it comes and a replacing first line would drop every VLAN in the
// later ones until they arrived, management included. So it goes as add
// lines for what's missing, then remove lines for what's going: a VLAN in
// both lists never leaves the trunk.
func trunkCommands(lines []string, want []int) []string {
	if list := vlanRanges(want); len(list) <= trunkLine {
		return []string{allowedPrefix + list}
	}
	all := make([]int, 4094)
	for n := range all {
		all[n] = n + 1
	}
	current, seen, err := trunkVLANs(lines)
	add := want
	switch {
	case err != nil:
		// The list can't be read, so add all of want; adding a VLAN the
		// trunk has does nothing.
		current = all
	case !seen:
		current = all
	default:
		add = minus(want, current)
	}
	return append(chunked(allowedPrefix+"add ", add), chunked(allowedPrefix+"remove ", minus(current, want))...)
}

func minus(a, b []int) []int {
	var in [4095]bool
	for _, v := range b {
		in[v] = true
	}
	var out []int
	for _, v := range a {
		if !in[v] {
			out = append(out, v)
		}
	}
	return out
}

// chunked writes vlans as verb lines of at most trunkLine characters of
// list each, cut at a comma.
func chunked(verb string, vlans []int) []string {
	var cmds []string
	list := vlanRanges(vlans)
	for list != "" {
		part := list
		if len(part) > trunkLine {
			part = part[:strings.LastIndex(part[:trunkLine], ",")]
		}
		cmds = append(cmds, verb+part)
		list = strings.TrimPrefix(list[len(part):], ",")
	}
	return cmds
}

// parseVLANs reads a list such as 10,20-22 back into VLANs.
func parseVLANs(list string) ([]int, error) {
	var vlans []int
	for _, part := range strings.Split(list, ",") {
		lo, hi, isRange := strings.Cut(part, "-")
		a, err := strconv.Atoi(lo)
		if err != nil {
			return nil, err
		}
		b := a
		if isRange {
			if b, err = strconv.Atoi(hi); err != nil || b < a || b > 4094 {
				return nil, fmt.Errorf("VLAN range %q", part)
			}
		}
		for v := a; v <= b; v++ {
			vlans = append(vlans, v)
		}
	}
	return vlans, nil
}

func (i Interface) parents() []string { return []string{"interface " + i.Name} }

func (i Interface) indented(cmds []string) []string {
	out := i.parents()
	for _, c := range cmds {
		out = append(out, " "+c)
	}
	return out
}

// InSync reports whether the interface has every setting i owns.
func (i Interface) InSync(config string) bool {
	lines, found := section(config, i.parents())
	if !found {
		return false
	}
	for _, s := range i.settings() {
		if s.got(lines) != s.want {
			return false
		}
	}
	return true
}

// Commands are what makes the interface have what i owns, or nil.
func (i Interface) Commands(config string) []string {
	lines, found := section(config, i.parents())
	var cmds []string
	for _, s := range i.settings() {
		switch got := s.got(lines); {
		case got == s.want:
		case s.want == "":
			cmds = append(cmds, s.reset())
		case s.prefix == allowedPrefix:
			cmds = append(cmds, trunkCommands(lines, i.AllowedVLANs)...)
		default:
			cmds = append(cmds, s.want)
		}
	}
	if found && len(cmds) == 0 {
		return nil
	}
	return i.indented(cmds)
}

// RemoveCommands take the settings i owns back to IOS's defaults, for
// on_remove = "delete". The interface itself stays.
func (i Interface) RemoveCommands(config string) []string {
	lines, found := section(config, i.parents())
	if !found {
		return nil
	}
	var cmds []string
	for _, s := range i.settings() {
		if got := s.got(lines); got != "" && got == s.want {
			cmds = append(cmds, s.reset())
		}
	}
	if len(cmds) == 0 {
		return nil
	}
	return i.indented(cmds)
}

// Guard refuses shutting down the interface that holds address, the one
// Conn3x reaches the device at. The revert timer would undo it, but only
// after the full wait.
func (i Interface) Guard(config, address string) error {
	if i.Enabled == nil || *i.Enabled {
		return nil
	}
	lines, _ := section(config, i.parents())
	for _, l := range lines {
		if f := strings.Fields(strings.TrimPrefix(l, "ip address ")); strings.HasPrefix(l, "ip address ") && len(f) > 0 && f[0] == address {
			return fmt.Errorf("Conn3x reaches this device at %s, which is %s's address, so shutting %s down would cut it off. Change it from another address, or by hand", address, i.Name, i.Name)
		}
	}
	return nil
}
