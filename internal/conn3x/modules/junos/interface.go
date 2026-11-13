// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package junos

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Interface is the settings junos_interface owns on one interface. Each one
// left unset is left alone, and so is every other statement under the
// interface, such as its addresses.
type Interface struct {
	Name         string
	Description  *string
	Enabled      *bool
	Mode         string   // "access", "trunk" or "" to leave
	AccessVLAN   string   // a VLAN name or ID; "" to leave
	AllowedVLANs []string // nil to leave
	MTU          int      // 0 to leave
}

var (
	interfaceName = regexp.MustCompile(`^((ge|xe|et|mge|fe)-[0-9]+/[0-9]+/[0-9]+|ae[0-9]+|irb|lo0|fxp0|em[0-9]+|me[0-9]+|vme)$`)
	switchPort    = regexp.MustCompile(`^((ge|xe|et|mge|fe)-|ae[0-9])`)
	vlanMember    = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9_.-]{0,63}|[0-9]{1,4}(-[0-9]{1,4})?)$`)
)

// management interfaces carry the out-of-band address on Junos platforms.
var management = []string{"fxp0", "em0", "me0", "vme"}

// Validate checks an Interface before anything reaches the device.
func (i Interface) Validate() error {
	if !interfaceName.MatchString(i.Name) {
		return fmt.Errorf("name %q is not a Junos interface name, such as ge-0/0/1, xe-0/0/48, ae0, irb or lo0", i.Name)
	}
	if i.Description != nil {
		if *i.Description == "" || strings.ContainsAny(*i.Description, "\"\\") {
			return errors.New("description must not be empty or hold a double quote or backslash")
		}
		if err := checkText(*i.Description, "description"); err != nil {
			return err
		}
	}
	switch i.Mode {
	case "", "access", "trunk":
	default:
		return fmt.Errorf("mode must be \"access\" or \"trunk\", not %q", i.Mode)
	}
	if (i.Mode != "" || i.AccessVLAN != "" || i.AllowedVLANs != nil) && !switchPort.MatchString(i.Name) {
		return fmt.Errorf("mode, access_vlan and allowed_vlans are ethernet-switching settings, which %s doesn't have", i.Name)
	}
	if i.AccessVLAN != "" && i.Mode == "trunk" {
		return errors.New("access_vlan is for mode \"access\"; a trunk takes allowed_vlans")
	}
	if i.AllowedVLANs != nil && i.Mode == "access" {
		return errors.New("allowed_vlans is for mode \"trunk\"; an access port takes access_vlan")
	}
	if i.AllowedVLANs != nil && len(i.AllowedVLANs) == 0 {
		return errors.New("allowed_vlans must name at least one VLAN; leave it unset to leave the trunk's members alone")
	}
	for _, v := range append([]string{i.AccessVLAN}, i.AllowedVLANs...) {
		if v != "" && !vlanMember.MatchString(v) {
			return fmt.Errorf("VLAN %q must be a VLAN name, an ID such as 10, or a range such as 20-22", v)
		}
	}
	if i.MTU != 0 && (i.MTU < 256 || i.MTU > 9216) {
		return fmt.Errorf("mtu must be between 256 and 9216, not %d", i.MTU)
	}
	return nil
}

func (i Interface) path() string { return "interfaces " + i.Name }

func (i Interface) eswitch() string { return i.path() + " unit 0 family ethernet-switching" }

// quote writes a value the way display set prints it: quoted when it holds
// a space or a character the CLI would read otherwise.
func quote(s string) string {
	if strings.ContainsAny(s, " ;{}#'|") {
		return `"` + s + `"`
	}
	return s
}

// leaf is one single-valued statement the interface owns: its path, and
// the full set line wanted, "" for none.
type leaf struct{ path, want string }

func (i Interface) leaves() []leaf {
	var l []leaf
	if i.Description != nil {
		l = append(l, leaf{i.path() + " description", "set " + i.path() + " description " + quote(*i.Description)})
	}
	if i.Enabled != nil {
		want := "set " + i.path() + " disable"
		if *i.Enabled {
			want = ""
		}
		l = append(l, leaf{i.path() + " disable", want})
	}
	if i.MTU != 0 {
		l = append(l, leaf{i.path() + " mtu", "set " + i.path() + " mtu " + strconv.Itoa(i.MTU)})
	}
	if i.Mode != "" {
		l = append(l, leaf{i.eswitch() + " interface-mode", "set " + i.eswitch() + " interface-mode " + i.Mode})
	}
	return l
}

// members is the VLAN list i owns, or nil when it owns none.
func (i Interface) members() []string {
	if i.AccessVLAN != "" {
		return []string{i.AccessVLAN}
	}
	return i.AllowedVLANs
}

func (i Interface) memberPath() string { return i.eswitch() + " vlan members" }

// haveLeaf is the set line at path, or "".
func haveLeaf(lines []string, path string) string {
	for _, l := range lines {
		if under(l, path) {
			return l
		}
	}
	return ""
}

func haveMembers(lines []string, path string) []string {
	var m []string
	for _, l := range lines {
		if v, ok := strings.CutPrefix(l, "set "+path+" "); ok {
			m = append(m, v)
		}
	}
	return m
}

// InSync reports whether the interface has every setting i owns.
func (i Interface) InSync(config string) bool { return i.Commands(config) == nil }

// Commands are what makes the interface have what i owns, or nil. A leaf
// with another value is deleted before it's set, so WithLines, which can't
// tell a leaf from a list, shows the next step only the new value. VLAN
// members are a list: the ones not wanted are deleted.
func (i Interface) Commands(config string) []string {
	lines := SetLines(config)
	var cmds []string
	for _, f := range i.leaves() {
		got := haveLeaf(lines, f.path)
		switch {
		case got == f.want:
		case f.want == "":
			cmds = append(cmds, "delete "+f.path)
		case got != "":
			cmds = append(cmds, "delete "+f.path, f.want)
		default:
			cmds = append(cmds, f.want)
		}
	}
	if want := i.members(); want != nil {
		have := haveMembers(lines, i.memberPath())
		for _, h := range have {
			if !slices.Contains(want, h) {
				cmds = append(cmds, "delete "+i.memberPath()+" "+h)
			}
		}
		for _, w := range want {
			if !slices.Contains(have, w) {
				cmds = append(cmds, "set "+i.memberPath()+" "+w)
			}
		}
	}
	return cmds
}

// RemoveCommands take the settings i owns back to Junos's defaults, for
// on_remove = "delete": each leaf it set is deleted, and so are its VLAN
// members. The interface itself stays.
func (i Interface) RemoveCommands(config string) []string {
	lines := SetLines(config)
	var cmds []string
	for _, f := range i.leaves() {
		if got := haveLeaf(lines, f.path); got != "" && got == f.want {
			cmds = append(cmds, "delete "+f.path)
		}
	}
	if want := i.members(); want != nil {
		for _, h := range haveMembers(lines, i.memberPath()) {
			if slices.Contains(want, h) {
				cmds = append(cmds, "delete "+i.memberPath()+" "+h)
			}
		}
	}
	return cmds
}

// Guard refuses disabling a management interface, or the interface that
// holds address, the one Conn3x reaches the device at. commit confirmed
// would undo either, but only after the full wait.
func (i Interface) Guard(config, address string) error {
	if i.Enabled == nil || *i.Enabled {
		return nil
	}
	if slices.Contains(management, i.Name) {
		return fmt.Errorf("%s is a management interface, and disabling it would most likely cut Conn3x off. Change it by hand", i.Name)
	}
	for _, l := range SetLines(config) {
		rest, ok := strings.CutPrefix(l, "set "+i.path()+" unit ")
		if !ok {
			continue
		}
		if _, addr, ok := strings.Cut(rest, " address "); ok && strings.SplitN(strings.Fields(addr)[0], "/", 2)[0] == address {
			return fmt.Errorf("Conn3x reaches this device at %s, which is %s's address, so disabling %s would cut it off. Change it from another address, or by hand", address, i.Name, i.Name)
		}
	}
	return nil
}
