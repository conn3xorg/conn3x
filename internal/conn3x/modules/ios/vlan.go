// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ios

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// VLAN is one VLAN and its name, as ios_vlan owns it. Name "" is IOS's
// default, such as VLAN0010, so a name set by hand is taken away.
type VLAN struct {
	ID   int
	Name string
}

// Validate checks the ID and name. VLAN 1 and 1002 to 1005 are IOS's own
// and can't be renamed or deleted.
func (v VLAN) Validate() error {
	if v.ID < 1 || v.ID > 4094 {
		return fmt.Errorf("vlan_id must be between 1 and 4094, not %d", v.ID)
	}
	if v.ID == 1 || (v.ID >= 1002 && v.ID <= 1005) {
		return fmt.Errorf("VLAN %d is one IOS keeps for itself; it can't be renamed or deleted", v.ID)
	}
	// ASCII only: IOS VLAN names are, and it keeps out look-alike,
	// zero-width and bidi characters. ? would ask the CLI for help.
	if strings.ContainsFunc(v.Name, func(r rune) bool { return r <= ' ' || r > '~' || r == '?' }) || len(v.Name) > 32 {
		return errors.New("name must be one word of at most 32 printable ASCII characters, without ?")
	}
	return nil
}

func (v VLAN) parent() string { return fmt.Sprintf("vlan %d", v.ID) }

// lines is what show running-config has under the VLAN, and whether the
// VLAN is there at all. A VLAN with nothing set under it can be printed in
// a list with others, as in "vlan 10,20-22".
func (v VLAN) lines(config string) ([]string, bool) {
	if lines, ok := section(config, []string{v.parent()}); ok {
		return lines, true
	}
	for _, k := range parse(config).kids {
		if list, ok := strings.CutPrefix(k.text, "vlan "); ok && len(k.kids) == 0 {
			if ids, err := parseVLANs(list); err == nil && slices.Contains(ids, v.ID) {
				return nil, true
			}
		}
	}
	return nil, false
}

func (v VLAN) haveName(lines []string) string {
	for _, l := range lines {
		if name, ok := strings.CutPrefix(l, "name "); ok {
			return name
		}
	}
	return ""
}

// InSync reports whether the VLAN is there with v's name.
func (v VLAN) InSync(config string) bool {
	lines, found := v.lines(config)
	return found && v.haveName(lines) == v.Name
}

// Commands make the VLAN and set its name, or nil.
func (v VLAN) Commands(config string) []string {
	if v.InSync(config) {
		return nil
	}
	lines, _ := v.lines(config)
	switch {
	case v.Name != "":
		return []string{v.parent(), " name " + v.Name}
	case v.haveName(lines) != "":
		return []string{v.parent(), " no name"}
	}
	return []string{v.parent()}
}

// RemoveCommands delete the VLAN, or nil when it isn't there.
func (v VLAN) RemoveCommands(config string) []string {
	if _, found := v.lines(config); !found {
		return nil
	}
	return []string{"no " + v.parent()}
}

// VTPLocal refuses a VLAN change unless the device keeps its VLANs to
// itself. In VTP server mode a change goes to every switch in the domain,
// and the VLANs live in vlan.dat, outside the running configuration the
// revert timer rolls back. Transparent mode (or off, in VTP version 3)
// keeps them local and in the running configuration, with the mode line.
func VTPLocal(config string) error {
	for _, k := range parse(config).kids {
		if k.text == "vtp mode transparent" || k.text == "vtp mode off" {
			return nil
		}
	}
	return errors.New(`the device's running configuration has no "vtp mode transparent" or "vtp mode off" line. In VTP server mode a VLAN change goes to every switch in the domain and isn't covered by the revert timer, so ios_vlan changes VLANs only on a device in transparent mode. Set "vtp mode transparent" first, for example with an ios_config step before this one`)
}
