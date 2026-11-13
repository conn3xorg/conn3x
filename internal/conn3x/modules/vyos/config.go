// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package vyos

import (
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"

	"github.com/opentofu/opentofu/internal/conn3x/modules/setcfg"
)

// quoted matches a single-quoted value, as show configuration commands
// prints every value: set system host-name 'r1'.
var quoted = regexp.MustCompile(`'([^']*)'`)

// Normalize writes a set line the one way Conn3x compares lines: a value
// with nothing a shell would split on goes bare, and one with a space
// keeps double quotes. VyOS prints single quotes and takes either, so a
// step can write a line the way it likes.
func Normalize(line string) string {
	return quoted.ReplaceAllStringFunc(line, func(m string) string {
		v := m[1 : len(m)-1]
		if v == "" || strings.ContainsAny(v, " \t\"$`\\;|&<>()") {
			return `"` + v + `"`
		}
		return v
	})
}

// Config is set lines as vyos_config owns them, normalized.
func Config(prefix string, lines []string, match string) setcfg.Config {
	norm := make([]string, len(lines))
	for i, l := range lines {
		norm[i] = Normalize(l)
	}
	return setcfg.Config{Prefix: prefix, Lines: norm, Match: match}
}

var hostnameRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

// ValidateHostname checks a name VyOS takes: letters, digits and hyphens.
func ValidateHostname(name string) error {
	if !hostnameRe.MatchString(name) {
		return fmt.Errorf("hostname %q must be letters, digits and hyphens, starting and ending with a letter or digit, at most 63 characters", name)
	}
	return nil
}

// Hostname is the router's name, one leaf.
func Hostname(name string) setcfg.Leaf { return setcfg.Leaf{Path: "system host-name", Value: name} }

// Interface is the settings vyos_interface owns on one interface.
type Interface struct {
	Name        string
	Description *string
	Addresses   []string // CIDR or dhcp/dhcpv6; nil leaves them alone
	Enabled     *bool
	MTU         int
}

var interfaceTypes = map[string]string{"eth": "ethernet", "bond": "bonding", "br": "bridge", "lo": "loopback", "wg": "wireguard"}

var interfaceName = regexp.MustCompile(`^(eth|bond|br|wg)[0-9]+$|^lo$`)

// kind is the configuration node the interface lives under.
func (i Interface) kind() string {
	for prefix, t := range interfaceTypes {
		if strings.HasPrefix(i.Name, prefix) {
			return t
		}
	}
	return ""
}

func (i Interface) path() string { return "interfaces " + i.kind() + " " + i.Name }

// Validate checks an Interface before anything reaches the router.
func (i Interface) Validate() error {
	if !interfaceName.MatchString(i.Name) {
		return fmt.Errorf("name %q is not an interface name this step knows, such as eth0, bond0, br0, wg0 or lo", i.Name)
	}
	if i.Description != nil {
		if *i.Description == "" || strings.ContainsAny(*i.Description, "'\"\\") {
			return fmt.Errorf("description must not be empty or hold a quote or backslash")
		}
		if err := setcfg.CheckText(*i.Description, "description"); err != nil {
			return err
		}
	}
	for _, a := range i.Addresses {
		if a == "dhcp" || a == "dhcpv6" {
			continue
		}
		if _, err := netip.ParsePrefix(a); err != nil {
			return fmt.Errorf("address %q must be an address with its prefix length, such as 192.0.2.1/24, or dhcp or dhcpv6", a)
		}
	}
	if i.MTU != 0 && (i.MTU < 68 || i.MTU > 16000) {
		return fmt.Errorf("mtu must be between 68 and 16000, not %d", i.MTU)
	}
	return nil
}

func (i Interface) leaves() []setcfg.Leaf {
	var l []setcfg.Leaf
	if i.Description != nil {
		l = append(l, setcfg.Leaf{Path: i.path() + " description", Value: Normalize("'" + *i.Description + "'")})
	}
	if i.MTU != 0 {
		l = append(l, setcfg.Leaf{Path: i.path() + " mtu", Value: fmt.Sprint(i.MTU)})
	}
	return l
}

func (i Interface) addrPath() string    { return i.path() + " address" }
func (i Interface) disableLine() string { return "set " + i.path() + " disable" }

func (i Interface) haveAddrs(lines []string) []string {
	var a []string
	for _, l := range lines {
		if v, ok := strings.CutPrefix(l, "set "+i.addrPath()+" "); ok {
			a = append(a, v)
		}
	}
	return a
}

// InSync reports whether the interface has every setting i owns.
func (i Interface) InSync(config string) bool { return i.Commands(config) == nil }

// Commands are what makes the interface have what i owns, or nil.
func (i Interface) Commands(config string) []string {
	lines := setcfg.SetLines(config)
	var cmds []string
	for _, f := range i.leaves() {
		cmds = append(cmds, f.Commands(config)...)
	}
	if i.Enabled != nil {
		disabled := slices.Contains(lines, i.disableLine())
		switch {
		case *i.Enabled && disabled:
			cmds = append(cmds, "delete "+i.path()+" disable")
		case !*i.Enabled && !disabled:
			cmds = append(cmds, i.disableLine())
		}
	}
	if i.Addresses != nil {
		have := i.haveAddrs(lines)
		for _, h := range have {
			if !slices.Contains(i.Addresses, h) {
				cmds = append(cmds, "delete "+i.addrPath()+" "+h)
			}
		}
		for _, w := range i.Addresses {
			if !slices.Contains(have, w) {
				cmds = append(cmds, "set "+i.addrPath()+" "+w)
			}
		}
	}
	return cmds
}

// RemoveCommands take the settings i owns away, for on_remove = "delete".
// The interface itself stays.
func (i Interface) RemoveCommands(config string) []string {
	lines := setcfg.SetLines(config)
	var cmds []string
	for _, f := range i.leaves() {
		if got := setcfg.HaveLeaf(lines, f.Path); got != "" {
			cmds = append(cmds, "delete "+f.Path)
		}
	}
	if i.Enabled != nil && !*i.Enabled && slices.Contains(lines, i.disableLine()) {
		cmds = append(cmds, "delete "+i.path()+" disable")
	}
	for _, h := range i.haveAddrs(lines) {
		if slices.Contains(i.Addresses, h) {
			cmds = append(cmds, "delete "+i.addrPath()+" "+h)
		}
	}
	return cmds
}

// Guard refuses what would cut Conn3x off from the router at address:
// disabling the interface that holds it, or taking the address off it.
func (i Interface) Guard(config, address string) error {
	holds := false
	for _, a := range i.haveAddrs(setcfg.SetLines(config)) {
		if p, err := netip.ParsePrefix(a); err == nil && p.Addr().String() == address {
			holds = true
			if i.Addresses != nil && !slices.Contains(i.Addresses, a) {
				return fmt.Errorf("Conn3x reaches this router at %s, which is %s's address %s, so taking it off would cut it off. Keep it in addresses, or change it by hand", address, i.Name, a)
			}
		}
	}
	if holds && i.Enabled != nil && !*i.Enabled {
		return fmt.Errorf("Conn3x reaches this router at %s, which is %s's address, so disabling %s would cut it off. Change it from another address, or by hand", address, i.Name, i.Name)
	}
	return nil
}
