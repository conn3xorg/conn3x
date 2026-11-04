// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package windows

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/opentofu/opentofu/internal/conn3x/modules/windows/ps"
)

// Windows expands * ? and [ ] in -InterfaceAlias, and a backtick escapes them,
// so a name can't hold any of them.
var interfaceAlias = regexp.MustCompile("^[^*?\\[\\]`\\x00-\\x1f\\x7f]{1,256}$")

// DNSClient is the list of DNS servers one network interface asks, in order.
type DNSClient struct {
	Interface string // alias, such as Ethernet; empty is the one with the IPv4 default route
	Servers   []string
}

// Validate checks a DNSClient before anything reaches a host.
func (d DNSClient) Validate() error {
	_, err := d.Check()
	return err
}

// Check is Validate, also naming the attribute at fault.
func (d DNSClient) Check() (attr string, err error) {
	if d.Interface != "" && (!interfaceAlias.MatchString(d.Interface) || strings.TrimSpace(d.Interface) != d.Interface) {
		return "interface", fmt.Errorf("interface %q isn't an interface name: no * ? [ ] `, control characters or spaces at either end", d.Interface)
	}
	if len(d.Servers) == 0 {
		return "servers", errors.New("list at least one server")
	}
	seen := map[netip.Addr]bool{}
	for _, s := range d.Servers {
		a, err := netip.ParseAddr(s)
		if err != nil || a.Zone() != "" || a.Is4In6() {
			return "servers", fmt.Errorf("server %q must be a plain IPv4 or IPv6 address, such as 10.0.0.4", s)
		}
		if a.IsUnspecified() || a.IsMulticast() || a == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
			return "servers", fmt.Errorf("server %s can't be a DNS server: it's unspecified, broadcast or multicast", s)
		}
		if seen[a] {
			return "servers", fmt.Errorf("server %s is listed twice", s)
		}
		seen[a] = true
	}
	return "", nil
}

// families splits the servers into IPv4 and IPv6, each in order.
func families(list []string) (v4, v6 []netip.Addr) {
	for _, s := range list {
		a, err := netip.ParseAddr(s)
		switch {
		case err != nil:
			v6 = append(v6, netip.Addr{}) // never equal to a real one
		case a.Is4():
			v4 = append(v4, a)
		default:
			v6 = append(v6, a)
		}
	}
	return v4, v6
}

// ActualDNSClient is what an interface has now.
type ActualDNSClient struct {
	Found bool
	Index int
	Alias string
	IPv4  []string
	IPv6  []string
}

// ReadDNSClient reads an interface's DNS servers.
func ReadDNSClient(ctx context.Context, r ps.Runner, d DNSClient) (ActualDNSClient, error) {
	res, err := ps.Read(ctx, r, script("read_dns_client.ps1"), map[string]any{"interface": d.Interface})
	if err != nil {
		return ActualDNSClient{}, err
	}
	var a struct {
		Found bool     `json:"found"`
		Index int      `json:"index"`
		Alias string   `json:"alias"`
		IPv4  []string `json:"ipv4"`
		IPv6  []string `json:"ipv6"`
	}
	if err := json.Unmarshal(res.Value, &a); err != nil {
		return ActualDNSClient{}, errors.New("reading DNS servers: the host's answer wasn't valid")
	}
	return ActualDNSClient(a), nil
}

// Matches reports whether the interface asks the servers as configured. Only
// the address families the list has count: listing IPv4 servers alone leaves
// IPv6 as Windows has it.
func (d DNSClient) Matches(a ActualDNSClient) bool {
	if !a.Found {
		return false
	}
	want4, want6 := families(d.Servers)
	have4, _ := families(a.IPv4)
	_, have6 := families(a.IPv6)
	return (len(want4) == 0 || slices.Equal(want4, have4)) && (len(want6) == 0 || slices.Equal(want6, have6))
}

// ApplyDNSClient sets the interface's servers.
func ApplyDNSClient(ctx context.Context, r ps.Runner, d DNSClient) error {
	_, err := ps.Apply(ctx, r, script("apply_dns_client.ps1"), map[string]any{"interface": d.Interface, "servers": d.Servers}, time.Minute)
	return err
}
