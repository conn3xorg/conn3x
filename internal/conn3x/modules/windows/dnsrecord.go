// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package windows

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/opentofu/opentofu/internal/conn3x/modules/windows/ps"
)

// DNSRecord is one name's records of one type in a zone on a Windows DNS
// server, owned as a set: Values is every value it has.
type DNSRecord struct {
	Zone, Name, Type string
	Values           []string
	TTL              int // seconds; 0 is the zone's default, 3600
}

var (
	dnsTypes      = []string{"A", "AAAA", "CNAME", "PTR", "TXT"}
	dnsRecordName = regexp.MustCompile(`^(@|\*|[A-Za-z0-9_]([A-Za-z0-9_-]{0,62})?(\.[A-Za-z0-9_]([A-Za-z0-9_-]{0,62})?)*)$`)
	dnsZone       = regexp.MustCompile(`^[A-Za-z0-9_]([A-Za-z0-9_-]{0,62})?(\.[A-Za-z0-9_]([A-Za-z0-9_-]{0,62})?)*$`)
	dnsHost       = regexp.MustCompile(`^[A-Za-z0-9_]([A-Za-z0-9_-]{0,62})?(\.[A-Za-z0-9_]([A-Za-z0-9_-]{0,62})?)*\.?$`)
)

// ttl is TTL with its default.
func (d DNSRecord) ttl() int {
	if d.TTL == 0 {
		return 3600
	}
	return d.TTL
}

// Validate checks a record before anything reaches the server.
func (d DNSRecord) Validate() error {
	if !dnsZone.MatchString(d.Zone) {
		return fmt.Errorf("zone %q must be a DNS zone, such as corp.example.com", d.Zone)
	}
	if !dnsRecordName.MatchString(d.Name) {
		return fmt.Errorf("name %q must be a name in the zone, such as www, or @ for the zone itself", d.Name)
	}
	if !slices.Contains(dnsTypes, d.Type) {
		return fmt.Errorf("type %q must be one of %s", d.Type, strings.Join(dnsTypes, ", "))
	}
	if len(d.Values) == 0 {
		return errors.New("values must name at least one value")
	}
	if d.Type == "CNAME" && len(d.Values) > 1 {
		return errors.New("a CNAME has one value")
	}
	if d.TTL < 0 || d.TTL > 2147483647 {
		return fmt.Errorf("ttl must be a number of seconds, not %d", d.TTL)
	}
	for _, v := range d.Values {
		ip := net.ParseIP(v)
		switch {
		case d.Type == "A" && (ip == nil || ip.To4() == nil):
			return fmt.Errorf("value %q must be an IPv4 address", v)
		case d.Type == "AAAA" && (ip == nil || ip.To4() != nil):
			return fmt.Errorf("value %q must be an IPv6 address", v)
		case (d.Type == "CNAME" || d.Type == "PTR") && !dnsHost.MatchString(v):
			return fmt.Errorf("value %q must be a host name, such as web1.corp.example.com", v)
		case d.Type == "TXT" && (v == "" || len(v) > 255 || strings.ContainsFunc(v, func(r rune) bool { return r < 0x20 })):
			return fmt.Errorf("value %q must be one line of text, up to 255 characters", v)
		}
	}
	return nil
}

// norm is how the server's value and the step's compare: addresses in
// their usual form, names without case or the trailing dot.
func (d DNSRecord) norm(v string) string {
	switch d.Type {
	case "A", "AAAA":
		if ip := net.ParseIP(v); ip != nil {
			return ip.String()
		}
	case "CNAME", "PTR":
		return strings.ToLower(strings.TrimSuffix(v, "."))
	}
	return v
}

// ActualDNSRecord is what the server has for the name and type.
type ActualDNSRecord struct {
	Zone   bool
	Values []string
	TTL    int
}

// ReadDNSRecord reads the name's records of the type.
func ReadDNSRecord(ctx context.Context, r ps.Runner, d DNSRecord) (ActualDNSRecord, error) {
	res, err := ps.Read(ctx, r, script("read_dns_record.ps1"), map[string]any{"zone": d.Zone, "name": d.Name, "type": d.Type})
	if err != nil {
		return ActualDNSRecord{}, err
	}
	var raw struct {
		Zone   bool            `json:"zone"`
		Values json.RawMessage `json:"values"`
		TTL    int             `json:"ttl"`
	}
	if err := json.Unmarshal(res.Value, &raw); err != nil {
		return ActualDNSRecord{}, errors.New("reading a DNS record: the host's answer wasn't valid")
	}
	a := ActualDNSRecord{Zone: raw.Zone, TTL: raw.TTL}
	if len(raw.Values) > 0 && string(raw.Values) != "null" {
		if err := json.Unmarshal(raw.Values, &a.Values); err != nil {
			var one string
			if err := json.Unmarshal(raw.Values, &one); err != nil {
				return ActualDNSRecord{}, errors.New("reading a DNS record: the host's answer wasn't valid")
			}
			a.Values = []string{one}
		}
	}
	return a, nil
}

// changes are the values to add and to remove, by the server's own spelling
// for removes, and whether the TTL needs setting on what stays.
func (d DNSRecord) changes(a ActualDNSRecord) (add, remove []string, setTTL bool) {
	want := map[string]bool{}
	for _, v := range d.Values {
		want[d.norm(v)] = true
	}
	have := map[string]bool{}
	for _, v := range a.Values {
		have[d.norm(v)] = true
		if !want[d.norm(v)] {
			remove = append(remove, v)
		}
	}
	for _, v := range d.Values {
		if !have[d.norm(v)] {
			add = append(add, v)
		}
	}
	return add, remove, len(a.Values) > len(remove) && a.TTL != d.ttl()
}

// Matches reports whether the server has exactly these values at the TTL.
func (d DNSRecord) Matches(a ActualDNSRecord) bool {
	add, remove, setTTL := d.changes(a)
	return a.Zone && add == nil && remove == nil && !setTTL
}

// ApplyDNSRecord adds what's missing, removes what isn't listed, and sets
// the TTL in place on what stays.
func ApplyDNSRecord(ctx context.Context, r ps.Runner, d DNSRecord) error {
	if err := d.Validate(); err != nil {
		return err
	}
	a, err := ReadDNSRecord(ctx, r, d)
	if err != nil {
		return err
	}
	if !a.Zone {
		return fmt.Errorf("this server has no DNS zone %s; run the step on the zone's DNS server, usually a domain controller", d.Zone)
	}
	add, remove, setTTL := d.changes(a)
	_, err = ps.Apply(ctx, r, script("apply_dns_record.ps1"), map[string]any{
		"zone": d.Zone, "name": d.Name, "type": d.Type, "ttl": d.ttl(), "add_values": add, "remove_values": remove, "set_ttl": setTTL,
	}, 2*time.Minute)
	return err
}

// ApplyDNSRecordRemove removes every one of the name's records of the type.
func ApplyDNSRecordRemove(ctx context.Context, r ps.Runner, d DNSRecord) error {
	a, err := ReadDNSRecord(ctx, r, d)
	if err != nil || !a.Zone || len(a.Values) == 0 {
		return err
	}
	_, err = ps.Apply(ctx, r, script("apply_dns_record.ps1"), map[string]any{
		"zone": d.Zone, "name": d.Name, "type": d.Type, "ttl": d.ttl(), "add_values": []string{}, "remove_values": a.Values, "set_ttl": false,
	}, 2*time.Minute)
	return err
}
