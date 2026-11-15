// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package windows

import (
	"slices"
	"testing"
)

func TestDNSRecordChanges(t *testing.T) {
	d := DNSRecord{Zone: "corp.example.com", Name: "www", Type: "A", Values: []string{"10.0.1.11", "10.0.1.12"}, TTL: 300}
	if err := d.Validate(); err != nil {
		t.Fatal(err)
	}
	a := ActualDNSRecord{Zone: true, Values: []string{"10.0.1.11", "10.0.1.9"}, TTL: 3600}
	add, remove, setTTL := d.changes(a)
	if !slices.Equal(add, []string{"10.0.1.12"}) || !slices.Equal(remove, []string{"10.0.1.9"}) || !setTTL {
		t.Errorf("add %v, remove %v, ttl %v", add, remove, setTTL)
	}
	if d.Matches(a) {
		t.Error("matched before the changes")
	}
	// Everything is replaced: the new records carry the TTL, nothing to set.
	if _, _, setTTL := d.changes(ActualDNSRecord{Zone: true, Values: []string{"10.0.1.9"}, TTL: 3600}); setTTL {
		t.Error("set a TTL with nothing staying")
	}
	if !d.Matches(ActualDNSRecord{Zone: true, Values: []string{"10.0.1.12", "10.0.1.11"}, TTL: 300}) {
		t.Error("order mattered")
	}
	if d.Matches(ActualDNSRecord{Values: d.Values, TTL: 300}) {
		t.Error("matched without the zone")
	}

	// Names compare without case or the server's trailing dot, IPv6 in any form.
	c := DNSRecord{Zone: "corp.example.com", Name: "intranet", Type: "CNAME", Values: []string{"Web1.corp.example.com"}}
	if !c.Matches(ActualDNSRecord{Zone: true, Values: []string{"web1.corp.example.com."}, TTL: 3600}) {
		t.Error("CNAME didn't match the server's spelling")
	}
	six := DNSRecord{Zone: "corp.example.com", Name: "v6", Type: "AAAA", Values: []string{"2001:db8::1"}}
	if !six.Matches(ActualDNSRecord{Zone: true, Values: []string{"2001:0db8:0000:0000:0000:0000:0000:0001"}, TTL: 3600}) {
		t.Error("AAAA didn't match the long form")
	}

	for _, bad := range []DNSRecord{
		{Zone: "corp.example.com", Name: "www", Type: "MX", Values: []string{"x"}},
		{Zone: "corp.example.com", Name: "www", Type: "A", Values: []string{"2001:db8::1"}},
		{Zone: "corp.example.com", Name: "www", Type: "AAAA", Values: []string{"10.0.0.1"}},
		{Zone: "corp.example.com", Name: "www", Type: "A"},
		{Zone: "corp.example.com", Name: "www", Type: "CNAME", Values: []string{"a.example.com", "b.example.com"}},
		{Zone: "corp.example.com", Name: "www", Type: "PTR", Values: []string{"not a host"}},
		{Zone: "corp.example.com", Name: "www", Type: "TXT", Values: []string{"two\nlines"}},
		{Zone: "corp example", Name: "www", Type: "A", Values: []string{"10.0.0.1"}},
		{Zone: "corp.example.com", Name: "a b", Type: "A", Values: []string{"10.0.0.1"}},
		{Zone: "corp.example.com", Name: "www", Type: "A", Values: []string{"10.0.0.1"}, TTL: -1},
	} {
		if bad.Validate() == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	if (DNSRecord{Zone: "corp.example.com", Name: "@", Type: "TXT", Values: []string{"v=spf1 -all"}}).Validate() != nil {
		t.Error("refused a TXT at the zone apex")
	}
}
