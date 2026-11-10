// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package facts

import (
	"reflect"
	"testing"
)

func TestParse(t *testing.T) {
	out := `id=rocky
version=10.0
like=rhel centos fedora
arch=x86_64
cpus=2
memory_kb=2013564
ipv4=203.0.113.10
`
	got, err := parse(out)
	if err != nil {
		t.Fatal(err)
	}
	want := Facts{Family: "redhat", ID: "rocky", Version: "10.0", Arch: "x86_64", CPUs: 2, MemoryMB: 1966, IPv4: "203.0.113.10"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}

	deb, err := parse("id=ubuntu\nversion=24.04\nlike=debian\narch=aarch64\ncpus=4\nmemory_kb=4096000\nipv4=\n")
	if err != nil || deb.Family != "debian" || deb.IPv4 != "" {
		t.Fatalf("got %+v, %v", deb, err)
	}
	if _, err := parse("id=alpine\nversion=3.20\narch=x86_64\ncpus=1\nmemory_kb=1\n"); err == nil {
		t.Fatal("accepted an unsupported family")
	}
	if _, err := parse("id=rocky\ncpus=lots\n"); err == nil {
		t.Fatal("accepted a non-numeric CPU count")
	}
}

// A circuit can put one host's fact into a command for another host, so a
// fact has to be the plain word it claims to be.
func TestParseRefusesFactsThatAreNotPlainWords(t *testing.T) {
	good := map[string]string{"id": "rocky", "version": "10.0", "arch": "x86_64", "ipv4": "203.0.113.10"}
	for name, c := range map[string]struct{ key, value string }{
		"shell in the OS id":      {"id", "rocky; touch /tmp/x"},
		"upper case OS id":        {"id", "Rocky"},
		"substitution in version": {"version", "10.0$(id)"},
		"quote in version":        {"version", `10"`},
		"space in arch":           {"arch", "x86_64 -o"},
		"empty arch":              {"arch", ""},
		"host name for ipv4":      {"ipv4", "example.com"},
		"ipv4 with a command":     {"ipv4", "203.0.113.10;id"},
		"ipv6 for ipv4":           {"ipv4", "2001:db8::1"},
		"escape sequence":         {"version", "10\x1b[2J"},
	} {
		out := "like=rhel\ncpus=1\nmemory_kb=1024\n"
		for k, v := range good {
			if k == c.key {
				v = c.value
			}
			out += k + "=" + v + "\n"
		}
		if f, err := parse(out); err == nil {
			t.Errorf("%s: accepted %+v", name, f)
		}
	}
	// Debian testing has no VERSION_ID.
	if _, err := parse("id=debian\nversion=\narch=aarch64\ncpus=1\nmemory_kb=1024\nipv4=\n"); err != nil {
		t.Errorf("empty version: %v", err)
	}
}
