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
