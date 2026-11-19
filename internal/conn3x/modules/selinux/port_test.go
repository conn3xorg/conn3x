// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package selinux

import "testing"

func TestLocalPortType(t *testing.T) {
	out := "SELinux Port Type              Proto    Port Number\n\nhttp_port_t                    tcp      8080, 8443-8450\npostgresql_port_t              tcp      5433\nhttp_port_t                    udp      8080\n"
	for _, tc := range []struct {
		p    Port
		want string
	}{
		{Port{Port: "8080", Protocol: "tcp"}, "http_port_t"},
		{Port{Port: "8443-8450", Protocol: "tcp"}, "http_port_t"},
		{Port{Port: "5433", Protocol: "tcp"}, "postgresql_port_t"},
		{Port{Port: "8080", Protocol: "udp"}, "http_port_t"},
		{Port{Port: "8443", Protocol: "tcp"}, ""}, // inside a range isn't the range
		{Port{Port: "80", Protocol: "tcp"}, ""},   // "8080" mustn't match "80"
		{Port{Port: "5433", Protocol: "udp"}, ""},
	} {
		if got := localPortType(out, tc.p); got != tc.want {
			t.Errorf("%+v: %q, want %q", tc.p, got, tc.want)
		}
	}
}

func TestPortValidate(t *testing.T) {
	ok := Port{Port: "8080", Protocol: "tcp", Type: "http_port_t"}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []Port{
		{Port: "0", Protocol: "tcp", Type: "http_port_t"},
		{Port: "65536", Protocol: "tcp", Type: "http_port_t"},
		{Port: "9000-8000", Protocol: "tcp", Type: "http_port_t"},
		{Port: "80;id", Protocol: "tcp", Type: "http_port_t"},
		{Port: "80", Protocol: "icmp", Type: "http_port_t"},
		{Port: "80", Protocol: "tcp", Type: "http port"},
	} {
		if bad.Validate() == nil {
			t.Errorf("%+v validated", bad)
		}
	}
	if (Port{Port: "8443-8450", Protocol: "sctp", Type: "http_port_t"}).Validate() != nil {
		t.Error("a range was refused")
	}
}
