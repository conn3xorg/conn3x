// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package system

import (
	"strings"
	"testing"
)

func TestSysctl(t *testing.T) {
	s := Sysctl{Key: "net.ipv4.ip_local_port_range", Value: "1024   65000"}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	if got := s.Path(); got != "/etc/sysctl.d/90-conn3x-net.ipv4.ip_local_port_range.conf" {
		t.Fatalf("path = %s", got)
	}
	if got := s.Content(); got != "# Managed by Conn3x.\nnet.ipv4.ip_local_port_range = 1024 65000\n" {
		t.Fatalf("content = %q", got)
	}
	// sysctl -n separates multi-value settings with tabs.
	if !s.Matches("1024\t65000\n") || s.Matches("32768\t60999\n") {
		t.Fatal("Matches compares the wrong thing")
	}
	if got := (Sysctl{Key: "net.ipv4.conf.eth0/100.rp_filter", Value: "1"}).Path(); strings.Count(got, "/") != 3 {
		t.Fatalf("a / in the key leaked into the file name: %s", got)
	}
	for _, bad := range []Sysctl{
		{Key: "", Value: "1"},
		{Key: "ip_forward", Value: "1"},
		{Key: "net.ipv4.ip_forward; reboot", Value: "1"},
		{Key: "net/../../etc", Value: "1"},
		{Key: "net.ipv4.ip_forward", Value: ""},
		{Key: "net.ipv4.ip_forward", Value: "1\nkernel.panic = 1"},
	} {
		if bad.Validate() == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}

func TestValidateHostname(t *testing.T) {
	for _, ok := range []string{"web1", "web-1.example.com", "a", strings.Repeat("a", 63)} {
		if err := ValidateHostname(ok); err != nil {
			t.Errorf("rejected %q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "-web", "web-", "web_1", "web 1", "web..example", strings.Repeat("a", 64), strings.Repeat("a.", 33)} {
		if ValidateHostname(bad) == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestTimezone(t *testing.T) {
	for _, ok := range []string{"UTC", "Europe/Dublin", "America/Argentina/Buenos_Aires", "Etc/GMT+5"} {
		if err := ValidateTimezone(ok); err != nil {
			t.Errorf("rejected %q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "../etc/passwd", "Europe/../../etc", "/UTC", "Europe/", "Europe Dublin"} {
		if ValidateTimezone(bad) == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	for link, want := range map[string]string{
		"/usr/share/zoneinfo/Europe/Dublin\n": "Europe/Dublin",
		"../usr/share/zoneinfo/Etc/UTC\n":     "Etc/UTC",
		"":                                    "",
	} {
		if got := zoneFromLink(link); got != want {
			t.Errorf("zoneFromLink(%q) = %q, want %q", link, got, want)
		}
	}
}

func TestSysctlKeyIsNotAFlag(t *testing.T) {
	if (Sysctl{Key: "-p/etc/shadow", Value: "1"}).Validate() == nil {
		t.Fatal("accepted a key that sysctl reads as a flag")
	}
}
