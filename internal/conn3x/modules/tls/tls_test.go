// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package tls

import (
	"strings"
	"testing"
	"time"
)

func TestKeyValidate(t *testing.T) {
	for _, k := range []Key{{Path: "/k"}, {Path: "/k", Type: "ecdsa", Curve: "P-384"}, {Path: "/k", Type: "ed25519", Mode: "0640"}, {Path: "/k", Bits: 4096}} {
		if err := k.Validate(); err != nil {
			t.Errorf("%+v: %v", k, err)
		}
	}
	for want, k := range map[string]Key{
		"absolute":    {Path: "k"},
		"2048, 3072":  {Path: "/k", Bits: 1024},
		"P-256":       {Path: "/k", Type: "ecdsa", Curve: "P-521"},
		"neither":     {Path: "/k", Type: "ed25519", Bits: 2048},
		"anyone read": {Path: "/k", Mode: "0644"},
		"\"rsa\"":     {Path: "/k", Type: "dsa"},
	} {
		if err := k.Validate(); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%+v: %v, want %q", k, err, want)
		}
	}
}

func TestKeyMatches(t *testing.T) {
	k := Key{Path: "/k", Group: "nginx"}
	have := KeyState{Exists: true, Type: "rsa", Bits: 3072, Mode: "0600", Owner: "root", Group: "nginx"}
	if !k.Matches(have) {
		t.Fatal("the default key should match")
	}
	for name, change := range map[string]func(*KeyState){
		"size":  func(s *KeyState) { s.Bits = 2048 },
		"mode":  func(s *KeyState) { s.Mode = "0640" },
		"group": func(s *KeyState) { s.Group = "root" },
		"type":  func(s *KeyState) { s.Type = "" },
	} {
		s := have
		change(&s)
		if k.Matches(s) {
			t.Errorf("%s: matched %+v", name, s)
		}
	}
}

func TestCertValidateAndConfig(t *testing.T) {
	c := Cert{Path: "/c", KeyPath: "/k", CommonName: "web1", DNSNames: []string{"web1.example", "*.web.example"}, IPs: []string{"10.0.0.1", "::1"}}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	cfg := c.config()
	for _, want := range []string{"CN = web1\n", "CA:FALSE", "subjectAltName = DNS:web1.example,DNS:*.web.example,IP:10.0.0.1,IP:::1\n"} {
		if !strings.Contains(cfg, want) {
			t.Errorf("config lacks %q:\n%s", want, cfg)
		}
	}
	for want, bad := range map[string]Cert{
		"common_name":       {Path: "/c", KeyPath: "/k", CommonName: "a\nb"},
		"isn't a host name": {Path: "/c", KeyPath: "/k", CommonName: "x", DNSNames: []string{"a b"}},
		"IP address":        {Path: "/c", KeyPath: "/k", CommonName: "x", IPs: []string{"10.0.0"}},
		"less than days":    {Path: "/c", KeyPath: "/k", CommonName: "x", Days: 5, RenewDays: 10},
		"different files":   {Path: "/c", KeyPath: "/c", CommonName: "x"},
	} {
		if err := bad.Validate(); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%+v: %v, want %q", bad, err, want)
		}
	}
}

func TestCertMatchesRenewal(t *testing.T) {
	now := time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC)
	c := Cert{Path: "/c", KeyPath: "/k", CommonName: "web1", DNSNames: []string{"b", "a"}}
	s := CertState{Exists: true, PEM: "x", KeyMatches: true, CommonName: "web1", DNSNames: []string{"a", "b"}, NotAfter: now.Add(40 * 24 * time.Hour), Mode: "0644"}
	if !c.Matches(s, now) {
		t.Fatal("names in another order should match")
	}
	s.NotAfter = now.Add(29 * 24 * time.Hour)
	if c.Matches(s, now) {
		t.Error("29 days left with 30 days' notice should renew")
	}
	s.NotAfter, s.KeyMatches = now.Add(40*24*time.Hour), false
	if c.Matches(s, now) {
		t.Error("a certificate for another key matched")
	}
}
