// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package hostpattern

import (
	"slices"
	"strings"
	"testing"
)

func TestMatch(t *testing.T) {
	hosts := []string{"web1", "web2", "web3", "db1", "db2", "eu-web1"}
	for pattern, want := range map[string][]string{
		"web1":                {"web1"},
		"web1,db1":            {"web1", "db1"},
		"web1:db1":            {"web1", "db1"},
		"web*":                {"web1", "web2", "web3"},
		"*web*":               {"web1", "web2", "web3", "eu-web1"},
		"web[12]":             {"web1", "web2"},
		"web*:!web3":          {"web1", "web2"},
		"!web3":               {"web1", "web2", "db1", "db2", "eu-web1"},
		"all:!db*":            {"web1", "web2", "web3", "eu-web1"},
		"*:&*1":               {"web1", "db1", "eu-web1"},
		"web*,db*:&*2":        {"web2", "db2"},
		"~^db[0-9]$":          {"db1", "db2"},
		"~web:!~^eu-":         {"web1", "web2", "web3"},
		" web1 , db2 ":        {"web1", "db2"},
		"db1,~^web[12]{1,2}$": {"web1", "web2", "db1"},
		"~^(web|db)1$,web3":   {"web1", "web3", "db1"},
		"nothing":             nil,
		"web*:!web*":          nil,
	} {
		p, err := Parse(pattern)
		if err != nil {
			t.Fatalf("%q: %v", pattern, err)
		}
		var got []string
		for _, h := range hosts {
			if p.Match(h) {
				got = append(got, h)
			}
		}
		if !slices.Equal(got, want) {
			t.Errorf("%q matched %v, want %v", pattern, got, want)
		}
		if p.Matched() != (len(want) > 0) {
			t.Errorf("%q: Matched() = %v after matching %v", pattern, p.Matched(), got)
		}
	}
}

func TestParseErrors(t *testing.T) {
	for _, pattern := range []string{"", ",", "web1,!", "web1,&", "~(", "web["} {
		if _, err := Parse(pattern); err == nil {
			t.Errorf("%q parsed, want an error", pattern)
		}
	}
}

func TestMatchInGroups(t *testing.T) {
	groups := map[string][]string{"web1": {"webservers", "eu"}, "web2": {"webservers", "us"}, "db1": {"dbservers", "eu"}}
	for raw, want := range map[string]string{
		"webservers":      "web1,web2",
		"webservers:&eu":  "web1",
		"eu:!dbservers":   "web1",
		"web*:dbservers":  "db1,web1,web2",
		"~^db":            "db1",
		"all:!webservers": "db1",
	} {
		p, err := Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, h := range []string{"db1", "web1", "web2"} {
			if p.MatchIn(h, groups[h]) {
				got = append(got, h)
			}
		}
		if strings.Join(got, ",") != want {
			t.Errorf("%s = %v, want %s", raw, got, want)
		}
	}
}

// Ansible's own examples, with webservers = cobweb, webbing, weber in that
// order: https://docs.ansible.com/ansible/latest/inventory_guide/intro_patterns.html
func TestSubscripts(t *testing.T) {
	order := func(g string) []string {
		switch g {
		case "webservers":
			return []string{"cobweb", "webbing", "weber"}
		case "all":
			return []string{"cobweb", "webbing", "weber", "db1"}
		}
		return nil
	}
	all := []string{"cobweb", "webbing", "weber", "db1", "web0"}
	for pattern, want := range map[string]string{
		"webservers[0]":             "cobweb",
		"webservers[-1]":            "weber",
		"webservers[0:2]":           "cobweb webbing",
		"webservers[1:]":            "webbing weber",
		"webservers[:3]":            "cobweb webbing weber",
		"webservers[9]":             "",
		"all[-1]":                   "db1",
		"webservers[0]:db1":         "cobweb db1",
		"webservers:!webservers[0]": "webbing weber",
		// Not a group, so still a glob: web[0] is web0.
		"web[0]": "web0",
	} {
		p, err := Parse(pattern)
		if err != nil {
			t.Fatalf("%s: %v", pattern, err)
		}
		p.Resolve(order)
		var got []string
		for _, h := range all {
			groups := []string{}
			if h != "db1" && h != "web0" {
				groups = append(groups, "webservers")
			}
			if p.MatchIn(h, groups) {
				got = append(got, h)
			}
		}
		if strings.Join(got, " ") != want {
			t.Errorf("%s matched %q, want %q", pattern, strings.Join(got, " "), want)
		}
	}
}
