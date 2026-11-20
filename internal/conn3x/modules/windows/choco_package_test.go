// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package windows

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestChocoValidate(t *testing.T) {
	yes := true
	for _, p := range []ChocoPackage{
		{Name: "git"},
		{Name: "notepadplusplus.install", Version: "8.6.2"},
		{Name: "app", Version: "1.2.0-beta.1", Source: "https://nuget.example.com/v3/index.json", Pinned: &yes},
		{Name: "app", Source: `C:\feeds\local`},
		{Name: "app", Source: `\\server\share\feed`},
		{Name: "app", Absent: true},
	} {
		if err := p.Validate(); err != nil {
			t.Errorf("%+v: %v", p, err)
		}
	}
	for p, want := range map[*ChocoPackage]string{
		{Name: "a b"}:                                     "package ID",
		{Name: "../x"}:                                    "package ID",
		{Name: "app", Version: ">=1.0"}:                   "exact version",
		{Name: "app", Version: "1.2.3.4.5"}:               "exact version",
		{Name: "app", Source: "https://u:p@feed.example"}: "login",
		{Name: "app", Source: "feeds/local"}:              "absolute folder",
		{Name: "app", Source: "https://feed\n.example"}:   "control character",
		{Name: "app", Absent: true, Version: "1.0"}:       `state "present"`,
		{Name: "app", Absent: true, Pinned: new(bool)}:    `state "present"`,
	} {
		if err := p.Validate(); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%+v: err = %v, want %q", *p, err, want)
		}
	}
}

func TestChocoVersions(t *testing.T) {
	for _, c := range []struct {
		a, b string
		same bool
	}{
		{"1.2", "1.2.0", true},
		{"1.2", "1.2.0.0", true},
		{"1.2.0-Beta", "1.2-beta", true},
		{"1.2.1", "1.2.0", false},
		{"1.2.0-beta", "1.2.0", false},
		{"10.0", "1.0", false},
	} {
		if got := sameVersion(c.a, c.b); got != c.same {
			t.Errorf("sameVersion(%q, %q) = %v", c.a, c.b, got)
		}
	}
}

func TestChocoMatches(t *testing.T) {
	yes, no := true, false
	have := ActualChoco{Installed: true, Version: "1.2.0", Pinned: true}
	for p, want := range map[*ChocoPackage]bool{
		{Name: "a"}:                 true,
		{Name: "a", Version: "1.2"}: true,
		{Name: "a", Version: "1.3"}: false,
		{Name: "a", Pinned: &yes}:   true,
		{Name: "a", Pinned: &no}:    false,
		{Name: "a", Absent: true}:   false,
	} {
		if got := p.Matches(have); got != want {
			t.Errorf("%+v: %v", *p, got)
		}
	}
	if !(ChocoPackage{Name: "a", Absent: true}).Matches(ActualChoco{}) {
		t.Error("absent and not installed didn't match")
	}
}

// What apply asks the script to do, for each starting point.
func TestChocoApplyArgs(t *testing.T) {
	yes, no := true, false
	for _, c := range []struct {
		name string
		p    ChocoPackage
		a    ActualChoco
		want map[string]any
	}{
		{"install", ChocoPackage{Name: "a"}, ActualChoco{},
			map[string]any{"install": true, "remove": false, "unpin_first": false, "pin": ""}},
		{"install and pin", ChocoPackage{Name: "a", Pinned: &yes}, ActualChoco{},
			map[string]any{"install": true, "pin": "add"}},
		{"upgrade a pinned one, keeping the pin", ChocoPackage{Name: "a", Version: "2.0"}, ActualChoco{Installed: true, Version: "1.0", Pinned: true},
			map[string]any{"install": true, "unpin_first": true, "pin": "add", "version": "2.0"}},
		{"upgrade a pinned one, unpinning", ChocoPackage{Name: "a", Version: "2.0", Pinned: &no}, ActualChoco{Installed: true, Version: "1.0", Pinned: true},
			map[string]any{"install": true, "unpin_first": true, "pin": ""}},
		{"pin only", ChocoPackage{Name: "a", Pinned: &yes}, ActualChoco{Installed: true, Version: "1.0"},
			map[string]any{"install": false, "pin": "add"}},
		{"unpin only", ChocoPackage{Name: "a", Pinned: &no}, ActualChoco{Installed: true, Version: "1.0", Pinned: true},
			map[string]any{"install": false, "unpin_first": false, "pin": "remove"}},
		{"remove", ChocoPackage{Name: "a", Absent: true}, ActualChoco{Installed: true, Version: "1.0", Pinned: true},
			map[string]any{"remove": true, "install": false, "pin": ""}},
	} {
		f := &fake{answers: []map[string]any{ok(map[string]any{"restart": c.name == "install"})}}
		restart, err := ApplyChoco(context.Background(), f, c.p, c.a, time.Minute)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		got := args(f, 0)
		for k, v := range c.want {
			if got[k] != v {
				t.Errorf("%s: %s = %v, want %v (sent %v)", c.name, k, got[k], v, got)
			}
		}
		if restart != (c.name == "install") {
			t.Errorf("%s: restart = %v", c.name, restart)
		}
	}
}

func TestChocoReadWithoutChocolatey(t *testing.T) {
	f := &fake{answers: []map[string]any{ok(map[string]any{"chocolatey": false})}}
	if _, err := ReadChoco(context.Background(), f, "git"); err == nil || !strings.Contains(err.Error(), "Chocolatey isn't installed") {
		t.Errorf("err = %v", err)
	}
	f = &fake{answers: []map[string]any{ok(map[string]any{"chocolatey": true, "installed": true, "version": "2.44.0", "pinned": true})}}
	a, err := ReadChoco(context.Background(), f, "git")
	if err != nil || a != (ActualChoco{Installed: true, Version: "2.44.0", Pinned: true}) {
		t.Errorf("got %+v, %v", a, err)
	}
}
