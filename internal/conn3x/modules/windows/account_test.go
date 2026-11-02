// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package windows

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/opentofu/opentofu/internal/conn3x/modules/windows/ps"
)

func TestAccountNames(t *testing.T) {
	for _, ok := range []string{"appsvc", "Guest", "a.b-c_d", "$(x)'", "名前", "twenty-characters-xy"} {
		if err := (User{Name: ok}).Validate(); err != nil {
			t.Errorf("user %q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "...", "  ", "a*", "a?", "[a]", `a\b`, "a/b", "a;b", "a@b", "a,b", "a\nb", "a\x00b", "twenty-one-characters", "alice ", " alice", "alice."} {
		if (User{Name: bad}).Validate() == nil {
			t.Errorf("accepted user %q", bad)
		}
	}
	if (Group{Name: "Remote Desktop Users"}).Validate() != nil || (Group{Name: "a*"}).Validate() == nil {
		t.Error("group names")
	}
	long := strings.Repeat("x", 49)
	if (User{Name: "a", Description: &long}).Validate() == nil || (Group{Name: "a", Description: &long}).Validate() == nil {
		t.Error("accepted a 49-character description")
	}
	if (Group{Name: "a", Members: []string{"alice", "ALICE"}}).Validate() == nil {
		t.Error("accepted members that differ only in case")
	}
	if (Group{Name: "a", Members: []string{"a\nb"}}).Validate() == nil || (Group{Name: "a", Authoritative: true}).Validate() == nil {
		t.Error("accepted bad members")
	}
}

// The password travels as an argument on stdin and nowhere else, and an error
// that echoes it comes back blanked.
func TestApplyUserPassword(t *testing.T) {
	const secret = "s3ntinel-Pw!"
	f := &fake{answers: []map[string]any{{"ok": false, "error": "refused " + secret}}}
	pw := secret
	err := ApplyUser(context.Background(), f, User{Name: "appsvc"}, ActualUser{}, &pw)
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("err = %v", err)
	}
	args := f.sent[0]["args"].(map[string]any)
	if args["password"] != secret || strings.Contains(f.sent[0]["script"].(string), secret) {
		t.Errorf("sent %v", f.sent[0])
	}
	if !strings.Contains(ps.Command, "-EncodedCommand") || strings.Contains(ps.Command, secret) {
		t.Error("the command line changed")
	}
}

// No account is made or left enabled with no password.
func TestApplyUserRefusesBlankPasswords(t *testing.T) {
	yes, no := true, false
	for name, tc := range map[string]struct {
		u    User
		a    ActualUser
		fail bool
	}{
		"new, enabled":                {User{Name: "a"}, ActualUser{}, true},
		"new, disabled":               {User{Name: "a", Disabled: &yes}, ActualUser{}, false},
		"enabling one with none":      {User{Name: "a", Disabled: &no}, ActualUser{Exists: true}, true},
		"enabled, none, left alone":   {User{Name: "a"}, ActualUser{Exists: true, Enabled: true}, true},
		"enabled with one":            {User{Name: "a", Disabled: &no}, ActualUser{Exists: true, PasswordSet: true}, false},
		"disabled stays without one":  {User{Name: "a"}, ActualUser{Exists: true}, false},
		"disabling one with none set": {User{Name: "a", Disabled: &yes}, ActualUser{Exists: true, Enabled: true}, false},
	} {
		f := &fake{answers: []map[string]any{{"ok": true}}}
		err := ApplyUser(context.Background(), f, tc.u, tc.a, nil)
		if (err != nil) != tc.fail {
			t.Errorf("%s: err = %v", name, err)
		}
		if tc.fail && len(f.sent) != 0 {
			t.Errorf("%s: reached the host", name)
		}
	}
}

func TestGroupChanges(t *testing.T) {
	a := ActualGroup{Exists: true, Members: []string{"S-1-5-21-1-500", "s-1-5-21-1-1001"},
		Wanted: map[string]string{"azadmin": "S-1-5-21-1-500", "bob": "S-1-5-21-1-1001", "new": ""}}
	g := Group{Name: "g", Members: []string{"azadmin", "bob"}}
	if !g.Matches(a) {
		t.Error("same members by SID, in another case, didn't match")
	}
	g.Members = []string{"azadmin"}
	if !g.Matches(a) {
		t.Error("additive: an extra member counted")
	}
	g.Authoritative = true
	if add, remove, _ := g.changes(a); len(add) != 0 || !slices.Equal(remove, []string{"s-1-5-21-1-1001"}) {
		t.Errorf("authoritative: add %v remove %v", add, remove)
	}
	g = Group{Name: "g", Members: []string{"new"}}
	if g.Matches(a) {
		t.Error("an unresolved member matched")
	}
	if err := ApplyGroup(context.Background(), &fake{}, g, a); err == nil || !strings.Contains(err.Error(), "no account named new") {
		t.Errorf("err = %v", err)
	}
	// A SID the host gives back is checked before it's sent again.
	bad := ActualGroup{Exists: true, Wanted: map[string]string{"x": "S-1-5; rm"}}
	if err := ApplyGroup(context.Background(), &fake{}, Group{Name: "g", Members: []string{"x"}}, bad); err == nil {
		t.Error("sent a bad SID")
	}
}
