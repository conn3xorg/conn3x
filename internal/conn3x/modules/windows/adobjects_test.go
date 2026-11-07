// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package windows

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

func TestADObjectsCheck(t *testing.T) {
	s := func(v string) *string { return &v }
	for _, ok := range []interface{ Check() (string, error) }{
		OU{Name: "Servers"},
		OU{Name: "App servers", Path: "OU=Lab,DC=lab,DC=test", Description: s("x")},
		ADGroup{Name: "App Admins", Scope: "domainlocal", Category: "distribution", Members: []string{"alice", "web1$", "Ops"}},
		ADGroup{Name: "g", Members: []string{}, Authoritative: true},
		ADUser{Name: "alice", UPN: s("alice@lab.test"), DisplayName: s("Alice Smith")},
		ADUser{Name: "bob", UPN: s("")},
	} {
		if attr, err := ok.Check(); err != nil {
			t.Errorf("%+v: %s: %v", ok, attr, err)
		}
	}
	for name, c := range map[string]struct {
		v    interface{ Check() (string, error) }
		attr string
	}{
		"ou comma":         {OU{Name: "a,b"}, "name"},
		"ou wildcard":      {OU{Name: "a*"}, "name"},
		"ou paren":         {OU{Name: "a(b)"}, "name"},
		"ou hash":          {OU{Name: "#a"}, "name"},
		"ou space":         {OU{Name: " a"}, "name"},
		"ou long":          {OU{Name: strings.Repeat("a", 65)}, "name"},
		"ou path":          {OU{Name: "a", Path: "Lab"}, "path"},
		"ou path newline":  {OU{Name: "a", Path: "OU=a\n,DC=x"}, "path"},
		"group scope":      {ADGroup{Name: "g", Scope: "Global"}, "scope"},
		"group category":   {ADGroup{Name: "g", Category: "mail"}, "category"},
		"group domain":     {ADGroup{Name: "g", Members: []string{`LAB\alice`}}, "members"},
		"group dn":         {ADGroup{Name: "g", Members: []string{"CN=alice,CN=Users,DC=lab,DC=test"}}, "members"},
		"group twice":      {ADGroup{Name: "g", Members: []string{"alice", "ALICE"}}, "members"},
		"group auth":       {ADGroup{Name: "g", Authoritative: true}, "authoritative"},
		"group wildcard":   {ADGroup{Name: "g*"}, "name"},
		"user long":        {ADUser{Name: strings.Repeat("a", 21)}, "name"},
		"user at":          {ADUser{Name: "a@b"}, "name"},
		"user upn":         {ADUser{Name: "a", UPN: s("alice")}, "upn"},
		"user upn two @":   {ADUser{Name: "a", UPN: s("a@b@c")}, "upn"},
		"user upn space":   {ADUser{Name: "a", UPN: s("a b@c")}, "upn"},
		"user control":     {ADUser{Name: "a", DisplayName: s("a\x00")}, "display_name"},
		"user description": {ADUser{Name: "a", Description: s(strings.Repeat("d", 1025))}, "description"},
	} {
		if attr, err := c.v.Check(); err == nil || attr != c.attr {
			t.Errorf("%s: %s, %v", name, attr, err)
		}
	}
}

func TestADGroupChanges(t *testing.T) {
	a := ActualADGroup{AD: true, Exists: true, Parent: "OU=Lab,DC=lab,DC=test", PathDN: "OU=Lab,DC=lab,DC=test", Scope: "Global", Category: "Security",
		Members: []string{"CN=alice,CN=Users,DC=lab,DC=test", "CN=old,CN=Users,DC=lab,DC=test"},
		Wanted:  map[string]string{"alice": "cn=Alice,cn=users,dc=lab,dc=test", "bob": "CN=bob,CN=Users,DC=lab,DC=test", "ghost": ""}}
	g := ADGroup{Name: "g", Path: "ou=lab,dc=lab,dc=test", Scope: "global", Members: []string{"alice"}}
	if !g.Matches(a) {
		t.Error("additive, alice in: no match")
	}
	g.Authoritative = true
	if add, remove, _ := g.changes(a); g.Matches(a) || len(add) != 0 || len(remove) != 1 || remove[0] != "CN=old,CN=Users,DC=lab,DC=test" {
		t.Errorf("authoritative: add %v, remove %v", add, remove)
	}
	g = ADGroup{Name: "g", Members: []string{"alice", "bob", "ghost"}}
	add, _, unresolved := g.changes(a)
	if len(add) != 1 || add[0] != "CN=bob,CN=Users,DC=lab,DC=test" || len(unresolved) != 1 || g.Matches(a) {
		t.Errorf("add %v, unresolved %v", add, unresolved)
	}
	if err := ApplyADGroup(context.Background(), &fake{}, g, a); err == nil || !strings.Contains(err.Error(), "ghost") {
		t.Errorf("unresolved: %v", err)
	}
	for name, g := range map[string]ADGroup{
		"scope":    {Name: "g", Scope: "universal"},
		"category": {Name: "g", Category: "distribution"},
	} {
		if g.Matches(a) {
			t.Errorf("%s: matched", name)
		}
	}
	// The group sits elsewhere: apply moves it.
	f := &fake{answers: []map[string]any{{"ok": true}}}
	moved := a
	moved.Parent = "CN=Users,DC=lab,DC=test"
	if err := ApplyADGroup(context.Background(), f, ADGroup{Name: "g", Path: "OU=Lab,DC=lab,DC=test"}, moved); err != nil || f.sent[0]["args"].(map[string]any)["move"] != true {
		t.Errorf("move: %v, %v", err, f.sent)
	}
	if err := ApplyADGroup(context.Background(), &fake{}, ADGroup{Name: "g"}, ActualADGroup{}); err != errNoAD {
		t.Errorf("no AD: %v", err)
	}
}

func TestADUserApply(t *testing.T) {
	const pw = "s3ntinel-ADUser!"
	ctx := context.Background()
	no := false
	// A new user with no password stays disabled, and refuses to be enabled.
	f := &fake{answers: []map[string]any{{"ok": true}}}
	if err := ApplyADUser(ctx, f, ADUser{Name: "svc"}, ActualADUser{AD: true}, nil); err != nil || f.sent[0]["args"].(map[string]any)["enabled"] != false {
		t.Errorf("no password: %v, %v", err, f.sent)
	}
	yes := true
	if err := ApplyADUser(ctx, &fake{}, ADUser{Name: "svc", Enabled: &yes}, ActualADUser{AD: true}, nil); err == nil {
		t.Error("enabled with no password")
	}
	// With one it's enabled, and the password is only on stdin.
	f = &fake{answers: []map[string]any{{"ok": false, "error": "refused " + pw}}}
	p := pw
	if err := ApplyADUser(ctx, f, ADUser{Name: "alice"}, ActualADUser{AD: true}, &p); err == nil || strings.Contains(err.Error(), pw) {
		t.Errorf("error: %v", err)
	}
	args := f.sent[0]["args"].(map[string]any)
	if args["password"] != pw || args["enabled"] != true || strings.Contains(f.sent[0]["script"].(string), pw) {
		t.Errorf("sent %v", args)
	}
	f = &fake{answers: []map[string]any{{"ok": false, "error": "The password does not meet the length, complexity, or history requirement of the domain."}}}
	if err := ApplyADUser(ctx, f, ADUser{Name: "alice", Enabled: &no}, ActualADUser{AD: true}, &p); err == nil || !strings.Contains(err.Error(), "password policy") {
		t.Errorf("policy: %v", err)
	}
	empty := ""
	if err := ApplyADUser(ctx, &fake{}, ADUser{Name: "alice"}, ActualADUser{AD: true}, &empty); err == nil {
		t.Error("empty password accepted")
	}
	a := ActualADUser{AD: true, Exists: true, Parent: "CN=Users,DC=lab,DC=test", UPN: "alice@lab.test", Enabled: true, PasswordSet: true}
	upn := "alice@lab.test"
	if !(ADUser{Name: "alice", UPN: &upn}).Matches(a) || (ADUser{Name: "alice", Enabled: &no}).Matches(a) || (ADUser{Name: "alice", Path: "OU=Lab,DC=lab,DC=test"}).Matches(a) {
		t.Error("matches")
	}
}

// hang never answers, like a write to AD before its global catalog is up.
type hang struct{ runs int }

func (h *hang) RunRaw(ctx context.Context, _ string, _ []byte) (ssh.Result, error) {
	h.runs++
	<-ctx.Done()
	return ssh.Result{}, ctx.Err()
}

func TestWaitAD(t *testing.T) {
	poll, check := adPoll, adCheckLimit
	adPoll, adCheckLimit = time.Millisecond, 50*time.Millisecond
	t.Cleanup(func() { adPoll, adCheckLimit = poll, check })
	ctx := context.Background()

	// Ready, or not a DC: one check and done.
	f := &fake{answers: []map[string]any{{"ok": true, "value": ""}}}
	if err := WaitAD(ctx, f, time.Minute); err != nil || len(f.sent) != 1 || !strings.Contains(f.sent[0]["script"].(string), "3268") {
		t.Errorf("ready: %v, %d runs", err, len(f.sent))
	}
	// A reason, then an error from the script, then ready.
	f = &fake{answers: []map[string]any{
		{"ok": true, "value": "Unable to contact the server."},
		{"ok": false, "error": "Unable to find a default server with Active Directory Web Services running."},
		{"ok": true, "value": ""},
	}}
	if err := WaitAD(ctx, f, time.Minute); err != nil || len(f.sent) != 3 {
		t.Errorf("came up: %v, %d runs", err, len(f.sent))
	}
	// Never ready: the error says how long and why, after more than one check.
	f = &fake{}
	for range 1000 {
		f.answers = append(f.answers, map[string]any{"ok": true, "value": "Unable to contact the server."})
	}
	if err := WaitAD(ctx, f, 20*time.Millisecond); err == nil || !strings.Contains(err.Error(), "within 20ms") || !strings.Contains(err.Error(), "Unable to contact") || len(f.sent) < 2 {
		t.Errorf("never: %v, %d runs", err, len(f.sent))
	}
	// A check that hangs is cut off and counts as not ready.
	h := &hang{}
	if err := WaitAD(ctx, h, 120*time.Millisecond); err == nil || !strings.Contains(err.Error(), "no answer within 50ms") || h.runs < 2 {
		t.Errorf("hang: %v, %d runs", err, h.runs)
	}
	// A cancelled apply stops the wait.
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if err := WaitAD(cctx, &hang{}, time.Minute); err != context.Canceled {
		t.Errorf("cancelled: %v", err)
	}
}
