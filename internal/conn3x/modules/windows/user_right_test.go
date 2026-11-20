// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package windows

import (
	"context"
	"slices"
	"strings"
	"testing"
)

func TestUserRightValidate(t *testing.T) {
	for _, u := range []UserRight{
		{Name: "SeServiceLogonRight", Principals: []string{`.\svc_app`}},
		{Name: "SeDebugPrivilege", Principals: []string{"S-1-5-32-544"}},
		{Name: "SeDebugPrivilege", Authoritative: true},
	} {
		if err := u.Validate(); err != nil {
			t.Errorf("%+v: %v", u, err)
		}
	}
	for _, u := range []UserRight{
		{Name: "ServiceLogonRight", Principals: []string{"a"}},
		{Name: "SeServiceLogonRight; x", Principals: []string{"a"}},
		{Name: "SeServiceLogonRight"},
		{Name: "SeServiceLogonRight", Principals: []string{"a", "A"}},
		{Name: "SeServiceLogonRight", Principals: []string{" "}},
		{Name: "SeServiceLogonRight", Principals: []string{"a\nb"}},
	} {
		if err := u.Validate(); err == nil {
			t.Errorf("%+v passed", u)
		}
	}
}

func TestUserRightChanges(t *testing.T) {
	a := ActualUserRight{Holders: []string{"S-1-5-32-544", "s-1-5-21-1-1001"},
		Wanted: map[string]string{"Administrators": "S-1-5-32-544", `.\svc_app`: "S-1-5-21-1-1001", "new": ""}}
	u := UserRight{Name: "SeServiceLogonRight", Principals: []string{"Administrators", `.\svc_app`}}
	if !u.Matches(a) {
		t.Error("same holders by SID, in another case, didn't match")
	}
	u.Principals = []string{`.\svc_app`}
	if !u.Matches(a) {
		t.Error("additive: another holder counted")
	}
	u.Authoritative = true
	if add, remove, _ := u.changes(a); len(add) != 0 || !slices.Equal(remove, []string{"S-1-5-32-544"}) {
		t.Errorf("authoritative: add %v remove %v", add, remove)
	}
	// Authoritative with no principals clears the right.
	if _, remove, _ := (UserRight{Name: "SeDebugPrivilege", Authoritative: true}).changes(a); len(remove) != 2 {
		t.Errorf("clearing: remove %v", remove)
	}
	u = UserRight{Name: "SeServiceLogonRight", Principals: []string{"new"}}
	if u.Matches(a) {
		t.Error("an unresolved principal matched")
	}
	if err := ApplyUserRight(context.Background(), &fake{}, u, a); err == nil || !strings.Contains(err.Error(), "no account named new") {
		t.Errorf("err = %v", err)
	}
	// A SID the host gives back is checked before it's sent again.
	bad := ActualUserRight{Wanted: map[string]string{"x": "S-1-5; rm"}}
	if err := ApplyUserRight(context.Background(), &fake{}, UserRight{Name: "SeServiceLogonRight", Principals: []string{"x"}}, bad); err == nil {
		t.Error("sent a bad SID")
	}
}

func TestUserRightApply(t *testing.T) {
	ctx := context.Background()
	f := &fake{answers: []map[string]any{ok(nil)}}
	a := ActualUserRight{Holders: []string{"S-1-5-32-544"}, Wanted: map[string]string{`.\svc_app`: "S-1-5-21-1-1001"}}
	if err := ApplyUserRight(ctx, f, UserRight{Name: "SeServiceLogonRight", Principals: []string{`.\svc_app`}}, a); err != nil {
		t.Fatal(err)
	}
	got := args(f, 0)
	if got["name"] != "SeServiceLogonRight" || len(got["add"].([]any)) != 1 || got["remove"] != nil || len(got["holders"].([]any)) != 1 {
		t.Errorf("sent %v", got)
	}

	// on_remove "delete" revokes only the step's principals that hold it.
	f = &fake{answers: []map[string]any{
		ok(map[string]any{"holders": []string{"S-1-5-32-544", "S-1-5-21-1-1001"}, "sids": map[string]string{`.\svc_app`: "S-1-5-21-1-1001", "gone": ""}}),
		ok(nil),
	}}
	if err := ApplyUserRightRemove(ctx, f, "SeServiceLogonRight", []string{`.\svc_app`, "gone"}); err != nil {
		t.Fatal(err)
	}
	if got := args(f, 1); !slices.Equal(got["remove"].([]any), []any{"S-1-5-21-1-1001"}) {
		t.Errorf("sent %v", got)
	}
	// Nothing to revoke runs nothing more.
	f = &fake{answers: []map[string]any{ok(map[string]any{"holders": []string{}, "sids": map[string]string{"a": "S-1-5-21-1-1001"}})}}
	if err := ApplyUserRightRemove(ctx, f, "SeServiceLogonRight", []string{"a"}); err != nil || len(f.sent) != 1 {
		t.Errorf("err %v, runs %d", err, len(f.sent))
	}
}
