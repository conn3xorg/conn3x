// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package windows

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/opentofu/opentofu/internal/conn3x/modules/windows/ps"
)

// A user right's constant name, such as SeServiceLogonRight or
// SeDebugPrivilege. Whether Windows has it is for ReadUserRight to say.
var userRightName = regexp.MustCompile(`^Se[A-Z][A-Za-z]{0,59}(Privilege|Right)$`)

// UserRight is who must hold a user right. Principals are names, such as
// .\svc_app or LAB\alice, or SIDs. Without Authoritative they are only
// added; with it they are the complete list.
type UserRight struct {
	Name          string
	Principals    []string
	Authoritative bool
}

// Validate checks a user right before anything reaches a host.
func (u UserRight) Validate() error {
	if !userRightName.MatchString(u.Name) {
		return fmt.Errorf("%q isn't a user right's name, such as SeServiceLogonRight", u.Name)
	}
	if !u.Authoritative && len(u.Principals) == 0 {
		return errors.New("principals is empty: give who must hold the right, or set authoritative to clear it")
	}
	seen := map[string]bool{}
	for _, p := range u.Principals {
		if seen[strings.ToLower(p)] {
			return fmt.Errorf("principal %q is listed twice; names ignore case", p)
		}
		seen[strings.ToLower(p)] = true
		if strings.TrimSpace(p) == "" || strings.ContainsFunc(p, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
			return fmt.Errorf("principal %q isn't a name or a SID", p)
		}
	}
	return nil
}

// ActualUserRight is who holds a right on the host, by SID.
type ActualUserRight struct {
	Holders []string          // SIDs
	Wanted  map[string]string // each configured principal's SID; "" when it doesn't resolve
}

// ReadUserRight reads who holds a right and resolves the configured
// principals to SIDs. A principal that doesn't resolve yet, such as a user
// an earlier step makes, isn't an error here: the right just isn't in sync.
func ReadUserRight(ctx context.Context, r ps.Runner, u UserRight) (ActualUserRight, error) {
	res, err := ps.Read(ctx, r, script("read_user_right.ps1"), map[string]any{"name": u.Name, "principals": u.Principals})
	if err != nil {
		return ActualUserRight{}, err
	}
	var a struct {
		Holders []string          `json:"holders"`
		SIDs    map[string]string `json:"sids"`
	}
	if err := json.Unmarshal(res.Value, &a); err != nil {
		return ActualUserRight{}, fmt.Errorf("reading user right %s: the host's answer wasn't valid", u.Name)
	}
	return ActualUserRight{Holders: a.Holders, Wanted: a.SIDs}, nil
}

// changes is what ApplyUserRight has to grant and revoke, by SID.
func (u UserRight) changes(a ActualUserRight) (add, remove, unresolved []string) {
	want := map[string]bool{}
	for _, p := range u.Principals {
		sid := a.Wanted[p]
		if sid == "" {
			unresolved = append(unresolved, p)
			continue
		}
		want[strings.ToUpper(sid)] = true
		if !slices.ContainsFunc(a.Holders, func(s string) bool { return strings.EqualFold(s, sid) }) && !slices.Contains(add, sid) {
			add = append(add, sid)
		}
	}
	if u.Authoritative {
		for _, s := range a.Holders {
			if !want[strings.ToUpper(s)] {
				remove = append(remove, s)
			}
		}
	}
	return add, remove, unresolved
}

// Matches reports whether the right is held as configured.
func (u UserRight) Matches(a ActualUserRight) bool {
	add, remove, unresolved := u.changes(a)
	return len(add)+len(remove)+len(unresolved) == 0
}

// ApplyUserRight grants and revokes the right. The script refuses to leave
// the login running it without a logon right it has, or give it a
// deny-logon right, which could lock Conn3x out of the host.
func ApplyUserRight(ctx context.Context, r ps.Runner, u UserRight, a ActualUserRight) error {
	add, remove, unresolved := u.changes(a)
	if len(unresolved) > 0 {
		return fmt.Errorf("user right %s: no account named %s", u.Name, strings.Join(unresolved, ", "))
	}
	return ApplyUserRightChange(ctx, r, u.Name, a.Holders, add, remove)
}

// ApplyUserRightRemove revokes the right from principals, for a removed
// step whose on_remove is "delete". Principals that no longer resolve, or
// don't hold it, are skipped.
func ApplyUserRightRemove(ctx context.Context, r ps.Runner, name string, principals []string) error {
	a, err := ReadUserRight(ctx, r, UserRight{Name: name, Principals: principals})
	if err != nil {
		return err
	}
	var remove []string
	for _, p := range principals {
		if sid := a.Wanted[p]; sid != "" && slices.ContainsFunc(a.Holders, func(s string) bool { return strings.EqualFold(s, sid) }) {
			remove = append(remove, sid)
		}
	}
	if len(remove) == 0 {
		return nil
	}
	return ApplyUserRightChange(ctx, r, name, a.Holders, nil, remove)
}

// ApplyUserRightChange grants the right to the SIDs in add and revokes it from
// those in remove. holders are who has it now, for the lockout check.
func ApplyUserRightChange(ctx context.Context, r ps.Runner, name string, holders, add, remove []string) error {
	for _, s := range append(slices.Clone(add), remove...) {
		if !sidText.MatchString(s) {
			return fmt.Errorf("user right %s: the host gave %q as a SID", name, s)
		}
	}
	_, err := ps.Apply(ctx, r, script("apply_user_right.ps1"), map[string]any{"name": name, "holders": holders, "add": add, "remove": remove}, 2*time.Minute)
	return err
}
