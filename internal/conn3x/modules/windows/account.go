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

// Windows refuses these in local account names. Keeping them out also keeps
// a name out of the wildcards that Get-LocalUser and Get-LocalGroup expand.
var (
	userName  = regexp.MustCompile(`^[^"/\\\[\]:;|=,+*?<>@\x00-\x1f\x7f]{1,20}$`)
	groupName = regexp.MustCompile(`^[^"/\\\[\]:;|=,+*?<>\x00-\x1f\x7f]{1,256}$`)
	sidText   = regexp.MustCompile(`^S-1-[0-9]+(-[0-9]+)+$`)
)

// maxDescription is the longest description the LocalAccounts cmdlets take.
const maxDescription = 48

func checkAccountName(kind, name string, re *regexp.Regexp) error {
	// Windows drops a trailing dot or space, so "alice " would be alice.
	if !re.MatchString(name) || strings.Trim(name, ". ") == "" || strings.TrimSpace(name) != name || strings.HasSuffix(name, ".") {
		return fmt.Errorf(`%s name %q isn't valid: Windows allows up to %d characters, no space at either end or dot at the end, and none of " / \ [ ] : ; | = , + * ? < >`, kind, name, map[string]int{"user": 20, "group": 256}[kind])
	}
	return nil
}

func checkText(attr string, v *string, max int) error {
	if v == nil {
		return nil
	}
	if strings.ContainsFunc(*v, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return fmt.Errorf("%s must not contain control characters", attr)
	}
	if max > 0 && len([]rune(*v)) > max {
		return fmt.Errorf("%s is longer than Windows allows: %d characters", attr, max)
	}
	return nil
}

// User is the wanted state of a local user. A nil field is left alone.
type User struct {
	Name        string
	FullName    *string
	Description *string
	Disabled    *bool
}

// Validate checks a user before anything reaches a host.
func (u User) Validate() error {
	if err := checkAccountName("user", u.Name, userName); err != nil {
		return err
	}
	if err := checkText("full_name", u.FullName, 256); err != nil {
		return err
	}
	return checkText("description", u.Description, maxDescription)
}

// ActualUser is a local user as the host has it.
type ActualUser struct {
	Exists      bool
	SID         string
	FullName    string
	Description string
	Enabled     bool
	PasswordSet bool // false for an account made with no password
}

// ReadUser reads a local user. Nothing about its password comes back.
func ReadUser(ctx context.Context, r ps.Runner, name string) (ActualUser, error) {
	res, err := ps.Read(ctx, r, script("read_user.ps1"), map[string]any{"name": name})
	if err != nil {
		return ActualUser{}, err
	}
	var a struct {
		Exists      bool   `json:"exists"`
		SID         string `json:"sid"`
		FullName    string `json:"full_name"`
		Description string `json:"description"`
		Enabled     bool   `json:"enabled"`
		PasswordSet bool   `json:"password_set"`
	}
	if err := json.Unmarshal(res.Value, &a); err != nil {
		return ActualUser{}, fmt.Errorf("reading user %s: the host's answer wasn't valid", name)
	}
	return ActualUser(a), nil
}

// Matches reports whether the host has the user as configured. A password
// can't be read back, so it never counts.
func (u User) Matches(a ActualUser) bool {
	return a.Exists && (u.FullName == nil || *u.FullName == a.FullName) &&
		(u.Description == nil || *u.Description == a.Description) &&
		(u.Disabled == nil || *u.Disabled == !a.Enabled)
}

// ApplyUser creates or changes a user. password nil leaves the password as it
// is. It travels on stdin only, and errors have it blanked.
//
// It refuses to leave an enabled account with no password: Windows lets a
// blank password log on at the console.
func ApplyUser(ctx context.Context, r ps.Runner, u User, a ActualUser, password *string) error {
	enabled := a.Exists && a.Enabled
	if !a.Exists || u.Disabled != nil {
		enabled = u.Disabled == nil || !*u.Disabled
	}
	if enabled && password == nil && !a.PasswordSet {
		return fmt.Errorf("user %s would be enabled with no password: set password_wo, or disabled = true", u.Name)
	}
	args := map[string]any{"name": u.Name, "create": !a.Exists, "full_name": u.FullName, "description": u.Description, "disabled": u.Disabled}
	var secrets []string
	if password != nil {
		if *password == "" || strings.ContainsRune(*password, 0) {
			return errors.New("password_wo must not be empty or contain NUL")
		}
		args["password"] = *password
		secrets = []string{*password}
	}
	if _, err := ps.Apply(ctx, r, script("apply_user.ps1"), args, 2*time.Minute); err != nil {
		if strings.Contains(err.Error(), "InvalidPasswordException") {
			return fmt.Errorf("user %s: Windows refused the password: it doesn't meet the password policy, such as length, complexity or history", u.Name)
		}
		return errors.New(Scrub(err.Error(), secrets))
	}
	return nil
}

// ApplyUserRemove deletes a user, if it's there. Its profile folder stays.
func ApplyUserRemove(ctx context.Context, r ps.Runner, name string) error {
	_, err := ps.Apply(ctx, r, script("apply_user_remove.ps1"), map[string]any{"name": name}, 2*time.Minute)
	return err
}

// Group is the wanted state of a local group. Members are names, such as
// LAB\alice, or SIDs; nil leaves membership alone. Without Authoritative,
// members are only added.
type Group struct {
	Name          string
	Description   *string
	Members       []string
	Authoritative bool
}

// Validate checks a group before anything reaches a host.
func (g Group) Validate() error {
	if err := checkAccountName("group", g.Name, groupName); err != nil {
		return err
	}
	if err := checkText("description", g.Description, maxDescription); err != nil {
		return err
	}
	if g.Authoritative && g.Members == nil {
		return errors.New("authoritative needs members: the complete list")
	}
	seen := map[string]bool{}
	for _, m := range g.Members {
		// Windows names ignore case, and so does the host's answer.
		if seen[strings.ToLower(m)] {
			return fmt.Errorf("member %q is listed twice; names ignore case", m)
		}
		seen[strings.ToLower(m)] = true
		if strings.TrimSpace(m) == "" || strings.ContainsFunc(m, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
			return fmt.Errorf("member %q isn't a name or a SID", m)
		}
	}
	return nil
}

// ActualGroup is a local group as the host has it, with members by SID.
type ActualGroup struct {
	Exists      bool
	Description string
	Members     []string          // SIDs
	Wanted      map[string]string // each configured member's SID; "" when it doesn't resolve
}

// ReadGroup reads a local group and resolves the configured members to SIDs.
// A member that doesn't resolve yet, such as a user an earlier step makes,
// isn't an error here: the group just isn't in sync.
func ReadGroup(ctx context.Context, r ps.Runner, g Group) (ActualGroup, error) {
	res, err := ps.Read(ctx, r, script("read_group.ps1"), map[string]any{"name": g.Name, "principals": g.Members})
	if err != nil {
		return ActualGroup{}, err
	}
	var a struct {
		Exists      bool              `json:"exists"`
		Description string            `json:"description"`
		Members     []string          `json:"members"`
		SIDs        map[string]string `json:"sids"`
	}
	if err := json.Unmarshal(res.Value, &a); err != nil {
		return ActualGroup{}, fmt.Errorf("reading group %s: the host's answer wasn't valid", g.Name)
	}
	return ActualGroup{Exists: a.Exists, Description: a.Description, Members: a.Members, Wanted: a.SIDs}, nil
}

// changes is what ApplyGroup has to add and remove, by SID.
func (g Group) changes(a ActualGroup) (add, remove []string, unresolved []string) {
	want := map[string]bool{}
	for _, m := range g.Members {
		sid := a.Wanted[m]
		if sid == "" {
			unresolved = append(unresolved, m)
			continue
		}
		want[strings.ToUpper(sid)] = true
		if !slices.ContainsFunc(a.Members, func(s string) bool { return strings.EqualFold(s, sid) }) && !slices.Contains(add, sid) {
			add = append(add, sid)
		}
	}
	if g.Authoritative {
		for _, s := range a.Members {
			if !want[strings.ToUpper(s)] {
				remove = append(remove, s)
			}
		}
	}
	return add, remove, unresolved
}

// Matches reports whether the host has the group as configured.
func (g Group) Matches(a ActualGroup) bool {
	if !a.Exists || (g.Description != nil && *g.Description != a.Description) {
		return false
	}
	add, remove, unresolved := g.changes(a)
	return len(add)+len(remove)+len(unresolved) == 0
}

// ApplyGroup creates or changes a group. It refuses to take the login running
// it out of the group, which could lock Conn3x out of the host.
func ApplyGroup(ctx context.Context, r ps.Runner, g Group, a ActualGroup) error {
	add, remove, unresolved := g.changes(a)
	if len(unresolved) > 0 {
		return fmt.Errorf("group %s: no account named %s", g.Name, strings.Join(unresolved, ", "))
	}
	for _, s := range append(slices.Clone(add), remove...) {
		if !sidText.MatchString(s) {
			return fmt.Errorf("group %s: the host gave %q as a SID", g.Name, s)
		}
	}
	_, err := ps.Apply(ctx, r, script("apply_group.ps1"), map[string]any{
		"name": g.Name, "create": !a.Exists, "description": g.Description, "add": add, "remove": remove,
	}, 2*time.Minute)
	return err
}

// ApplyGroupRemove deletes a group, if it's there.
func ApplyGroupRemove(ctx context.Context, r ps.Runner, name string) error {
	_, err := ps.Apply(ctx, r, script("apply_group_remove.ps1"), map[string]any{"name": name}, 2*time.Minute)
	return err
}
