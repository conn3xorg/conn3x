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

// OUs, groups and users in Active Directory. They run on a domain controller:
// a key login on a member server has no domain credentials to reach AD with,
// while on a DC it is the domain account itself.

// errNoAD is what apply says on a host without the ActiveDirectory module.
var errNoAD = errors.New("this host isn't a domain controller with the ActiveDirectory module: run the step on a DC, after the reboot that finishes its promotion")

// An OU name can't hold what a distinguished name or an LDAP filter would
// have to escape, so it never needs escaping. 64 characters is AD's limit.
var ouName = regexp.MustCompile(`^[^#,+"\\<>;=/*()\x00-\x1f\x7f][^,+"\\<>;=/*()\x00-\x1f\x7f]{0,63}$`)

func checkOUName(name string) error {
	if !ouName.MatchString(name) || strings.TrimSpace(name) != name {
		return fmt.Errorf(`name %q isn't a valid OU name: up to 64 characters, no space at either end, no # at the start, and none of , + " \ < > ; = / * ( )`, name)
	}
	return nil
}

// checkDN checks a distinguished name given as a path, such as
// OU=Servers,DC=lab,DC=example,DC=com. AD itself decides whether it exists.
func checkDN(attr, dn string) error {
	if dn == "" {
		return nil
	}
	if len(dn) > 2048 || !strings.Contains(dn, "=") || strings.ContainsFunc(dn, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return fmt.Errorf("%s %q must be a distinguished name, such as OU=Servers,DC=lab,DC=example,DC=com", attr, dn)
	}
	return nil
}

// checkSAM checks a sAMAccountName. maxLen is 20 for users and 256 for groups.
func checkSAM(attr, name string, maxLen int) error {
	re := groupName
	if maxLen == 20 {
		re = userName
	}
	if !re.MatchString(name) || strings.Trim(name, ". ") == "" || strings.TrimSpace(name) != name || strings.HasSuffix(name, ".") {
		return fmt.Errorf(`%s %q isn't a valid account name: up to %d characters, no space at either end or dot at the end, and none of " / \ [ ] : ; | = , + * ? < >`, attr, name, maxLen)
	}
	return nil
}

// OU is an organizational unit. A nil field is left as it is.
type OU struct {
	Name        string
	Path        string // DN of the parent; "" for the top of the domain
	Description *string
	Protected   *bool // protected from accidental deletion
}

// Check validates an OU, naming the attribute at fault.
func (o OU) Check() (attr string, err error) {
	if err := checkOUName(o.Name); err != nil {
		return "name", err
	}
	if err := checkDN("path", o.Path); err != nil {
		return "path", err
	}
	if err := checkText("description", o.Description, 1024); err != nil {
		return "description", err
	}
	return "", nil
}

// ActualOU is an OU as AD has it.
type ActualOU struct {
	AD          bool   // the host has the ActiveDirectory module
	Base        string // DN of the parent the OU was looked for in
	Exists      bool
	DN          string
	Description string
	Protected   bool
}

// decodeAD reads a read script's answer into a.
func decodeAD[T any](res ps.Result, err error, what string) (T, error) {
	var a T
	if err != nil {
		return a, err
	}
	if err := json.Unmarshal(res.Value, &a); err != nil {
		return a, fmt.Errorf("reading %s: the host's answer wasn't valid", what)
	}
	return a, nil
}

// ReadOU reads an OU by its name under its parent. A host without the AD
// module, or a parent that doesn't exist, reads as no OU.
func ReadOU(ctx context.Context, r ps.Runner, o OU) (ActualOU, error) {
	res, err := ps.Read(ctx, r, script("read_ad_ou.ps1"), map[string]any{"name": o.Name, "path": o.Path})
	a, err := decodeAD[struct {
		AD          bool   `json:"ad"`
		Base        string `json:"base"`
		Exists      bool   `json:"exists"`
		DN          string `json:"dn"`
		Description string `json:"description"`
		Protected   bool   `json:"protected"`
	}](res, err, "OU "+o.Name)
	return ActualOU(a), err
}

// Matches reports whether AD has the OU as configured.
func (o OU) Matches(a ActualOU) bool {
	return a.Exists && (o.Description == nil || *o.Description == a.Description) && (o.Protected == nil || *o.Protected == a.Protected)
}

// ApplyOU creates an OU or changes it.
func ApplyOU(ctx context.Context, r ps.Runner, o OU, a ActualOU) error {
	if !a.AD {
		return errNoAD
	}
	if !a.Exists && a.Base == "" {
		return fmt.Errorf("OU %s: the path %s doesn't exist", o.Name, o.Path)
	}
	_, err := ps.Apply(ctx, r, script("apply_ad_ou.ps1"), map[string]any{
		"create": !a.Exists, "dn": a.DN, "name": o.Name, "path": a.Base, "description": o.Description, "protected": o.Protected,
	}, 2*time.Minute)
	return err
}

// ApplyOURemove deletes an OU, if it's there. It refuses one that's protected
// from deletion or isn't empty: it never deletes what's inside.
func ApplyOURemove(ctx context.Context, r ps.Runner, o OU) error {
	a, err := ReadOU(ctx, r, o)
	if err != nil || !a.Exists {
		return err
	}
	_, err = ps.Apply(ctx, r, script("apply_ad_ou_remove.ps1"), map[string]any{"dn": a.DN}, 2*time.Minute)
	return err
}

// Group scopes and categories, as Windows names them, in lower case.
var (
	ADGroupScopes     = []string{"domainlocal", "global", "universal"}
	ADGroupCategories = []string{"security", "distribution"}
)

// ADGroup is a group in AD. Name is both its name and its sAMAccountName.
// Members are sAMAccountNames in the same domain, such as alice, ops or
// web1$; nil leaves membership alone. Without Authoritative, members are only
// added.
type ADGroup struct {
	Name          string
	Path          string // DN of its OU or container; "" leaves it where it is, or Windows' default when new
	Scope         string // "" leaves it, or global when new
	Category      string // "" leaves it, or security when new
	Description   *string
	Members       []string
	Authoritative bool
}

// Check validates a group, naming the attribute at fault.
func (g ADGroup) Check() (attr string, err error) {
	if err := checkSAM("name", g.Name, 256); err != nil {
		return "name", err
	}
	if err := checkDN("path", g.Path); err != nil {
		return "path", err
	}
	if g.Scope != "" && !slices.Contains(ADGroupScopes, g.Scope) {
		return "scope", fmt.Errorf("scope must be one of %s, not %q", strings.Join(ADGroupScopes, ", "), g.Scope)
	}
	if g.Category != "" && !slices.Contains(ADGroupCategories, g.Category) {
		return "category", fmt.Errorf("category must be one of %s, not %q", strings.Join(ADGroupCategories, ", "), g.Category)
	}
	if err := checkText("description", g.Description, 1024); err != nil {
		return "description", err
	}
	if g.Authoritative && g.Members == nil {
		return "authoritative", errors.New("authoritative needs members: the complete list")
	}
	seen := map[string]bool{}
	for _, m := range g.Members {
		if err := checkSAM("member", m, 256); err != nil {
			return "members", fmt.Errorf(`%w; members are account names in this domain, such as alice or web1$, not DOMAIN\name or a distinguished name`, err)
		}
		if seen[strings.ToLower(m)] {
			return "members", fmt.Errorf("member %q is listed twice; names ignore case", m)
		}
		seen[strings.ToLower(m)] = true
	}
	return "", nil
}

// ActualADGroup is a group as AD has it, with members by DN.
type ActualADGroup struct {
	AD          bool
	Exists      bool
	DN          string
	Parent      string
	PathDN      string // the configured path as AD writes it; "" when it doesn't exist
	SID         string
	Scope       string
	Category    string
	Description string
	Members     []string
	Wanted      map[string]string // each configured member's DN; "" when there's no such account
}

// ReadADGroup reads a group by sAMAccountName and finds each configured
// member's DN. A member that doesn't exist yet only puts the group out of sync.
func ReadADGroup(ctx context.Context, r ps.Runner, g ADGroup) (ActualADGroup, error) {
	res, err := ps.Read(ctx, r, script("read_ad_group.ps1"), map[string]any{"name": g.Name, "path": g.Path, "members": g.Members})
	a, err := decodeAD[struct {
		AD          bool              `json:"ad"`
		Exists      bool              `json:"exists"`
		DN          string            `json:"dn"`
		Parent      string            `json:"parent"`
		PathDN      string            `json:"path_dn"`
		SID         string            `json:"sid"`
		Scope       string            `json:"scope"`
		Category    string            `json:"category"`
		Description string            `json:"description"`
		Members     []string          `json:"members"`
		Wanted      map[string]string `json:"wanted"`
	}](res, err, "group "+g.Name)
	return ActualADGroup(a), err
}

func inPath(path, parent, pathDN string) bool {
	return path == "" || (pathDN != "" && strings.EqualFold(parent, pathDN))
}

func hasFold(list []string, s string) bool {
	return slices.ContainsFunc(list, func(v string) bool { return strings.EqualFold(v, s) })
}

// changes is what ApplyADGroup has to add and remove, by DN.
func (g ADGroup) changes(a ActualADGroup) (add, remove, unresolved []string) {
	var want []string
	for _, m := range g.Members {
		dn := a.Wanted[m]
		if dn == "" {
			unresolved = append(unresolved, m)
			continue
		}
		want = append(want, dn)
		if !hasFold(a.Members, dn) && !hasFold(add, dn) {
			add = append(add, dn)
		}
	}
	if g.Authoritative {
		for _, dn := range a.Members {
			if !hasFold(want, dn) {
				remove = append(remove, dn)
			}
		}
	}
	return add, remove, unresolved
}

// Matches reports whether AD has the group as configured.
func (g ADGroup) Matches(a ActualADGroup) bool {
	if !a.Exists || !inPath(g.Path, a.Parent, a.PathDN) ||
		(g.Scope != "" && !strings.EqualFold(g.Scope, a.Scope)) ||
		(g.Category != "" && !strings.EqualFold(g.Category, a.Category)) ||
		(g.Description != nil && *g.Description != a.Description) {
		return false
	}
	add, remove, unresolved := g.changes(a)
	return len(add)+len(remove)+len(unresolved) == 0
}

// ApplyADGroup creates or changes a group, moving it to its path. It refuses to
// take the login out of a group it gets its rights through, such as Domain
// Admins, which could lock Conn3x out.
func ApplyADGroup(ctx context.Context, r ps.Runner, g ADGroup, a ActualADGroup) error {
	if !a.AD {
		return errNoAD
	}
	if g.Path != "" && a.PathDN == "" {
		return fmt.Errorf("group %s: the path %s doesn't exist", g.Name, g.Path)
	}
	add, remove, unresolved := g.changes(a)
	if len(unresolved) > 0 {
		return fmt.Errorf("group %s: no account named %s in the domain", g.Name, strings.Join(unresolved, ", "))
	}
	_, err := ps.Apply(ctx, r, script("apply_ad_group.ps1"), map[string]any{
		"create": !a.Exists, "dn": a.DN, "name": g.Name, "path": g.Path, "move": a.Exists && !inPath(g.Path, a.Parent, a.PathDN),
		"scope": g.Scope, "category": g.Category, "description": g.Description, "add": add, "remove": remove,
	}, 2*time.Minute)
	return err
}

// ApplyADGroupRemove deletes a group, if it's there.
func ApplyADGroupRemove(ctx context.Context, r ps.Runner, name string) error {
	a, err := ReadADGroup(ctx, r, ADGroup{Name: name})
	if err != nil || !a.Exists {
		return err
	}
	_, err = ps.Apply(ctx, r, script("apply_ad_group_remove.ps1"), map[string]any{"dn": a.DN}, 2*time.Minute)
	return err
}

// ADUser is a user in AD. Name is both its name (cn) and its sAMAccountName.
// A nil field is left as it is. Groups are set on the group, not here.
type ADUser struct {
	Name                 string
	Path                 string
	UPN                  *string
	GivenName            *string
	Surname              *string
	DisplayName          *string
	Description          *string
	Enabled              *bool
	PasswordNeverExpires *bool
}

// Check validates a user, naming the attribute at fault.
func (u ADUser) Check() (attr string, err error) {
	if err := checkSAM("name", u.Name, 20); err != nil {
		return "name", err
	}
	if err := checkDN("path", u.Path); err != nil {
		return "path", err
	}
	if u.UPN != nil && *u.UPN != "" {
		local, suffix, ok := strings.Cut(*u.UPN, "@")
		if !ok || local == "" || suffix == "" || strings.Contains(suffix, "@") || strings.ContainsAny(*u.UPN, ` "/\[]:;|=,+*?<>`) || len(*u.UPN) > 1024 {
			return "upn", fmt.Errorf("upn %q must be name@suffix, such as alice@lab.example.com", *u.UPN)
		}
	}
	for _, f := range []struct {
		attr string
		v    *string
		max  int
	}{{"upn", u.UPN, 1024}, {"given_name", u.GivenName, 64}, {"surname", u.Surname, 64}, {"display_name", u.DisplayName, 256}, {"description", u.Description, 1024}} {
		if err := checkText(f.attr, f.v, f.max); err != nil {
			return f.attr, err
		}
	}
	return "", nil
}

// ActualADUser is a user as AD has it. Nothing about the password comes back
// but whether one was ever set.
type ActualADUser struct {
	AD                   bool   `json:"ad"`
	Exists               bool   `json:"exists"`
	DN                   string `json:"dn"`
	Parent               string `json:"parent"`
	PathDN               string `json:"path_dn"`
	SID                  string `json:"sid"`
	UPN                  string `json:"upn"`
	GivenName            string `json:"given_name"`
	Surname              string `json:"surname"`
	DisplayName          string `json:"display_name"`
	Description          string `json:"description"`
	Enabled              bool   `json:"enabled"`
	PasswordNeverExpires bool   `json:"password_never_expires"`
	PasswordSet          bool   `json:"password_set"`
}

// ReadADUser reads a user by sAMAccountName.
func ReadADUser(ctx context.Context, r ps.Runner, u ADUser) (ActualADUser, error) {
	res, err := ps.Read(ctx, r, script("read_ad_user.ps1"), map[string]any{"name": u.Name, "path": u.Path})
	return decodeAD[ActualADUser](res, err, "user "+u.Name)
}

// Matches reports whether AD has the user as configured. A password can't be
// read back, so it never counts.
func (u ADUser) Matches(a ActualADUser) bool {
	same := func(want *string, got string) bool { return want == nil || *want == got }
	return a.Exists && inPath(u.Path, a.Parent, a.PathDN) &&
		same(u.UPN, a.UPN) && same(u.GivenName, a.GivenName) && same(u.Surname, a.Surname) &&
		same(u.DisplayName, a.DisplayName) && same(u.Description, a.Description) &&
		(u.Enabled == nil || *u.Enabled == a.Enabled) &&
		(u.PasswordNeverExpires == nil || *u.PasswordNeverExpires == a.PasswordNeverExpires)
}

// ApplyADUser creates or changes a user. password nil leaves the password as
// it is. It travels on stdin only, and errors have it blanked. A new user is
// enabled when it gets a password, unless enabled says otherwise, and is never
// enabled before it has one.
func ApplyADUser(ctx context.Context, r ps.Runner, u ADUser, a ActualADUser, password *string) error {
	if !a.AD {
		return errNoAD
	}
	if u.Path != "" && a.PathDN == "" {
		return fmt.Errorf("user %s: the path %s doesn't exist", u.Name, u.Path)
	}
	enabled := u.Enabled
	if !a.Exists && enabled == nil {
		b := password != nil
		enabled = &b
	}
	if enabled != nil && *enabled && password == nil && !a.PasswordSet {
		return fmt.Errorf("user %s would be enabled with no password: set password_wo, or enabled = false", u.Name)
	}
	args := map[string]any{
		"create": !a.Exists, "dn": a.DN, "name": u.Name, "path": u.Path, "move": a.Exists && !inPath(u.Path, a.Parent, a.PathDN),
		"upn": u.UPN, "given_name": u.GivenName, "surname": u.Surname, "display_name": u.DisplayName, "description": u.Description,
		"enabled": enabled, "password_never_expires": u.PasswordNeverExpires,
	}
	var secrets []string
	if password != nil {
		if err := checkPassword("password_wo", *password); err != nil {
			return err
		}
		args["password"] = *password
		secrets = []string{*password}
	}
	if _, err := ps.Apply(ctx, r, script("apply_ad_user.ps1"), args, 2*time.Minute); err != nil {
		if strings.Contains(err.Error(), "password does not meet") {
			return fmt.Errorf("user %s: the domain refused the password: it doesn't meet the password policy, such as length, complexity or history", u.Name)
		}
		return errors.New(Scrub(err.Error(), secrets))
	}
	return nil
}

// ApplyADUserRemove deletes a user, if it's there.
func ApplyADUserRemove(ctx context.Context, r ps.Runner, name string) error {
	a, err := ReadADUser(ctx, r, ADUser{Name: name})
	if err != nil || !a.Exists {
		return err
	}
	_, err = ps.Apply(ctx, r, script("apply_ad_user_remove.ps1"), map[string]any{"dn": a.DN}, 2*time.Minute)
	return err
}
