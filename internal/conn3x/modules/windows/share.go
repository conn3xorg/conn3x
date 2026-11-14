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

// Share is an SMB share and, when any of its lists is set, its whole set of
// Allow entries: Full, Change and Read together. Deny entries are left alone.
type Share struct {
	Name, Path  string
	Description *string // nil leaves it alone
	Full        []string
	Change      []string
	Read        []string
}

var (
	shareName  = regexp.MustCompile(`^[^\\/\[\]:|<>+=;,?*"\x00-\x1f]{1,80}$`)
	adminShare = regexp.MustCompile(`(?i)^([A-Z]|ADMIN|IPC|PRINT)\$$`)
	sharePath  = regexp.MustCompile(`^[A-Za-z]:\\`)
)

// Validate checks a share before anything reaches the host.
func (s Share) Validate() error {
	if !shareName.MatchString(s.Name) || strings.TrimSpace(s.Name) != s.Name {
		return fmt.Errorf("name %q must be a share name: up to 80 characters, none of \\ / [ ] : | < > + = ; , ? * \"", s.Name)
	}
	if adminShare.MatchString(s.Name) {
		return fmt.Errorf("name %q is one of Windows' own administrative shares, which windows_share won't own", s.Name)
	}
	if !sharePath.MatchString(s.Path) || strings.ContainsFunc(s.Path, func(r rune) bool { return r < 0x20 }) {
		return fmt.Errorf("path %q must be a local folder, such as D:\\Shares\\Finance", s.Path)
	}
	if s.Description != nil && strings.ContainsFunc(*s.Description, func(r rune) bool { return r < 0x20 }) {
		return errors.New("description must be one line")
	}
	for _, a := range s.accounts() {
		if strings.TrimSpace(a) == "" || strings.ContainsFunc(a, func(r rune) bool { return r < 0x20 }) {
			return fmt.Errorf("account %q must be an account name, such as BUILTIN\\Administrators or CONTOSO\\Finance", a)
		}
	}
	return nil
}

// ownsAccess reports whether the step owns the share's Allow entries.
func (s Share) ownsAccess() bool { return s.Full != nil || s.Change != nil || s.Read != nil }

func (s Share) accounts() []string { return slices.Concat(s.Full, s.Change, s.Read) }

// rights is what the step wants each account to have.
func (s Share) rights() map[string]string {
	want := map[string]string{}
	for right, list := range map[string][]string{"Read": s.Read, "Change": s.Change, "Full": s.Full} {
		for _, a := range list {
			if strongerRight(right, want[a]) {
				want[a] = right
			}
		}
	}
	return want
}

func strongerRight(a, b string) bool {
	rank := map[string]int{"": 0, "Read": 1, "Change": 2, "Full": 3}
	return rank[a] > rank[b]
}

// ShareAccess is one entry of a share's access list.
type ShareAccess struct {
	Account string `json:"account"`
	SID     string `json:"sid"`
	Right   string `json:"right"`
	Type    string `json:"type"`
}

// ActualShare is a share as the host has it.
type ActualShare struct {
	Exists      bool
	Path        string
	Description string
	Access      []ShareAccess
	SIDs        map[string]string // each account the step names, by its SID; "" if it doesn't resolve
}

// ReadShare reads a share and its access list, and resolves the accounts
// the step names, so they compare by SID.
func ReadShare(ctx context.Context, r ps.Runner, s Share) (ActualShare, error) {
	res, err := ps.Read(ctx, r, script("read_share.ps1"), map[string]any{"name": s.Name, "accounts": s.accounts()})
	if err != nil {
		return ActualShare{}, err
	}
	var raw struct {
		Exists      bool              `json:"exists"`
		Path        string            `json:"path"`
		Description string            `json:"description"`
		Access      json.RawMessage   `json:"access"`
		SIDs        map[string]string `json:"sids"`
	}
	if err := json.Unmarshal(res.Value, &raw); err != nil {
		return ActualShare{}, errors.New("reading a share: the host's answer wasn't valid")
	}
	a := ActualShare{Exists: raw.Exists, Path: raw.Path, Description: raw.Description, SIDs: raw.SIDs}
	if len(raw.Access) > 0 && string(raw.Access) != "null" {
		// PowerShell can send a list of one as the one object.
		if err := json.Unmarshal(raw.Access, &a.Access); err != nil {
			var one ShareAccess
			if err := json.Unmarshal(raw.Access, &one); err != nil {
				return ActualShare{}, errors.New("reading a share: the host's answer wasn't valid")
			}
			a.Access = []ShareAccess{one}
		}
	}
	return a, nil
}

// grant is an account to give a right.
type grant struct {
	Account string `json:"account"`
	Right   string `json:"right"`
}

// changes are the grants and revokes that make the Allow entries the
// step's. An account that doesn't resolve is an error: it can't be compared.
func (s Share) changes(a ActualShare) (grants []grant, revokes []string, err error) {
	if !s.ownsAccess() {
		return nil, nil, nil
	}
	want := map[string]string{} // SID -> right
	names := map[string]string{}
	for acct, right := range s.rights() {
		sid := a.SIDs[acct]
		if sid == "" {
			return nil, nil, fmt.Errorf("account %q isn't one this host knows", acct)
		}
		if strongerRight(right, want[sid]) {
			want[sid], names[sid] = right, acct
		}
	}
	have := map[string]string{}
	for _, e := range a.Access {
		if e.Type == "Allow" {
			have[e.SID] = e.Right
			if _, ok := want[e.SID]; !ok {
				revokes = append(revokes, e.Account)
			}
		}
	}
	for _, sid := range sortedSIDs(want) {
		if have[sid] != want[sid] {
			grants = append(grants, grant{names[sid], want[sid]})
		}
	}
	return grants, revokes, nil
}

func sortedSIDs(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// Matches reports whether the host has the share as configured.
func (s Share) Matches(a ActualShare) (bool, error) {
	if !a.Exists || !strings.EqualFold(strings.TrimRight(a.Path, `\`), strings.TrimRight(s.Path, `\`)) {
		return false, nil
	}
	if s.Description != nil && a.Description != *s.Description {
		return false, nil
	}
	g, r, err := s.changes(a)
	return err == nil && g == nil && r == nil, err
}

// ApplyShare makes the share, sets its description, and grants and
// revokes until its Allow entries are the step's. Access changes in place.
func ApplyShare(ctx context.Context, r ps.Runner, s Share) error {
	if err := s.Validate(); err != nil {
		return err
	}
	a, err := ReadShare(ctx, r, s)
	if err != nil {
		return err
	}
	if a.Exists && !strings.EqualFold(strings.TrimRight(a.Path, `\`), strings.TrimRight(s.Path, `\`)) {
		return fmt.Errorf("share %s is %s, not %s; a share's folder can't change in place, so remove it or pick another name", s.Name, a.Path, s.Path)
	}
	if !a.Exists && s.ownsAccess() {
		// New-SmbShare grants Everyone Read; the step's lists replace that.
		a.Access = []ShareAccess{{Account: "Everyone", SID: "S-1-1-0", Right: "Read", Type: "Allow"}}
	}
	grants, revokes, err := s.changes(a)
	if err != nil {
		return err
	}
	args := map[string]any{"name": s.Name, "path": s.Path, "grant": grants, "revoke": revokes}
	if s.Description != nil {
		args["description"] = *s.Description
	}
	_, err = ps.Apply(ctx, r, script("apply_share.ps1"), args, 2*time.Minute)
	return err
}

// ApplyShareRemove removes the share and leaves its folder.
func ApplyShareRemove(ctx context.Context, r ps.Runner, name string) error {
	_, err := ps.Apply(ctx, r, script("apply_share.ps1"), map[string]any{"name": name, "drop": true}, time.Minute)
	return err
}
