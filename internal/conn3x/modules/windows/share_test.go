// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package windows

import (
	"slices"
	"testing"
)

func TestShareChanges(t *testing.T) {
	s := Share{Name: "Finance", Path: `D:\Shares\Finance`, Full: []string{"Administrators"}, Read: []string{"Everyone", "Administrators"}}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	a := ActualShare{Exists: true, Path: `D:\Shares\Finance\`, SIDs: map[string]string{"Administrators": "S-1-5-32-544", "Everyone": "S-1-1-0"},
		Access: []ShareAccess{
			{Account: "Everyone", SID: "S-1-1-0", Right: "Full", Type: "Allow"},
			{Account: `CONTOSO\Old`, SID: "S-1-5-21-9", Right: "Change", Type: "Allow"},
			{Account: `CONTOSO\Banned`, SID: "S-1-5-21-8", Right: "Full", Type: "Deny"},
		}}
	g, r, err := s.changes(a)
	if err != nil {
		t.Fatal(err)
	}
	// Administrators gets Full (the stronger of its two), Everyone drops to
	// Read, the old account goes, and the Deny entry is left alone.
	if !slices.Equal(g, []grant{{"Everyone", "Read"}, {"Administrators", "Full"}}) || !slices.Equal(r, []string{`CONTOSO\Old`}) {
		t.Errorf("grants %v, revokes %v", g, r)
	}
	if ok, _ := s.Matches(a); ok {
		t.Error("matched before the changes")
	}
	a.Access = []ShareAccess{{Account: "BUILTIN\\Administrators", SID: "S-1-5-32-544", Right: "Full", Type: "Allow"}, {Account: "Everyone", SID: "S-1-1-0", Right: "Read", Type: "Allow"}}
	if ok, err := s.Matches(a); !ok || err != nil {
		t.Errorf("BUILTIN\\Administrators isn't Administrators: %v", err)
	}
	// Lists unset: access is left alone.
	if g, r, _ := (Share{Name: "X", Path: `C:\x`}).changes(a); g != nil || r != nil {
		t.Error("unset lists changed access")
	}
	a.SIDs["Nobody"] = ""
	if _, _, err := (Share{Name: "X", Path: `C:\x`, Read: []string{"Nobody"}}).changes(a); err == nil {
		t.Error("an unknown account compared")
	}
	for _, bad := range []Share{
		{Name: "C$", Path: `C:\`}, {Name: "ADMIN$", Path: `C:\x`}, {Name: "a/b", Path: `C:\x`}, {Name: "x", Path: `share`}, {Name: "", Path: `C:\x`},
		{Name: "x", Path: `C:\x`, Read: []string{" "}},
	} {
		if bad.Validate() == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	if (Share{Name: "Backup$", Path: `E:\Backup`}).Validate() != nil {
		t.Error("refused a hidden share")
	}
}
