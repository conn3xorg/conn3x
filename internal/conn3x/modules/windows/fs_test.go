// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package windows

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
)

func TestCleanLocalPath(t *testing.T) {
	for in, want := range map[string]string{
		`C:\app\x.txt`:      `C:\app\x.txt`,
		`c:/app/x`:          `c:\app\x`,
		`C:\app\`:           `C:\app`,
		`C:\`:               `C:\`,
		`D:\[odd] $(x) 'q'`: `D:\[odd] $(x) 'q'`,
	} {
		got, err := CleanLocalPath("p", in)
		if err != nil || got != want {
			t.Errorf("%q: got %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{
		``, `app`, `\\server\share\x`, `\\.\C:\x`, `\\?\C:\x`, `C:\a\..\b`, `C:\.\b`, `C:\a:stream`, `C:\a.\b`, `C:\a \b`, `C:\CON`, `C:\x\nul.txt`, `C:\lpt1`,
		`C:\a\\b`, "C:\\a\nb", `C:\*`, `C:\` + strings.Repeat("x", 260),
	} {
		if got, err := CleanLocalPath("p", bad); err == nil {
			t.Errorf("accepted %q as %q", bad, got)
		}
	}
}

func TestValidateEntry(t *testing.T) {
	ok := Entry{Principal: `BUILTIN\Users`, Rights: []string{"Read"}}
	if err := ValidateEntry(ok); err != nil {
		t.Error(err)
	}
	for _, e := range []Entry{
		{Principal: "x\"y", Rights: []string{"Read"}},
		{Principal: "a\nb", Rights: []string{"Read"}},
		{Principal: "Users"},
		{Principal: "Users", Rights: []string{"Everything"}},
		{Principal: "Users", Rights: []string{"Read"}, Type: "maybe"},
		{Principal: "Users", Rights: []string{"Read"}, Inheritance: "all"},
	} {
		if ValidateEntry(e) == nil {
			t.Errorf("accepted %+v", e)
		}
	}
}

func TestMatches(t *testing.T) {
	users := "S-1-5-32-545"
	admins := "S-1-5-32-544"
	readExec := int64(0x1200a9) // as Windows stores it, with SYNCHRONIZE
	state := PathState{
		Kind: "directory",
		SIDs: map[string]string{`BUILTIN\Users`: users, "users": users, "S-1-5-32-544": admins, "svc": "", "o": admins},
		Entries: []ACE{
			{SID: users, Mask: readExec, Allow: true, Flags: 3},
			{SID: admins, Mask: 0x1f01ff, Allow: true, Flags: 3, Inherited: true},
		},
		Owner: admins,
	}
	f, tr := false, true
	entry := func(p string, rights ...string) Entry { return Entry{Principal: p, Rights: rights} }
	for name, tc := range map[string]struct {
		entries []Entry
		exact   bool
		inherit *bool
		owner   string
		want    bool
	}{
		"held":                   {entries: []Entry{entry(`BUILTIN\Users`, "ReadAndExecute")}, want: true},
		"a name in other case":   {entries: []Entry{entry("users", "ReadAndExecute")}, want: true},
		"part of what's held":    {entries: []Entry{entry("users", "Read")}, want: true},
		"more than held":         {entries: []Entry{entry("users", "Modify")}},
		"held only as inherited": {entries: []Entry{entry("S-1-5-32-544", "FullControl")}, want: true},
		"deny isn't allow":       {entries: []Entry{{Principal: "users", Rights: []string{"Read"}, Type: "deny"}}},
		"other inheritance":      {entries: []Entry{{Principal: "users", Rights: []string{"ReadAndExecute"}, Inheritance: "none"}}},
		"authoritative, match":   {entries: []Entry{entry("users", "ReadAndExecute")}, exact: true, want: true},
		"authoritative, subset":  {entries: []Entry{entry("users", "Read")}, exact: true},
		"authoritative, extra":   {entries: []Entry{entry("users", "ReadAndExecute"), entry("o", "Read")}, exact: true},
		"wants inherit off":      {entries: []Entry{entry("users", "ReadAndExecute")}, inherit: &f},
		"wants inherit on":       {entries: []Entry{entry("users", "ReadAndExecute")}, inherit: &tr, want: true},
		"owner matches":          {owner: "o", want: true},
		"owner differs":          {owner: "users"},
	} {
		got, err := state.Matches(tc.entries, tc.exact, tc.inherit, tc.owner)
		if err != nil || got != tc.want {
			t.Errorf("%s: got %v, %v", name, got, err)
		}
	}
	if _, err := state.Matches([]Entry{entry("svc", "Read")}, false, nil, ""); err == nil {
		t.Error("an unknown principal gave no error")
	}
	// Exact needs everything explicit, and inheritance off.
	protected := PathState{Kind: "file", Protected: true, SIDs: map[string]string{"S-1-5-18": "S-1-5-18", "S-1-5-32-544": admins}, Entries: []ACE{
		{SID: "S-1-5-18", Mask: 0x1f01ff, Allow: true}, {SID: admins, Mask: 0x1f01ff, Allow: true},
	}}
	if ok, err := Exact(protected, SecretEntries); err != nil || !ok {
		t.Errorf("secret rules: %v, %v", ok, err)
	}
	protected.Protected = false
	if ok, _ := Exact(protected, SecretEntries); ok {
		t.Error("a file still inheriting counted as exact")
	}
	protected.Protected = true
	protected.Entries = append(protected.Entries, ACE{SID: users, Mask: 0x1200a9, Allow: true})
	if ok, _ := Exact(protected, SecretEntries); ok {
		t.Error("an extra reader counted as exact")
	}
}

func TestNormalMask(t *testing.T) {
	// GENERIC_ALL as a signed 32-bit number, as PowerShell reports it, and GENERIC_READ.
	if got := normalMask(0x10000000); got != rightsMasks["FullControl"] {
		t.Errorf("GENERIC_ALL: %x", got)
	}
	if got := normalMask(-2147483648); got != rightsMasks["Read"] {
		t.Errorf("GENERIC_READ: %x", got)
	}
	if got := normalMask(0x1f01ff); got != rightsMasks["FullControl"] {
		t.Errorf("SYNCHRONIZE wasn't dropped: %x", got)
	}
}

// The content goes as base64 and an error can't carry a secret back.
func TestApplyFileWireAndScrub(t *testing.T) {
	const secret = "hunter2\r\n\x00'$(x)"
	f := &fake{answers: []map[string]any{{"ok": false, "error": "denied: " + secret}}}
	err := ApplyFile(context.Background(), f, `C:\x`, []byte(secret), SecretEntries, []string{secret})
	if err == nil || strings.Contains(err.Error(), "hunter2") {
		t.Fatalf("err = %v", err)
	}
	args := f.sent[0]["args"].(map[string]any)
	got, _ := base64.StdEncoding.DecodeString(args["content"].(string))
	if string(got) != secret {
		t.Errorf("content on the wire: %q", got)
	}
	if !args["exact"].(bool) {
		t.Error("secret entries didn't make the list exact")
	}
	if strings.Contains(f.sent[0]["script"].(string), "hunter2") {
		t.Error("the secret is in the script text")
	}
}

func TestLibraryReachesApplyScripts(t *testing.T) {
	if !strings.Contains(script("apply_file.ps1").Body, "function Lock-Folders") {
		t.Error("apply_file.ps1 lost its library")
	}
	if !strings.HasPrefix(script("apply_file.ps1").Body, "param($A)") {
		t.Error("the library must come after param($A)")
	}
	if strings.Contains(script("read_path.ps1").Body, "Add-Type") {
		t.Error("a read compiles code")
	}
}
