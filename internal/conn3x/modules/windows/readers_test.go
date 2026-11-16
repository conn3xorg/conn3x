// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package windows

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/opentofu/opentofu/internal/conn3x/modules/windows/ps"
)

// Every read passes on the host's own error, and turns an answer of the
// wrong shape into an error rather than an empty, in-sync state.
func TestReadersRefuseBadAnswers(t *testing.T) {
	ctx := context.Background()
	ignore := func(err error) error { return err }
	for name, c := range map[string]struct {
		read    func(ps.Runner) error
		garbled string // what the error for a garbled answer says
	}{
		"user":        {func(r ps.Runner) error { _, err := ReadUser(ctx, r, "u"); return err }, "reading user u: the host's answer wasn't valid"},
		"group":       {func(r ps.Runner) error { _, err := ReadGroup(ctx, r, Group{Name: "g"}); return err }, "reading group g: the host's answer wasn't valid"},
		"certificate": {func(r ps.Runner) error { _, err := ReadCertificate(ctx, r, Certificate{}, ""); return err }, "reading a certificate: the host's answer wasn't valid"},
		"dns client":  {func(r ps.Runner) error { _, err := ReadDNSClient(ctx, r, DNSClient{}); return err }, "reading DNS servers: the host's answer wasn't valid"},
		"dns record":  {func(r ps.Runner) error { _, err := ReadDNSRecord(ctx, r, DNSRecord{}); return err }, "reading a DNS record: the host's answer wasn't valid"},
		"env":         {func(r ps.Runner) error { _, err := ReadEnv(ctx, r, "X", false); return err }, "reading an environment variable: the host's answer wasn't valid"},
		"path":        {func(r ps.Runner) error { _, err := ReadPath(ctx, r, `C:\x`, nil, false); return err }, `reading C:\x:`},
		"content":     {func(r ps.Runner) error { _, err := ReadFileContent(ctx, r, `C:\x`); return err }, `reading C:\x:`},
		"app pool":    {func(r ps.Runner) error { _, err := ReadAppPool(ctx, r, "p"); return err }, "reading app pool p: the host's answer wasn't valid"},
		"site":        {func(r ps.Runner) error { _, err := ReadSite(ctx, r, "s"); return err }, "reading site s: the host's answer wasn't valid"},
		"package":     {func(r ps.Runner) error { _, err := PackageInstalled(ctx, r, "{X}"); return err }, "reading package {X}: the host's answer wasn't valid"},
		"share":       {func(r ps.Runner) error { _, err := ReadShare(ctx, r, Share{}); return err }, "reading a share: the host's answer wasn't valid"},
		"task":        {func(r ps.Runner) error { _, err := ReadTask(ctx, r, Task{Path: `\`, Name: "t"}); return err }, `reading task \t: the host's answer wasn't valid`},
		"updates":     {func(r ps.Runner) error { _, err := PendingUpdates(ctx, r, Update{}); return err }, "reading the updates waiting:"},
		"inventory":   {func(r ps.Runner) error { _, err := Inventory(ctx, r, "users"); return err }, "reading the users list:"},
		"ou":          {func(r ps.Runner) error { _, err := ReadOU(ctx, r, OU{Name: "o"}); return err }, "reading OU o: the host's answer wasn't valid"},
		"ad user":     {func(r ps.Runner) error { _, err := ReadADUser(ctx, r, ADUser{Name: "u"}); return err }, "reading user u: the host's answer wasn't valid"},
		"boot id":     {func(r ps.Runner) error { _, err := BootID(ctx, r); return err }, `reading the boot id: got "\"\""`},
		"elevated":    {func(r ps.Runner) error { _, err := Elevated(ctx, r); return err }, `read_elevated.ps1 returned "\"\"", not a boolean`},
		"pending":     {func(r ps.Runner) error { _, err := PendingReboot(ctx, r); return err }, "read_pending_reboot.ps1 returned"},
		"wait":        {func(r ps.Runner) error { _, err := (WaitFor{Port: 1}).Ready(ctx, r); return err }, "read_wait.ps1 returned"},
		"apply cert": {func(r ps.Runner) error {
			_, _, err := ApplyCertificate(ctx, r, Certificate{Path: `C:\c.cer`, Location: "LocalMachine", Store: "My"}, "")
			return err
		}, "importing a certificate: the host's answer wasn't valid"},
		"apply package": {func(r ps.Runner) error {
			_, err := ApplyPackage(ctx, r, Package{ProductCode: "{12345678-1234-1234-1234-123456789012}", Source: `C:\a.msi`, SHA256: strings.Repeat("a", 64)}, time.Minute)
			return err
		}, "reading the result for package"},
		"apply updates": {func(r ps.Runner) error { _, _, err := ApplyUpdates(ctx, r, Update{}, time.Minute); return ignore(err) }, "reading the update result:"},
	} {
		// "" is wrong for every one: no read answers with a bare string but the boot id, which must not be empty.
		if err := c.read(&fake{answers: []map[string]any{ok("")}}); err == nil || !strings.Contains(err.Error(), c.garbled) {
			t.Errorf("%s garbled: %v, want %q", name, err, c.garbled)
		}
		if err := c.read(&fake{answers: []map[string]any{{"ok": false, "error": "Access is denied."}}}); err == nil || !strings.Contains(err.Error(), "Access is denied.") {
			t.Errorf("%s host error: %v", name, err)
		}
	}
}

func TestReadUserAndGroup(t *testing.T) {
	ctx := context.Background()
	u, err := ReadUser(ctx, &fake{answers: []map[string]any{ok(map[string]any{"exists": true, "sid": "S-1-5-21-1-1001", "full_name": "A", "enabled": true, "password_set": true})}}, "a")
	if err != nil || u != (ActualUser{Exists: true, SID: "S-1-5-21-1-1001", FullName: "A", Enabled: true, PasswordSet: true}) {
		t.Errorf("user %+v, %v", u, err)
	}
	f := &fake{answers: []map[string]any{ok(map[string]any{"exists": true, "members": []string{"S-1-5-21-1-500"}, "sids": map[string]string{"alice": "S-1-5-21-1-1001"}})}}
	g, err := ReadGroup(ctx, f, Group{Name: "g", Members: []string{"alice"}})
	if err != nil || !g.Exists || g.Members[0] != "S-1-5-21-1-500" || g.Wanted["alice"] != "S-1-5-21-1-1001" {
		t.Errorf("group %+v, %v", g, err)
	}

	d := "ops"
	if (Group{Name: "g", Description: &d}).Matches(ActualGroup{Exists: true, Description: "other"}) {
		t.Error("another description matched")
	}
	if (Group{Name: "g"}).Matches(ActualGroup{}) {
		t.Error("a missing group matched")
	}
	// A SID the host gave that isn't one is never sent back.
	err = ApplyGroup(ctx, &fake{}, Group{Name: "g", Members: []string{"a"}}, ActualGroup{Wanted: map[string]string{"a": "S-1-5-21-1-1001'; x"}})
	if err == nil || !strings.Contains(err.Error(), "as a SID") {
		t.Errorf("bad SID: %v", err)
	}
	f = &fake{answers: []map[string]any{ok(nil)}}
	if err := ApplyGroup(ctx, f, Group{Name: "g", Members: []string{"a"}}, ActualGroup{Wanted: map[string]string{"a": "S-1-5-21-1-1001"}}); err != nil || args(f, 0)["create"] != true {
		t.Errorf("apply: %v", err)
	}
}

func TestApplyUserMore(t *testing.T) {
	ctx := context.Background()
	empty := ""
	if err := ApplyUser(ctx, &fake{}, User{Name: "u"}, ActualUser{}, &empty); err == nil || err.Error() != "password_wo must not be empty or contain NUL" {
		t.Errorf("empty password: %v", err)
	}
	pw := "short"
	f := &fake{answers: []map[string]any{{"ok": false, "error": "Microsoft.PowerShell.Commands.InvalidPasswordException: short"}}}
	if err := ApplyUser(ctx, f, User{Name: "u"}, ActualUser{}, &pw); err == nil || !strings.Contains(err.Error(), "doesn't meet the password policy") || strings.Contains(err.Error(), "short") {
		t.Errorf("policy: %v", err)
	}
	// An existing user that has a password keeps it.
	f = &fake{answers: []map[string]any{ok(nil)}}
	if err := ApplyUser(ctx, f, User{Name: "u"}, ActualUser{Exists: true, Enabled: true, PasswordSet: true}, nil); err != nil || args(f, 0)["create"] != false {
		t.Errorf("existing: %v", err)
	}
}

func TestCertificateReadAndApply(t *testing.T) {
	ctx := context.Background()
	c := Certificate{Path: `C:\certs\web.pfx`, Location: "LocalMachine", Store: "My", Password: "pfx-s3cret"}
	a, err := ReadCertificate(ctx, &fake{answers: []map[string]any{ok(map[string]any{"in_store": true, "has_key": true, "file_exists": true, "file_sha256": "ab"})}}, c, "T")
	if err != nil || a != (ActualCertificate{InStore: true, HasKey: true, FileExists: true, FileSHA256: "ab"}) {
		t.Errorf("read %+v, %v", a, err)
	}
	f := &fake{answers: []map[string]any{ok(map[string]any{"thumbprint": "T", "sha256": "ab"})}}
	if tp, sum, err := ApplyCertificate(ctx, f, c, ""); err != nil || tp != "T" || sum != "ab" || args(f, 0)["pfx"] != true || args(f, 0)["password"] != "pfx-s3cret" {
		t.Errorf("apply: %q %q %v", tp, sum, err)
	}
	f = &fake{answers: []map[string]any{{"ok": false, "error": "bad password pfx-s3cret"}}}
	if _, _, err := ApplyCertificate(ctx, f, c, ""); err == nil || strings.Contains(err.Error(), "pfx-s3cret") {
		t.Errorf("error with the password: %v", err)
	}
	if _, _, err := ApplyCertificate(ctx, &fake{}, Certificate{Path: "web.pfx"}, ""); err == nil {
		t.Error("an invalid certificate reached the host")
	}
}

func TestDNSRecordReadAndApply(t *testing.T) {
	ctx := context.Background()
	d := DNSRecord{Zone: "lab.test", Name: "web", Type: "A", Values: []string{"10.0.0.2"}}
	// PowerShell sends a list of one as the one value.
	a, err := ReadDNSRecord(ctx, &fake{answers: []map[string]any{ok(map[string]any{"zone": true, "values": "10.0.0.1", "ttl": 3600})}}, d)
	if err != nil || !a.Zone || len(a.Values) != 1 || a.Values[0] != "10.0.0.1" || a.TTL != 3600 {
		t.Errorf("one value: %+v, %v", a, err)
	}
	a, err = ReadDNSRecord(ctx, &fake{answers: []map[string]any{ok(map[string]any{"zone": true, "values": nil})}}, d)
	if err != nil || a.Values != nil {
		t.Errorf("no values: %+v, %v", a, err)
	}
	if _, err := ReadDNSRecord(ctx, &fake{answers: []map[string]any{ok(map[string]any{"values": 5})}}, d); err == nil {
		t.Error("a number as values")
	}

	f := &fake{answers: []map[string]any{ok(map[string]any{"zone": true, "values": []string{"10.0.0.1"}, "ttl": 3600}), ok(nil)}}
	if err := ApplyDNSRecord(ctx, f, d); err != nil {
		t.Fatal(err)
	}
	if s := args(f, 1); !equalJSON(s["add_values"], []any{"10.0.0.2"}) || !equalJSON(s["remove_values"], []any{"10.0.0.1"}) || s["set_ttl"] != false {
		t.Errorf("sent %v", s)
	}
	if err := ApplyDNSRecord(ctx, &fake{answers: []map[string]any{ok(map[string]any{"zone": false})}}, d); err == nil || !strings.Contains(err.Error(), "no DNS zone lab.test") {
		t.Errorf("no zone: %v", err)
	}
	if err := ApplyDNSRecord(ctx, &fake{err: errors.New("down")}, d); err == nil {
		t.Error("read error ignored")
	}
	if err := ApplyDNSRecord(ctx, &fake{}, DNSRecord{Zone: "lab.test", Name: "web", Type: "MX"}); err == nil {
		t.Error("an invalid record reached the host")
	}

	f = &fake{answers: []map[string]any{ok(map[string]any{"zone": true, "values": []string{"10.0.0.1"}}), ok(nil)}}
	if err := ApplyDNSRecordRemove(ctx, f, d); err != nil || len(f.sent) != 2 || !equalJSON(args(f, 1)["remove_values"], []any{"10.0.0.1"}) {
		t.Errorf("remove: %v, sent %v", err, f.sent)
	}
	f = &fake{answers: []map[string]any{ok(map[string]any{"zone": true, "values": []string{}})}}
	if err := ApplyDNSRecordRemove(ctx, f, d); err != nil || len(f.sent) != 1 {
		t.Errorf("nothing to remove: %v, %d runs", err, len(f.sent))
	}
	// Names compare without case or the trailing dot; text as it is.
	cname := DNSRecord{Type: "PTR"}
	if cname.norm("Web1.Lab.Test.") != "web1.lab.test" || (DNSRecord{Type: "A"}).norm("not-ip") != "not-ip" || (DNSRecord{Type: "TXT"}).norm("A") != "A" {
		t.Error("norm")
	}
}

func TestEnvAndPath(t *testing.T) {
	ctx := context.Background()
	f := &fake{answers: []map[string]any{ok(map[string]any{"exists": true, "kind": "ExpandString", "value": "%X%"})}}
	if a, err := ReadEnv(ctx, f, "X", true); err != nil || a != (ActualEnv{Exists: true, Kind: "ExpandString", Value: "%X%"}) || args(f, 0)["key"] != userEnvKey {
		t.Errorf("read %+v, %v", a, err)
	}
	if err := ApplyEnv(ctx, &fake{}, EnvVar{Name: "A=B"}); err == nil {
		t.Error("an invalid name reached the host")
	}
	if (EnvVar{Name: "X", Value: "a\x00"}).Validate() == nil {
		t.Error("a NUL in a value")
	}
	if !(EnvVar{Name: "X", Absent: true}).Matches(ActualEnv{}) || (EnvVar{Name: "X", Absent: true}).Matches(ActualEnv{Exists: true}) {
		t.Error("absent")
	}

	p := PathEntry{Element: `C:\Tools`}
	// Already there, in another case and with a trailing backslash: nothing is written.
	f = &fake{answers: []map[string]any{ok(map[string]any{"exists": true, "value": `C:\Windows;c:\tools\`})}}
	if err := ApplyPath(ctx, f, p); err != nil || len(f.sent) != 1 {
		t.Errorf("present: %v, %d runs", err, len(f.sent))
	}
	f = &fake{answers: []map[string]any{ok(map[string]any{"exists": true, "value": `C:\Windows;`}), ok(nil)}}
	if err := ApplyPath(ctx, f, p); err != nil || args(f, 1)["value"] != `C:\Windows;C:\Tools` || args(f, 1)["key"] != machineEnvKey {
		t.Errorf("add: %v, sent %v", err, f.sent)
	}
	if got := (PathEntry{Element: `C:\x`, Absent: true}).NewPath(`C:\x;C:\y;c:\X\`); got != `C:\y` {
		t.Errorf("remove gave %q", got)
	}
	if got := p.NewPath(";"); got != `C:\Tools` {
		t.Errorf("into an empty Path: %q", got)
	}
	if err := ApplyPath(ctx, &fake{err: errors.New("down")}, p); err == nil {
		t.Error("read error ignored")
	}
	if err := ApplyPath(ctx, &fake{}, PathEntry{Element: "a;b"}); err == nil {
		t.Error("two folders in one element")
	}
}

func TestReadPathAndFiles(t *testing.T) {
	ctx := context.Background()
	f := &fake{answers: []map[string]any{ok(map[string]any{"kind": "file", "sha256": "ABCD"})}}
	s, err := ReadPath(ctx, f, `C:\x`, nil, true)
	if err != nil || s.SHA256 != "abcd" || s.Kind != "file" {
		t.Errorf("read %+v, %v", s, err)
	}
	// No principals goes as an empty list, never null.
	if p, ok := args(f, 0)["principals"].([]any); !ok || len(p) != 0 {
		t.Errorf("principals sent as %v", args(f, 0)["principals"])
	}
	if got := Principals([]Entry{{Principal: "a"}}, "o"); len(got) != 2 || got[1] != "o" {
		t.Errorf("principals %q", got)
	}
	if got := Principals(nil, ""); len(got) != 0 {
		t.Errorf("no principals %q", got)
	}

	for name, c := range map[string]struct {
		answer map[string]any
		want   string
	}{
		"text":   {map[string]any{"ok": true, "content": "aGk="}, ""},
		"link":   {map[string]any{"ok": false, "why": "it's a link"}, `C:\x can't be imported as content: it's a link`},
		"base64": {map[string]any{"ok": true, "content": "!"}, `reading C:\x:`},
		"binary": {map[string]any{"ok": true, "content": "/w=="}, "it isn't UTF-8 text"},
	} {
		got, err := ReadFileContent(ctx, &fake{answers: []map[string]any{ok(c.answer)}}, `C:\x`)
		if c.want == "" && (err != nil || got != "hi") || c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)) {
			t.Errorf("%s: %q, %v", name, got, err)
		}
	}

	if err := ApplyFile(ctx, &fake{}, `C:\x`, make([]byte, MaxContent+1), nil, nil); err == nil || err.Error() != "content is larger than 2 MiB" {
		t.Errorf("big file: %v", err)
	}
	f = &fake{answers: []map[string]any{ok(nil), ok(nil), ok(nil)}}
	if err := ApplyFileRemove(ctx, f, `C:\x`); err != nil || args(f, 0)["path"] != `C:\x` {
		t.Errorf("remove: %v", err)
	}
	if err := ApplyDirectory(ctx, f, `C:\d`, []Entry{{Principal: "a", Rights: []string{"Read"}}}); err != nil || args(f, 1)["exact"] != true {
		t.Errorf("directory: %v", err)
	}
	on := true
	if err := ApplyACL(ctx, f, ACL{Path: `C:\d`, Inherit: &on, Owner: "o"}, true); err != nil || args(f, 2)["inherit"] != true || args(f, 2)["owner"] != "o" {
		t.Errorf("acl: %v", err)
	}
}

func TestMatchesMore(t *testing.T) {
	sid := "S-1-5-32-545"
	s := PathState{Kind: "file", SIDs: map[string]string{"u": sid}, Entries: []ACE{
		{SID: sid, Mask: 0x1200a9, Allow: true},
		{SID: sid, Mask: 0x1f01ff, Allow: true, Inherited: true},
	}}
	e := []Entry{{Principal: "u", Rights: []string{"ReadAndExecute"}}}
	on, off := true, false
	// Exact and inheriting: an inherited rule is fine.
	if ok, err := s.Matches(e, true, &on, ""); !ok || err != nil {
		t.Errorf("inherit on: %v, %v", ok, err)
	}
	s.Protected = true
	if ok, _ := s.Matches(e, true, &off, ""); ok {
		t.Error("an inherited rule with inheritance off")
	}
	// A rule that applies only to children can't be described by an entry.
	s.Entries = []ACE{{SID: sid, Mask: 0x1200a9, Allow: true}, {SID: sid, Mask: 0x1200a9, Allow: true, Only: 1}}
	if ok, _ := s.Matches(e, true, nil, ""); ok {
		t.Error("an inherit-only rule in an exact list")
	}
	if ok, _ := s.Matches(e, false, nil, ""); !ok {
		t.Error("an inherit-only rule kept a plain list from matching")
	}
	if _, err := s.Matches(nil, false, nil, "nobody"); err == nil || !strings.Contains(err.Error(), "nobody") {
		t.Errorf("unknown owner: %v", err)
	}
	// GENERIC_WRITE and GENERIC_EXECUTE.
	if got := normalMask(0x40000000); got != rightsMasks["Write"]|rightsMasks["ReadPermissions"] {
		t.Errorf("GENERIC_WRITE: %x", got)
	}
	if got := normalMask(0x20000000); got != 0x0200a0 {
		t.Errorf("GENERIC_EXECUTE: %x", got)
	}
}

func TestIISReadAndRemove(t *testing.T) {
	ctx := context.Background()
	p, err := ReadAppPool(ctx, &fake{answers: []map[string]any{ok(map[string]any{"installed": true, "exists": true})}}, "p")
	if err != nil || !p.Installed || !p.Exists {
		t.Errorf("pool %+v, %v", p, err)
	}
	s, err := ReadSite(ctx, &fake{answers: []map[string]any{ok(map[string]any{"installed": true, "exists": true, "bindings": []map[string]string{{"protocol": "http", "information": "*:80:"}}})}}, "s")
	if err != nil || len(s.Bindings) != 1 || s.Bindings[0].Information != "*:80:" {
		t.Errorf("site %+v, %v", s, err)
	}
	f := &fake{answers: []map[string]any{ok(nil), ok(nil)}}
	if ApplyAppPoolRemove(ctx, f, "p") != nil || ApplySiteRemove(ctx, f, "s") != nil || args(f, 0)["name"] != "p" || args(f, 1)["name"] != "s" {
		t.Errorf("remove sent %v", f.sent)
	}
	if ApplyAppPoolRemove(ctx, f, "a/b") == nil || ApplySiteRemove(ctx, f, "") == nil || len(f.sent) != 2 {
		t.Error("an invalid name reached the host")
	}
	if ApplyAppPool(ctx, f, AppPool{Name: ""}) == nil || ApplySite(ctx, f, Site{Name: ""}) == nil {
		t.Error("an invalid pool or site reached the host")
	}
}

func TestInventoryAndUpdates(t *testing.T) {
	ctx := context.Background()
	for _, kind := range []string{"features", "services", "users", "groups"} {
		f := &fake{answers: []map[string]any{ok(map[string]any{"names": []string{"a"}})}}
		if names, err := Inventory(ctx, f, kind); err != nil || len(names) != 1 || args(f, 0)["kind"] != kind {
			t.Errorf("%s: %q, %v", kind, names, err)
		}
	}
	if _, err := Inventory(ctx, &fake{}, "drivers"); err == nil || err.Error() != `can't list Windows "drivers"` {
		t.Errorf("unknown kind: %v", err)
	}

	f := &fake{answers: []map[string]any{ok(map[string]any{"pending": nil})}}
	if got, err := PendingUpdates(ctx, f, Update{Categories: []string{"SecurityUpdates"}, Accept: []string{"KB5034441"}}); err != nil || got == nil || len(got) != 0 {
		t.Errorf("none pending: %v, %v", got, err)
	}
	if cats := args(f, 0)["categories"].([]any); len(cats) != 1 || cats[0] != UpdateCategories["SecurityUpdates"] || args(f, 0)["reject"] == nil {
		t.Errorf("sent %v", args(f, 0))
	}
	if _, err := PendingUpdates(ctx, &fake{}, Update{Accept: []string{"5034441"}}); err == nil {
		t.Error("a bad KB reached the host")
	}
	f = &fake{answers: []map[string]any{ok(map[string]any{"installed": []string{"KB1"}, "failed": []string{"KB2 x"}, "restart": true})}}
	if got, restart, err := ApplyUpdates(ctx, f, Update{}, time.Hour); err == nil || err.Error() != "these updates didn't install: KB2 x" || len(got) != 1 || !restart || args(f, 0)["timeout_seconds"] != float64(3600) {
		t.Errorf("failed: %v %v %v", got, restart, err)
	}
	f = &fake{answers: []map[string]any{ok(map[string]any{})}}
	if got, restart, err := ApplyUpdates(ctx, f, Update{}, time.Hour); err != nil || got == nil || restart {
		t.Errorf("nothing: %v %v %v", got, restart, err)
	}
	if _, _, err := ApplyUpdates(ctx, &fake{}, Update{Categories: []string{"games"}}, time.Hour); err == nil {
		t.Error("an unknown category reached the host")
	}
	if _, _, err := ApplyUpdates(ctx, &fake{err: errors.New("down")}, Update{}, time.Hour); err == nil {
		t.Error("runner error ignored")
	}
}

func TestPackageAndTaskMore(t *testing.T) {
	ctx := context.Background()
	f := &fake{answers: []map[string]any{ok(map[string]any{"installed": true})}}
	if in, err := PackageInstalled(ctx, f, "{abc}"); err != nil || !in || args(f, 0)["code"] != "{ABC}" {
		t.Errorf("installed: %v, %v", in, err)
	}
	f = &fake{answers: []map[string]any{ok(nil)}}
	if err := ApplyTaskRemove(ctx, f, `\`, "t"); err != nil || args(f, 0)["name"] != "t" {
		t.Errorf("remove: %v", err)
	}
	if err := ApplyTaskRemove(ctx, f, `no-slash`, "t"); err == nil || err.Error() != "not a task name" {
		t.Errorf("bad folder: %v", err)
	}
	f = &fake{answers: []map[string]any{ok(map[string]any{"exists": true, "user_sid": "S-1-5-18"})}}
	if a, err := ReadTask(ctx, f, Task{Path: `\`, Name: "t", User: "SYSTEM"}); err != nil || !a.Exists || a.UserSID != "S-1-5-18" || args(f, 0)["user"] != "SYSTEM" {
		t.Errorf("read %+v, %v", a, err)
	}
	if (Task{HasPassword: true}).logonFor("S-1-5-18") != "Password" {
		t.Error("a password logon")
	}
}

func TestShareReadAndApply(t *testing.T) {
	ctx := context.Background()
	s := Share{Name: "Finance", Path: `D:\Shares\Finance`, Full: []string{`BUILTIN\Administrators`}}
	sids := map[string]string{`BUILTIN\Administrators`: "S-1-5-32-544"}
	// PowerShell sends a list of one as the one object.
	a, err := ReadShare(ctx, &fake{answers: []map[string]any{ok(map[string]any{"exists": true, "path": `D:\Shares\Finance`, "access": map[string]any{"account": "Everyone", "sid": "S-1-1-0", "right": "Read", "type": "Allow"}, "sids": sids})}}, s)
	if err != nil || len(a.Access) != 1 || a.Access[0].SID != "S-1-1-0" || a.SIDs[`BUILTIN\Administrators`] != "S-1-5-32-544" {
		t.Errorf("one entry: %+v, %v", a, err)
	}
	if a, err := ReadShare(ctx, &fake{answers: []map[string]any{ok(map[string]any{"exists": true, "access": nil})}}, s); err != nil || a.Access != nil {
		t.Errorf("no access: %+v, %v", a, err)
	}
	if _, err := ReadShare(ctx, &fake{answers: []map[string]any{ok(map[string]any{"access": "x"})}}, s); err == nil {
		t.Error("text as access")
	}

	// A new share's Everyone Read goes, and the step's list goes in.
	f := &fake{answers: []map[string]any{ok(map[string]any{"exists": false, "sids": sids}), ok(nil)}}
	d := "money"
	s.Description = &d
	if err := ApplyShare(ctx, f, s); err != nil {
		t.Fatal(err)
	}
	if sent := args(f, 1); !equalJSON(sent["revoke"], []any{"Everyone"}) || sent["description"] != "money" || len(sent["grant"].([]any)) != 1 {
		t.Errorf("sent %v", sent)
	}
	f = &fake{answers: []map[string]any{ok(map[string]any{"exists": true, "path": `E:\Other`, "sids": sids})}}
	if err := ApplyShare(ctx, f, s); err == nil || !strings.Contains(err.Error(), "can't change in place") {
		t.Errorf("moved: %v", err)
	}
	f = &fake{answers: []map[string]any{ok(map[string]any{"exists": true, "path": `D:\Shares\Finance\`, "sids": map[string]string{}})}}
	if err := ApplyShare(ctx, f, s); err == nil || !strings.Contains(err.Error(), "isn't one this host knows") {
		t.Errorf("unknown account: %v", err)
	}
	if err := ApplyShare(ctx, &fake{err: errors.New("down")}, s); err == nil {
		t.Error("read error ignored")
	}
	if err := ApplyShare(ctx, &fake{}, Share{Name: "C$", Path: `C:\`}); err == nil {
		t.Error("an admin share reached the host")
	}
	bad := "two\nlines"
	if (Share{Name: "x", Path: `D:\x`, Description: &bad}).Validate() == nil {
		t.Error("a two-line description")
	}

	m := Share{Name: "x", Path: `D:\x`, Description: &d}
	if ok, _ := m.Matches(ActualShare{Exists: true, Path: `D:\y`}); ok {
		t.Error("another folder matched")
	}
	if ok, _ := m.Matches(ActualShare{Exists: true, Path: `D:\x`, Description: "other"}); ok {
		t.Error("another description matched")
	}
	// Full beats Read for the same account.
	if r := (Share{Read: []string{"a"}, Full: []string{"a"}}).rights(); r["a"] != "Full" {
		t.Errorf("rights %v", r)
	}
}

func TestADObjectsMore(t *testing.T) {
	ctx := context.Background()
	if err := ApplyOU(ctx, &fake{}, OU{Name: "o"}, ActualOU{}); !errors.Is(err, errNoAD) {
		t.Errorf("no AD: %v", err)
	}
	if err := ApplyOU(ctx, &fake{}, OU{Name: "o", Path: "OU=Gone,DC=lab"}, ActualOU{AD: true}); err == nil || err.Error() != "OU o: the path OU=Gone,DC=lab doesn't exist" {
		t.Errorf("no parent: %v", err)
	}
	f := &fake{answers: []map[string]any{ok(nil)}}
	if err := ApplyOU(ctx, f, OU{Name: "o"}, ActualOU{AD: true, Base: "DC=lab"}); err != nil || args(f, 0)["create"] != true || args(f, 0)["path"] != "DC=lab" {
		t.Errorf("create: %v", err)
	}

	// Removing reads first and leaves what isn't there.
	for name, rm := range map[string]func(ps.Runner) error{
		"ou":    func(r ps.Runner) error { return ApplyOURemove(ctx, r, OU{Name: "o"}) },
		"group": func(r ps.Runner) error { return ApplyADGroupRemove(ctx, r, "g") },
		"user":  func(r ps.Runner) error { return ApplyADUserRemove(ctx, r, "u") },
	} {
		f := &fake{answers: []map[string]any{ok(map[string]any{"ad": true, "exists": false})}}
		if err := rm(f); err != nil || len(f.sent) != 1 {
			t.Errorf("%s missing: %v, %d runs", name, err, len(f.sent))
		}
		f = &fake{answers: []map[string]any{ok(map[string]any{"ad": true, "exists": true, "dn": "CN=x,DC=lab"}), ok(nil)}}
		if err := rm(f); err != nil || len(f.sent) != 2 || args(f, 1)["dn"] != "CN=x,DC=lab" {
			t.Errorf("%s: %v, sent %v", name, err, f.sent)
		}
		if err := rm(&fake{err: errors.New("down")}); err == nil {
			t.Errorf("%s: read error ignored", name)
		}
	}

	if err := ApplyADGroup(ctx, &fake{}, ADGroup{Name: "g", Path: "OU=Gone,DC=lab"}, ActualADGroup{AD: true}); err == nil || !strings.Contains(err.Error(), "the path OU=Gone,DC=lab doesn't exist") {
		t.Errorf("group path: %v", err)
	}
	// A member known only by DN goes in by DN.
	f = &fake{answers: []map[string]any{ok(nil)}}
	g := ADGroup{Name: "g", Members: []string{"web1$"}}
	if err := ApplyADGroup(ctx, f, g, ActualADGroup{AD: true, Exists: true, Wanted: map[string]ADPrincipal{"web1$": {DN: "CN=web1,DC=lab"}}}); err != nil || !equalJSON(args(f, 0)["add"], []any{"CN=web1,DC=lab"}) {
		t.Errorf("by DN: %v, sent %v", err, f.sent)
	}

	if err := ApplyADUser(ctx, &fake{}, ADUser{Name: "u"}, ActualADUser{}, nil); !errors.Is(err, errNoAD) {
		t.Errorf("user, no AD: %v", err)
	}
	if err := ApplyADUser(ctx, &fake{}, ADUser{Name: "u", Path: "OU=Gone,DC=lab"}, ActualADUser{AD: true}, nil); err == nil || !strings.Contains(err.Error(), "the path OU=Gone,DC=lab doesn't exist") {
		t.Errorf("user path: %v", err)
	}
}

func TestSatisfiedAndScript(t *testing.T) {
	ctx := context.Background()
	if ok, err := Satisfied(ctx, &fake{}, Guards{}, nil); ok || err != nil {
		t.Errorf("no guards: %v, %v", ok, err)
	}
	// Creates doesn't hold: Unless never runs.
	f := &fake{answers: []map[string]any{ok(false)}}
	if ok, err := Satisfied(ctx, f, Guards{Creates: `C:\done`, Unless: "x"}, nil); ok || err != nil || len(f.sent) != 1 {
		t.Errorf("creates unmet: %v, %v, %d runs", ok, err, len(f.sent))
	}
	f = &fake{answers: []map[string]any{ok(true), ok(true)}}
	if ok, err := Satisfied(ctx, f, Guards{Removes: `C:\gone`, Unless: "Test-Path x"}, nil); !ok || err != nil || len(f.sent) != 2 {
		t.Errorf("both hold: %v, %v", ok, err)
	}
	// A check that throws doesn't hold, and isn't an error.
	if ok, err := Satisfied(ctx, &fake{answers: []map[string]any{{"ok": false, "error": "boom"}}}, Guards{Unless: "throw"}, nil); ok || err != nil {
		t.Errorf("thrown: %v, %v", ok, err)
	}
	f = &fake{answers: []map[string]any{{"ok": true, "rc": 1}}}
	if ok, _ := Satisfied(ctx, f, Guards{Unless: "exit 1"}, nil); ok {
		t.Error("a non-zero exit held")
	}
	if (Guards{Removes: "rel"}).Validate() == nil || (Guards{Creates: `C:\a`, Removes: `C:\b`}).Validate() != nil {
		t.Error("guard paths")
	}

	f = &fake{answers: []map[string]any{{"ok": true, "rc": 3, "text": "out s3cret"}}}
	if out, err := RunScript(ctx, f, "x", nil, []string{"s3cret"}, time.Minute); err == nil || err.Error() != "the script's last native program exited with 3: out (sensitive value)" || out.Stdout != "out (sensitive value)" {
		t.Errorf("exit 3: %+v, %v", out, err)
	}
	long := strings.Repeat("x", MaxOutput+1)
	if got := clip(long); len(got) != MaxOutput+len("\n[output truncated]") || !strings.HasSuffix(got, "[output truncated]") {
		t.Errorf("clip %d", len(got))
	}
	if Scrub("a b", []string{" \n"}) != "a b" {
		t.Error("a secret of only spacing blanked something")
	}

	defer func() {
		if recover() == nil {
			t.Error("a missing script didn't panic")
		}
	}()
	script("no_such_script.ps1")
}

func TestWaitForString(t *testing.T) {
	for w, want := range map[WaitFor]string{{Path: `C:\x`}: `C:\x`, {Service: "W3SVC"}: "service W3SVC", {Port: 80}: "port 80"} {
		if got := w.String(); got != want {
			t.Errorf("%+v: %q", w, got)
		}
	}
	f := &fake{answers: []map[string]any{ok(true)}}
	if ok, err := (WaitFor{Service: "W3SVC"}).Ready(context.Background(), f); !ok || err != nil || args(f, 0)["service"] != "W3SVC" {
		t.Errorf("ready: %v, %v", ok, err)
	}
	f = &fake{answers: []map[string]any{ok("boot-1")}}
	if id, err := BootID(context.Background(), f); id != "boot-1" || err != nil {
		t.Errorf("boot id %q, %v", id, err)
	}
	if err := ApplyReboot(context.Background(), &fake{answers: []map[string]any{{"ok": false, "error": "denied"}}}); err == nil || err.Error() != "scheduling a reboot: denied" {
		t.Errorf("reboot: %v", err)
	}
}

// The promotions report the reboot Windows wants, and a garbled answer is
// an error, not "no reboot".
func TestADPromotionsReportRestart(t *testing.T) {
	ctx := context.Background()
	for name, apply := range map[string]func(ps.Runner) (bool, error){
		"forest": func(r ps.Runner) (bool, error) {
			return ApplyForest(ctx, r, Forest{DomainName: "lab.test", DatabasePath: `F:\NTDS`}, "dsrm", time.Minute)
		},
		"membership": func(r ps.Runner) (bool, error) {
			return ApplyMembership(ctx, r, Membership{Domain: "lab.test", Username: `LAB\j`}, "pw", time.Minute)
		},
		"domain controller": func(r ps.Runner) (bool, error) {
			return ApplyDomainController(ctx, r, DomainController{DomainName: "lab.test", Username: `LAB\j`, LogPath: `F:\Logs`}, "pw", "dsrm", time.Minute)
		},
		"child domain": func(r ps.Runner) (bool, error) {
			return ApplyChildDomain(ctx, r, ChildDomain{DomainName: "emea.lab.test", Username: `lab.test\j`}, "pw", "dsrm", time.Minute)
		},
	} {
		f := &fake{answers: []map[string]any{ok(map[string]any{"restart": true})}}
		if restart, err := apply(f); err != nil || !restart {
			t.Errorf("%s: %v, %v", name, restart, err)
		}
		if _, err := apply(&fake{answers: []map[string]any{ok("x")}}); err == nil || !strings.Contains(err.Error(), "reading the result for") {
			t.Errorf("%s garbled: %v", name, err)
		}
	}
	if _, err := ApplyDomainController(ctx, &fake{}, DomainController{DomainName: "lab.test", Username: "j"}, "", "x", time.Minute); err == nil || !strings.Contains(err.Error(), "password_wo") {
		t.Errorf("no password: %v", err)
	}
	if _, err := ApplyChildDomain(ctx, &fake{}, ChildDomain{DomainName: "a.lab.test"}, "", "x", time.Minute); err == nil {
		t.Error("child domain with no password")
	}
	if _, err := ApplyChildDomain(ctx, &fake{}, ChildDomain{DomainName: "a.lab.test"}, "x", "", time.Minute); err == nil {
		t.Error("child domain with no safe mode password")
	}
	if _, err := ReadForest(ctx, &fake{answers: []map[string]any{ok("x")}}); err == nil || err.Error() != "reading the forest: the host's answer wasn't valid" {
		t.Errorf("garbled forest: %v", err)
	}
	if _, err := ReadForest(ctx, &fake{answers: []map[string]any{{"ok": false, "error": "denied"}}}); err == nil {
		t.Error("forest host error ignored")
	}
	// A DC whose root DN is unknown is named by its domain.
	if a, err := ReadForest(ctx, &fake{answers: []map[string]any{ok(map[string]any{"role": 5, "domain": "lab.test"})}}); err != nil || a.Forest != "lab.test" {
		t.Errorf("DC without root DN: %+v, %v", a, err)
	}
	if got := dnToName("OU=x, DC=lab,CN=y,DC=test"); got != "lab.test" {
		t.Errorf("dnToName %q", got)
	}
}

func TestGatherMore(t *testing.T) {
	ctx := context.Background()
	if _, err := Gather(ctx, &fake{answers: []map[string]any{ok("x")}}); err == nil || !strings.Contains(err.Error(), "reading Windows facts") {
		t.Errorf("garbled: %v", err)
	}
	if _, err := Gather(ctx, &fake{answers: []map[string]any{{"ok": false, "error": "denied"}}}); err == nil {
		t.Error("host error ignored")
	}
	// An architecture with no other name is kept as Windows gives it, and a build not listed has no release.
	f, err := Gather(ctx, &fake{answers: []map[string]any{ok(map[string]any{"arch": "x86", "build": "99999", "product_type": 3})}})
	if err != nil || f.Arch != "x86" || f.Release != "" {
		t.Errorf("got %+v, %v", f, err)
	}
	if err := ApplyReboot(ctx, &fake{answers: []map[string]any{ok(nil)}}); err != nil {
		t.Errorf("reboot: %v", err)
	}
	if _, err := BootID(ctx, &fake{answers: []map[string]any{{"ok": false, "error": "denied"}}}); err == nil {
		t.Error("boot id host error ignored")
	}
	// A script that succeeds, and one whose failure printed to stderr.
	if out, err := RunScript(ctx, &fake{answers: []map[string]any{{"ok": true, "text": "done"}}}, "x", nil, nil, time.Minute); err != nil || out.Stdout != "done" {
		t.Errorf("success: %+v, %v", out, err)
	}
	// Removes alone, met.
	if ok, err := Satisfied(ctx, &fake{answers: []map[string]any{ok(true)}}, Guards{Removes: `C:\x`}, nil); !ok || err != nil {
		t.Errorf("removes: %v, %v", ok, err)
	}
}

func TestFileWritesSend(t *testing.T) {
	ctx := context.Background()
	f := &fake{answers: []map[string]any{ok(map[string]any{"kind": "missing"}), ok(nil), ok(nil)}}
	if _, err := ReadPath(ctx, f, `C:\x`, []string{"a"}, false); err != nil || !equalJSON(args(f, 0)["principals"], []any{"a"}) {
		t.Errorf("principals: %v, sent %v", err, args(f, 0))
	}
	if err := ApplyFile(ctx, f, `C:\x`, []byte("hi"), SecretEntries, nil); err != nil || args(f, 1)["content"] != "aGk=" || args(f, 1)["exact"] != true {
		t.Errorf("file: %v, sent %v", err, args(f, 1))
	}
	// Inheritance left as it is sends none.
	if err := ApplyACL(ctx, f, ACL{Path: `C:\x`}, false); err != nil {
		t.Fatal(err)
	}
	if _, has := args(f, 2)["inherit"]; has {
		t.Errorf("inherit sent: %v", args(f, 2))
	}
	if ValidateEntries(SecretEntries) != nil || ValidateEntries([]Entry{{Principal: "a"}}) == nil {
		t.Error("ValidateEntries")
	}
	// No description leaves the share's as it is.
	f = &fake{answers: []map[string]any{ok(map[string]any{"exists": true, "path": `D:\s`}), ok(nil)}}
	if err := ApplyShare(ctx, f, Share{Name: "s", Path: `D:\s`}); err != nil {
		t.Fatal(err)
	}
	if _, has := args(f, 1)["description"]; has {
		t.Errorf("description sent: %v", args(f, 1))
	}
	// Creates alone, met; a failure that printed only to stderr says so.
	if ok, err := Satisfied(ctx, &fake{answers: []map[string]any{ok(true)}}, Guards{Creates: `C:\x`}, nil); !ok || err != nil {
		t.Errorf("creates: %v, %v", ok, err)
	}
	g := &fake{answers: []map[string]any{{"ok": true, "rc": 2}}}
	if _, err := RunScript(ctx, g, "x", nil, nil, time.Minute); err == nil || !strings.HasPrefix(err.Error(), "the script's last native program exited with 2") {
		t.Errorf("exit 2: %v", err)
	}
}
