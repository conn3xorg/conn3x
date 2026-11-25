// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"encoding/base64"
	"strings"
	"sync"
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/providers"
)

// winEntryVal is one acl or entry block.
func winEntryVal(typeName, block, principal, inheritance string, rights ...string) cty.Value {
	ty := resourceTypes[typeName].schema().Block.BlockTypes[block].ImpliedType()
	vals := map[string]cty.Value{}
	for k, a := range ty.AttributeTypes() {
		vals[k] = cty.NullVal(a)
	}
	var rs []cty.Value
	for _, r := range rights {
		rs = append(rs, cty.StringVal(r))
	}
	vals["principal"], vals["rights"] = cty.StringVal(principal), cty.ListVal(rs)
	if inheritance != "" {
		vals["inheritance"] = cty.StringVal(inheritance)
	}
	return cty.ObjectVal(vals)
}

// winDisk is one path on the fake host, as read_path reports it.
type winDisk struct {
	mu   sync.Mutex
	path map[string]any
}

func (d *winDisk) set(kind, sha string, aces ...map[string]any) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if aces == nil {
		aces = []map[string]any{}
	}
	d.path = map[string]any{"kind": kind, "sha256": sha, "protected": true, "owner_trusted": true, "owner": "S-1-5-32-544", "entries": aces,
		"sids": map[string]any{"Users": "S-1-5-32-545", "S-1-5-18": "S-1-5-18", "S-1-5-32-544": "S-1-5-32-544", "Administrators": "S-1-5-32-544"}}
}

func (d *winDisk) edit(k string, v any) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.path[k] = v
}

func (d *winDisk) read(map[string]any) (any, string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.path, ""
}

func winACE(sid string, mask int64, flags int) map[string]any {
	return map[string]any{"sid": sid, "mask": mask, "allow": true, "flags": flags}
}

const winReadMask = 0x020089

func TestWinFileLifecycle(t *testing.T) {
	h := newWinFakeHost(t)
	const typ = "conn3x_windows_file"
	disk := &winDisk{}
	disk.set("missing", "")
	h.onFunc("read_path.ps1", disk.read)
	h.onFunc("apply_file.ps1", func(args map[string]any) (any, string) {
		b, _ := base64.StdEncoding.DecodeString(args["content"].(string))
		disk.set("file", strings.ToUpper(digest(string(b))), winACE("S-1-5-32-545", winReadMask, 0))
		return nil, ""
	})
	h.on("apply_file_remove.ps1", nil)
	cfg := h.step(typ, map[string]cty.Value{
		"path": cty.StringVal(`C:/app/config.json`), "content": cty.StringVal("hello"), "on_remove": cty.StringVal("delete"),
		"acl": cty.ListVal([]cty.Value{winEntryVal(typ, "acl", "Users", "", "Read")}),
	})
	state := h.create(typ, cfg)
	got := h.sent("apply_file.ps1")
	if len(got) != 1 || got[0]["path"] != `C:\app\config.json` || got[0]["content"] != base64.StdEncoding.EncodeToString([]byte("hello")) || got[0]["exact"] != true {
		t.Fatalf("apply sent %v", got)
	}
	if e := got[0]["entries"].([]any); len(e) != 1 || e[0].(map[string]any)["mask"] != float64(winReadMask) || e[0].(map[string]any)["flags"] != float64(0) {
		t.Errorf("entries sent %v", e)
	}
	if state.GetAttr("sha256").AsString() != digest("hello") || !winSynced(t, state) {
		t.Errorf("state %#v", state)
	}
	// Reads hash the file and resolve the acl's principals.
	if r := h.sent("read_path.ps1"); r[0]["hash"] != true || r[0]["principals"].([]any)[0] != "Users" {
		t.Errorf("read sent %v", r[0])
	}

	// Already as configured: nothing is written.
	h.create(typ, cfg)
	if n := len(h.sent("apply_file.ps1")); n != 1 {
		t.Errorf("an unchanged file was written %d times", n)
	}

	if r := h.read(typ, state); r.Diagnostics.HasErrors() || !winSynced(t, r.NewState) {
		t.Errorf("unchanged: %v", r.Diagnostics.Err())
	}
	// New content shows in sha256, which plans the write; in_sync is the rules.
	disk.edit("sha256", digest("edited"))
	if r := h.read(typ, state); r.NewState.GetAttr("sha256").AsString() != digest("edited") || !winSynced(t, r.NewState) {
		t.Errorf("edited content: %#v", r.NewState)
	}
	disk.edit("entries", []map[string]any{winACE("S-1-5-32-545", winReadMask, 0), winACE("S-1-1-0", winReadMask, 0)})
	if r := h.read(typ, state); winSynced(t, r.NewState) {
		t.Error("an extra rule read as in sync")
	}
	disk.edit("sids", map[string]any{})
	if r := h.read(typ, state); r.Diagnostics.HasErrors() || winSynced(t, r.NewState) {
		t.Errorf("a principal gone from the host: %v", r.Diagnostics.Err())
	}
	disk.set("file", digest("hello"))
	disk.edit("link_on_way", `C:\app`)
	if r := h.read(typ, state); winSynced(t, r.NewState) {
		t.Error("a link on the way read as in sync")
	}
	disk.set("missing", "")
	if r := h.read(typ, state); !r.NewState.IsNull() {
		t.Errorf("a missing file kept its state: %#v", r.NewState)
	}

	if r := h.destroy(typ, state); r.Diagnostics.HasErrors() {
		t.Fatal(r.Diagnostics.Err())
	}
	if got := h.sent("apply_file_remove.ps1"); len(got) != 1 || got[0]["path"] != `C:\app\config.json` {
		t.Errorf("remove sent %v", got)
	}
	h.fail("apply_file_remove.ps1", "in use")
	if r := h.destroy(typ, state); !r.Diagnostics.HasErrors() || !strings.Contains(r.Diagnostics.Err().Error(), "windows_file: in use") {
		t.Errorf("a failed remove: %v", r.Diagnostics.Err())
	}
}

func TestWinFileApplyFailures(t *testing.T) {
	h := newWinFakeHost(t)
	const typ = "conn3x_windows_file"
	disk := &winDisk{}
	disk.set("missing", "")
	h.onFunc("read_path.ps1", disk.read)
	cfg := h.step(typ, map[string]cty.Value{"path": cty.StringVal(`C:\app\x`), "content": cty.StringVal("x")})
	apply := func() string {
		t.Helper()
		r := h.update(typ, cty.NullVal(cfg.Type()), cfg)
		if !r.Diagnostics.HasErrors() {
			t.Fatal("applied")
		}
		return r.Diagnostics.Err().Error()
	}

	h.fail("apply_file.ps1", "Access is denied")
	if err := apply(); !strings.Contains(err, `writing C:\app\x: Access is denied`) {
		t.Errorf("write failed: %s", err)
	}
	// Written, but read back as something else.
	h.on("apply_file.ps1", nil)
	if err := apply(); !strings.Contains(err, "something else changed it") {
		t.Errorf("readback: %s", err)
	}
	h.fail("read_path.ps1", "boom")
	if err := apply(); !strings.Contains(err, "windows_file: boom") {
		t.Errorf("read failed: %s", err)
	}
	// A bad path stops before anything connects.
	bad := h.step(typ, map[string]cty.Value{"path": cty.StringVal(`\\srv\x`), "content": cty.StringVal("x"), "in_sync": cty.UnknownVal(cty.Bool)})
	n := len(h.sent("read_path.ps1"))
	if r := resourceTypes[typ].apply(ctx, providers.ApplyResourceChangeRequest{PriorState: cty.NullVal(bad.Type()), PlannedState: bad, Config: bad}); !r.Diagnostics.HasErrors() || len(h.sent("read_path.ps1")) != n {
		t.Errorf("a share: %v", r.Diagnostics.Err())
	}
	if r := h.read(typ, bad); !r.Diagnostics.HasErrors() {
		t.Error("a share read without error")
	}
}

// Write-only content is written under SYSTEM and Administrators alone, never
// lands in state, and never shows in an error.
func TestWinFileSecret(t *testing.T) {
	t.Setenv(hmacKeyEnv, strings.Repeat("k", 32))
	h := newWinFakeHost(t)
	const typ, secret = "conn3x_windows_file", "s3ntinel"
	disk := &winDisk{}
	disk.set("missing", "")
	h.onFunc("read_path.ps1", disk.read)
	h.onFunc("apply_file.ps1", func(map[string]any) (any, string) {
		disk.set("file", digest(secret), winACE("S-1-5-18", 0x1f01ff, 0), winACE("S-1-5-32-544", 0x1f01ff, 0))
		return nil, ""
	})
	cfg := h.step(typ, map[string]cty.Value{"path": cty.StringVal(`C:\s`), "content_wo": cty.StringVal(secret)})
	state := h.create(typ, cfg)
	key, _ := hmacKey(false)
	if !state.GetAttr("sha256").IsNull() || state.GetAttr("content_hmac").AsString() != winWoHMAC(key, `C:\s`, digest(secret)) {
		t.Errorf("state %#v", state)
	}
	got := h.sent("apply_file.ps1")
	if len(got) != 1 || got[0]["exact"] != true || len(got[0]["entries"].([]any)) != 2 {
		t.Errorf("apply sent %v", got)
	}
	if r := h.read(typ, state); !winSynced(t, r.NewState) || !r.NewState.GetAttr("content_hmac").RawEquals(state.GetAttr("content_hmac")) {
		t.Errorf("refresh: %#v", r.NewState)
	}
	disk.edit("sha256", digest("other"))
	if r := h.read(typ, state); r.NewState.GetAttr("content_hmac").RawEquals(state.GetAttr("content_hmac")) {
		t.Error("new content kept the old content_hmac")
	}

	disk.set("missing", "")
	h.fail("apply_file.ps1", "could not write "+secret)
	r := h.update(typ, cty.NullVal(cfg.Type()), cfg)
	if !r.Diagnostics.HasErrors() || strings.Contains(r.Diagnostics.Err().Error(), secret) {
		t.Errorf("error %v", r.Diagnostics.Err())
	}
	// State hashed with another key is refused rather than read as drift.
	t.Setenv(hmacKeyEnv, strings.Repeat("j", 32))
	disk.set("file", digest(secret))
	if r := h.read(typ, state); !r.Diagnostics.HasErrors() {
		t.Error("a different key read without error")
	}
}

func TestWinDirectoryLifecycle(t *testing.T) {
	h := newWinFakeHost(t)
	const typ = "conn3x_windows_directory"
	disk := &winDisk{}
	disk.set("missing", "")
	h.onFunc("read_path.ps1", disk.read)
	h.onFunc("apply_directory.ps1", func(map[string]any) (any, string) {
		disk.set("directory", "", winACE("S-1-5-32-544", 0x1f01ff, 3))
		return nil, ""
	})
	cfg := h.step(typ, map[string]cty.Value{"path": cty.StringVal(`C:\app\logs\`), "acl": cty.ListVal([]cty.Value{winEntryVal(typ, "acl", "Administrators", "", "FullControl")})})
	state := h.create(typ, cfg)
	got := h.sent("apply_directory.ps1")
	if len(got) != 1 || got[0]["path"] != `C:\app\logs` || got[0]["exact"] != true {
		t.Fatalf("apply sent %v", got)
	}
	// A folder's rule is inherited below it unless said otherwise.
	if e := got[0]["entries"].([]any)[0].(map[string]any); e["flags"] != float64(3) {
		t.Errorf("entry sent %v", e)
	}
	if r := h.sent("read_path.ps1"); r[0]["hash"] != false {
		t.Errorf("a folder read asked for a hash: %v", r[0])
	}
	if !winSynced(t, state) {
		t.Error("not in sync")
	}
	if r := h.read(typ, state); !winSynced(t, r.NewState) {
		t.Error("unchanged folder read as out of sync")
	}
	disk.edit("kind", "file")
	if r := h.read(typ, state); winSynced(t, r.NewState) {
		t.Error("a file in its place read as in sync")
	}
	disk.set("directory", "")
	disk.edit("sids", map[string]any{})
	if r := h.read(typ, state); winSynced(t, r.NewState) {
		t.Error("an unknown principal read as in sync")
	}
	disk.set("missing", "")
	if r := h.read(typ, state); !r.NewState.IsNull() {
		t.Error("a missing folder kept its state")
	}
	// Removing the step leaves the folder.
	if r := h.destroy(typ, state); r.Diagnostics.HasErrors() || len(h.applied()) != 1 {
		t.Errorf("remove ran %v: %v", h.applied(), r.Diagnostics.Err())
	}

	h.on("apply_directory.ps1", nil)
	if r := h.update(typ, cty.NullVal(cfg.Type()), cfg); !r.Diagnostics.HasErrors() || !strings.Contains(r.Diagnostics.Err().Error(), "something else changed it") {
		t.Errorf("still missing after apply: %v", r.Diagnostics.Err())
	}
	disk.set("directory", "")
	disk.edit("sids", map[string]any{})
	if r := h.update(typ, cty.NullVal(cfg.Type()), cfg); !r.Diagnostics.HasErrors() || !strings.Contains(r.Diagnostics.Err().Error(), "no such user or group") {
		t.Errorf("unknown principal: %v", r.Diagnostics.Err())
	}
	h.fail("apply_directory.ps1", "denied")
	if r := h.update(typ, cty.NullVal(cfg.Type()), cfg); !r.Diagnostics.HasErrors() || !strings.Contains(r.Diagnostics.Err().Error(), `making C:\app\logs: denied`) {
		t.Errorf("failed: %v", r.Diagnostics.Err())
	}
	h.fail("read_path.ps1", "gone")
	if r := h.read(typ, state); !r.Diagnostics.HasErrors() {
		t.Error("a failed read reported no error")
	}
	if d := resourceTypes[typ].validate(h.step(typ, map[string]cty.Value{"path": cty.StringVal(`C:\CON`)})); !d.HasErrors() {
		t.Error("accepted a device name")
	}
}

func TestWinACLLifecycle(t *testing.T) {
	h := newWinFakeHost(t)
	const typ = "conn3x_windows_acl"
	disk := &winDisk{}
	disk.set("missing", "")
	h.onFunc("read_path.ps1", disk.read)
	h.onFunc("apply_acl.ps1", func(map[string]any) (any, string) {
		disk.edit("entries", []map[string]any{winACE("S-1-5-32-545", winReadMask, 3)})
		disk.edit("protected", false)
		return nil, ""
	})
	cfg := h.step(typ, map[string]cty.Value{
		"path": cty.StringVal(`C:\data`), "inherit": cty.True, "owner": cty.StringVal("Administrators"),
		"entry": cty.ListVal([]cty.Value{winEntryVal(typ, "entry", "Users", "", "Read")}),
	})
	fail := func(want string) {
		t.Helper()
		r := h.update(typ, cty.NullVal(cfg.Type()), cfg)
		if !r.Diagnostics.HasErrors() || !strings.Contains(r.Diagnostics.Err().Error(), want) {
			t.Errorf("want %q, got %v", want, r.Diagnostics.Err())
		}
	}
	fail("Create it in an earlier step")
	disk.set("directory", "")
	state := h.create(typ, cfg)
	got := h.sent("apply_acl.ps1")
	if len(got) != 1 || got[0]["owner"] != "Administrators" || got[0]["inherit"] != true || got[0]["exact"] != false {
		t.Fatalf("apply sent %v", got)
	}
	if r := h.sent("read_path.ps1"); strings.Join(winStrings(r[0]["principals"]), ",") != "Users,Administrators" {
		t.Errorf("read sent %v", r[0])
	}
	if !winSynced(t, state) {
		t.Error("not in sync")
	}
	// Matching rules write nothing.
	h.create(typ, cfg)
	if n := len(h.sent("apply_acl.ps1")); n != 1 {
		t.Errorf("matching rules applied %d times", n)
	}
	if r := h.read(typ, state); !winSynced(t, r.NewState) {
		t.Error("matching rules read as out of sync")
	}
	disk.edit("owner", "S-1-5-32-545")
	if r := h.read(typ, state); winSynced(t, r.NewState) {
		t.Error("another owner read as in sync")
	}
	disk.edit("kind", "link")
	if r := h.read(typ, state); winSynced(t, r.NewState) {
		t.Error("a link read as in sync")
	}
	disk.set("directory", "")
	disk.edit("sids", map[string]any{"Users": "S-1-5-32-545"})
	if r := h.read(typ, state); winSynced(t, r.NewState) {
		t.Error("an unknown owner read as in sync")
	}
	fail("no such user or group on the host: Administrators")

	// Rules the host doesn't keep fail rather than loop.
	disk.set("directory", "")
	h.on("apply_acl.ps1", nil)
	fail("don't match what was set")
	h.fail("apply_acl.ps1", "denied")
	fail(`setting rules on C:\data: denied`)

	// Inheritance means nothing on a file.
	disk.set("file", "")
	inh := h.step(typ, map[string]cty.Value{"path": cty.StringVal(`C:\data`), "entry": cty.ListVal([]cty.Value{winEntryVal(typ, "entry", "Users", "container", "Read")})})
	if r := h.update(typ, cty.NullVal(inh.Type()), inh); !r.Diagnostics.HasErrors() || !strings.Contains(r.Diagnostics.Err().Error(), "is a file") {
		t.Errorf("inheritance on a file: %v", r.Diagnostics.Err())
	}
	// Removing the step leaves the rules.
	n := len(h.applied())
	if r := h.destroy(typ, state); r.Diagnostics.HasErrors() || len(h.applied()) != n {
		t.Errorf("remove: %v", r.Diagnostics.Err())
	}
	h.fail("read_path.ps1", "gone")
	if r := h.read(typ, state); !r.Diagnostics.HasErrors() {
		t.Error("a failed read reported no error")
	}
	fail("windows_acl: gone")
	if d := resourceTypes[typ].validate(h.step(typ, map[string]cty.Value{"path": cty.StringVal(`C:\x`), "owner": cty.StringVal("a|b")})); !d.HasErrors() {
		t.Error("accepted a bad owner")
	}
}

func winStrings(v any) []string {
	var out []string
	for _, s := range v.([]any) {
		out = append(out, s.(string))
	}
	return out
}

// A windows_file with source_path copies a file already on the host, plans
// clean once the copy matches, and plans a copy when either file changes,
// with neither file's content in the plan or state (#1377).
func TestWinFileSourcePath(t *testing.T) {
	h := newWinFakeHost(t)
	const typ, dest, src = "conn3x_windows_file", `C:\app\app.conf`, `C:\app\app.conf.sample`
	disks := map[string]*winDisk{dest: {}, src: {}}
	disks[dest].set("missing", "")
	disks[src].set("missing", "")
	h.onFunc("read_path.ps1", func(args map[string]any) (any, string) { return disks[args["path"].(string)].read(args) })
	h.onFunc("apply_file.ps1", func(args map[string]any) (any, string) {
		s := disks[args["source"].(string)]
		if s.path["kind"] != "file" {
			return nil, "source_path " + src + " doesn't exist on the host; a step that creates it has to come first"
		}
		disks[dest].set("file", s.path["sha256"].(string))
		return nil, ""
	})
	cfg := h.step(typ, map[string]cty.Value{"path": cty.StringVal(dest), "source_path": cty.StringVal("C:/app/app.conf.sample")})
	null := cty.NullVal(cfg.Type())

	// Missing at plan is "will copy": an earlier step may make it. At apply
	// it fails, naming it, before anything is written.
	planned := h.plan(typ, null, cfg).PlannedState
	if planned.GetAttr("sha256").IsKnown() || planned.GetAttr("source_sha256").IsKnown() || !planned.GetAttr("content").IsNull() {
		t.Fatalf("plan before the source exists: %#v", planned)
	}
	r := resourceTypes[typ].apply(ctx, providers.ApplyResourceChangeRequest{TypeName: typ, PriorState: null, PlannedState: planned, Config: cfg})
	if err := r.Diagnostics.Err(); err == nil || !strings.Contains(err.Error(), "source_path "+src+" doesn't exist on the host") {
		t.Fatalf("apply with the source missing: %v", err)
	}
	if n := len(h.sent("apply_file.ps1")); n != 0 {
		t.Fatalf("a missing source still wrote %d times", n)
	}

	disks[src].set("file", strings.ToUpper(digest("v1")))
	state := h.create(typ, cfg)
	if got := h.sent("apply_file.ps1"); len(got) != 1 || got[0]["source"] != src || got[0]["content"] != "" {
		t.Fatalf("apply sent %v", got)
	}
	if !state.GetAttr("content").IsNull() || !state.GetAttr("content_hmac").IsNull() || state.GetAttr("sha256").AsString() != digest("v1") || state.GetAttr("source_sha256").AsString() != digest("v1") {
		t.Fatalf("state after apply: %#v", state)
	}
	read := h.read(typ, state).NewState
	if p := h.plan(typ, read, cfg).PlannedState; !p.RawEquals(read) {
		t.Fatalf("second plan isn't clean:\n%#v\nwant\n%#v", p, read)
	}

	// A hand edit of the copy, then a change to the source, each plan a copy.
	disks[dest].edit("sha256", digest("edited"))
	if p := h.plan(typ, h.read(typ, state).NewState, cfg).PlannedState; p.GetAttr("sha256").IsKnown() {
		t.Fatalf("a hand edit planned no change: %#v", p)
	}
	disks[dest].edit("sha256", digest("v1"))
	disks[src].edit("sha256", digest("v2"))
	read = h.read(typ, state).NewState
	if read.GetAttr("source_sha256").AsString() != digest("v2") {
		t.Fatalf("source_sha256 after a source change: %#v", read)
	}
	planned = h.plan(typ, read, cfg).PlannedState
	if planned.GetAttr("sha256").IsKnown() {
		t.Fatalf("a source change planned no change: %#v", planned)
	}
	state = resourceTypes[typ].apply(ctx, providers.ApplyResourceChangeRequest{TypeName: typ, PriorState: read, PlannedState: planned, Config: cfg}).NewState
	if state.GetAttr("sha256").AsString() != digest("v2") {
		t.Fatalf("after copying the new source: %#v", state)
	}

	// A source that's gone reads as null and plans a copy.
	disks[src].set("missing", "")
	read = h.read(typ, state).NewState
	if !read.GetAttr("source_sha256").IsNull() {
		t.Fatalf("source_sha256 with the source gone: %#v", read)
	}
	if p := h.plan(typ, read, cfg).PlannedState; p.GetAttr("sha256").IsKnown() {
		t.Fatalf("a missing source planned no change: %#v", p)
	}

	// A folder or a link as the source is an error, never followed.
	for kind, want := range map[string]string{"directory": "is a folder, not a file", "link": "is a link or junction"} {
		disks[src].set(kind, "")
		if r := h.read(typ, state); !r.Diagnostics.HasErrors() || !strings.Contains(r.Diagnostics.Err().Error(), want) {
			t.Errorf("a %s source: %v", kind, r.Diagnostics.Err())
		}
	}
	disks[src].set("missing", "")
	disks[src].edit("link_on_way", `C:\app`)
	if r := h.read(typ, state); !r.Diagnostics.HasErrors() || !strings.Contains(r.Diagnostics.Err().Error(), "link or junction on the way") {
		t.Errorf("a link on the way to the source: %v", r.Diagnostics.Err())
	}
}

// A copy that applies only for its rules still copies the source again, so
// its hashes plan unknown: an earlier step in the same apply may rewrite the
// source, and a known plan would be an inconsistent result (#1376).
func TestWinFileSourcePathRulesDriftPlansHashesUnknown(t *testing.T) {
	h := newWinFakeHost(t)
	const typ, dest, src = "conn3x_windows_file", `C:\app\app.conf`, `C:\app\app.conf.sample`
	disks := map[string]*winDisk{dest: {}, src: {}}
	disks[dest].set("missing", "")
	disks[src].set("file", digest("v1"))
	h.onFunc("read_path.ps1", func(args map[string]any) (any, string) { return disks[args["path"].(string)].read(args) })
	h.onFunc("apply_file.ps1", func(map[string]any) (any, string) {
		disks[dest].set("file", disks[src].path["sha256"].(string))
		return nil, ""
	})
	cfg := h.step(typ, map[string]cty.Value{"path": cty.StringVal(dest), "source_path": cty.StringVal(src)})
	state := h.create(typ, cfg)
	read := h.read(typ, state).NewState
	if p := h.plan(typ, read, cfg).PlannedState; !p.RawEquals(read) {
		t.Fatalf("an in-sync copy planned a change:\n%#v", p)
	}

	vals := read.AsValueMap()
	vals["in_sync"] = cty.False
	read = cty.ObjectVal(vals)
	planned := h.plan(typ, read, cfg).PlannedState
	if planned.GetAttr("sha256").IsKnown() || planned.GetAttr("source_sha256").IsKnown() {
		t.Fatalf("rules drift planned known hashes: %#v", planned)
	}
	// The earlier step.
	disks[src].set("file", digest("v2"))
	r := resourceTypes[typ].apply(ctx, providers.ApplyResourceChangeRequest{TypeName: typ, PriorState: read, PlannedState: planned, Config: cfg})
	if r.Diagnostics.HasErrors() {
		t.Fatal(r.Diagnostics.Err())
	}
	for name, want := range planned.AsValueMap() {
		if want.IsWhollyKnown() && !want.RawEquals(r.NewState.GetAttr(name)) {
			t.Errorf("%s planned %#v, applied %#v", name, want, r.NewState.GetAttr(name))
		}
	}
	if r.NewState.GetAttr("sha256").AsString() != digest("v2") || r.NewState.GetAttr("source_sha256").AsString() != digest("v2") {
		t.Fatalf("after apply: %#v", r.NewState)
	}
}
