// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/providers"
)

const testSSH = `{"host":"203.0.113.10","port":2222,"user":"root"}`

func TestImportPriorPerModule(t *testing.T) {
	for _, tc := range []struct {
		typeName, args, wantID string
		check                  func(cty.Value) error
	}{
		{"conn3x_file", `{"path":"/etc/motd","owner":"root"}`, "203.0.113.10:2222:/etc/motd", func(v cty.Value) error {
			if !v.GetAttr("owner").RawEquals(cty.StringVal("root")) || !v.GetAttr("content").IsNull() {
				return fmt.Errorf("owner %#v, content %#v", v.GetAttr("owner"), v.GetAttr("content"))
			}
			return nil
		}},
		{"conn3x_directory", `{"path":"/srv/app"}`, "203.0.113.10:2222:directory:/srv/app", nil},
		{"conn3x_link", `{"path":"/srv/current","target":"/srv/app"}`, "203.0.113.10:2222:link:/srv/current", nil},
		{"conn3x_package", `{"name":"tree"}`, "203.0.113.10:2222:package:tree", func(v cty.Value) error {
			if !v.GetAttr("state").RawEquals(cty.StringVal("present")) {
				return fmt.Errorf("state = %#v, want the default", v.GetAttr("state"))
			}
			return nil
		}},
		{"conn3x_service", `{"name":"sshd","state":"started"}`, "203.0.113.10:2222:service:sshd.service", nil},
		{"conn3x_user", `{"name":"deploy","groups":["ops"],"uid":1000}`, "203.0.113.10:2222:user:deploy", nil},
		{"conn3x_group", `{"name":"ops","on_remove":"delete"}`, "203.0.113.10:2222:group:ops", func(v cty.Value) error {
			if !v.GetAttr("on_remove").RawEquals(cty.StringVal("delete")) {
				return fmt.Errorf("on_remove = %#v, want the step's", v.GetAttr("on_remove"))
			}
			return nil
		}},
		{"conn3x_authorized_key", `{"user":"deploy","key":"ssh-ed25519 AAAA deploy"}`, "203.0.113.10:2222:authorized_key:deploy", nil},
		{"conn3x_cron", `{"name":"backup","schedule":"@daily","command":"true"}`, "203.0.113.10:2222:cron:backup", nil},
		{"conn3x_timer", `{"name":"cleanup","on_calendar":"daily","command":"true"}`, "203.0.113.10:2222:timer:cleanup", nil},
		{"conn3x_sysctl", `{"name":"vm.swappiness","value":"10"}`, "203.0.113.10:2222:sysctl:vm.swappiness", nil},
		{"conn3x_mount", `{"path":"/mnt/scratch","src":"tmpfs","fstype":"tmpfs"}`, "203.0.113.10:2222:mount:/mnt/scratch", nil},
		{"conn3x_repository", `{"name":"example","url":"https://repo.example.com/","key":"k"}`, "203.0.113.10:2222:repository:example", nil},
	} {
		t.Run(tc.typeName, func(t *testing.T) {
			_, v, err := importPrior(tc.typeName, `{"v":1,"key":"web1","ssh":`+testSSH+`,"args":`+tc.args+`}`)
			if err != nil {
				t.Fatal(err)
			}
			if got := v.GetAttr("id").AsString(); got != tc.wantID {
				t.Errorf("id = %s, want %s", got, tc.wantID)
			}
			if !v.GetAttr("ssh").GetAttr("port").RawEquals(cty.NumberIntVal(2222)) {
				t.Errorf("ssh = %#v", v.GetAttr("ssh"))
			}
			// The default plan gives on_remove, so the plan after an import
			// doesn't change it.
			want := map[bool]string{false: "forget", true: "delete"}[importDeletes[tc.typeName]]
			if tc.typeName != "conn3x_group" && !v.GetAttr("on_remove").RawEquals(cty.StringVal(want)) {
				t.Errorf("on_remove = %#v, want %s", v.GetAttr("on_remove"), want)
			}
			if tc.check != nil {
				if err := tc.check(v); err != nil {
					t.Error(err)
				}
			}
		})
	}
}

func TestImportPriorRejectsBadIDs(t *testing.T) {
	for name, tc := range map[string]struct{ typeName, id, want string }{
		"not json":      {"conn3x_file", "127.0.0.1:/etc/motd", "doesn't read"},
		"version":       {"conn3x_file", `{"v":2,"key":"web1","ssh":` + testSSH + `,"args":{"path":"/x"}}`, "version 2"},
		"unknown field": {"conn3x_file", `{"v":1,"key":"web1","ssh":` + testSSH + `,"args":{"path":"/x"},"extra":1}`, "unknown field"},
		"no ssh":        {"conn3x_file", `{"v":1,"key":"web1","args":{"path":"/x"}}`, "needs key and ssh"},
		"no path":       {"conn3x_file", `{"v":1,"key":"web1","ssh":` + testSSH + `,"args":{}}`, "has no path"},
		"no name":       {"conn3x_user", `{"v":1,"key":"web1","ssh":` + testSSH + `,"args":{}}`, "has no name"},
		"no key":        {"conn3x_authorized_key", `{"v":1,"key":"web1","ssh":` + testSSH + `,"args":{"user":"deploy"}}`, "has no key"},
		"content":       {"conn3x_file", `{"v":1,"key":"web1","ssh":` + testSSH + `,"args":{"path":"/x","content":"s"}}`, "can't hold content"},
		"bad arg":       {"conn3x_package", `{"v":1,"key":"web1","ssh":` + testSSH + `,"args":{"name":"x","nope":1}}`, "nope"},
		"wo not file":   {"conn3x_user", `{"v":1,"key":"web1","ssh":` + testSSH + `,"args":{"name":"x"},"write_only":true}`, "files only"},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := importPrior(tc.typeName, tc.id)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

// A service step that sets state or enabled imports them as the host has
// them, so the plan shows how the host differs from the step.
func TestImportedServiceTakesStateFromTheHost(t *testing.T) {
	read := serviceObj(map[string]cty.Value{
		"name": cty.StringVal("nginx"), "state": cty.StringVal("started"), "enabled": cty.True,
		"running": cty.False, "is_enabled": cty.False,
	})
	got := adopted("conn3x_service", read)
	if !got.GetAttr("state").RawEquals(cty.StringVal("stopped")) || !got.GetAttr("enabled").RawEquals(cty.False) {
		t.Fatalf("state %#v, enabled %#v", got.GetAttr("state"), got.GetAttr("enabled"))
	}
	unset := adopted("conn3x_service", serviceObj(map[string]cty.Value{"name": cty.StringVal("nginx"), "running": cty.True, "is_enabled": cty.True}))
	if !unset.GetAttr("state").IsNull() || !unset.GetAttr("enabled").IsNull() {
		t.Fatal("arguments the step leaves unset must stay unset")
	}
}

func (f *fileTest) importID(args string, writeOnly bool) string {
	ssh := fmt.Sprintf(`{"host":%q,"port":%s,"user":"test","private_key_file":%q,"known_hosts_file":%q}`,
		f.conn.GetAttr("host").AsString(), f.conn.GetAttr("port").AsBigFloat().String(),
		f.conn.GetAttr("private_key_file").AsString(), f.conn.GetAttr("known_hosts_file").AsString())
	return fmt.Sprintf(`{"v":1,"key":"web1","ssh":%s,"args":%s,"write_only":%t}`, ssh, args, writeOnly)
}

// sameSSH is cfg reaching the host the way state does: the test's conn
// leaves out ssh settings the schema has.
func sameSSH(cfg, state cty.Value) cty.Value {
	vals := cfg.AsValueMap()
	vals["ssh"] = state.GetAttr("ssh")
	return cty.ObjectVal(vals)
}

func (f *fileTest) importAs(typeName, id string) providers.ImportResourceStateResponse {
	return f.p.ImportResourceState(ctx, providers.ImportResourceStateRequest{TypeName: typeName, Target: providers.ImportTarget{ID: id}})
}

func TestImportFileThenPlanHasNoChange(t *testing.T) {
	f := newFileTest(t)
	if err := os.WriteFile(f.path, []byte("Welcome\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	resp := f.importAs("conn3x_file", f.importID(fmt.Sprintf(`{"path":%q}`, f.path), false))
	if resp.Diagnostics.HasErrors() {
		t.Fatal(resp.Diagnostics.Err())
	}
	state := f.read(resp.ImportedResources[0].State)
	if got := state.GetAttr("content"); !got.RawEquals(cty.StringVal("Welcome\n")) {
		t.Fatalf("content = %#v", got)
	}
	cfg := sameSSH(f.config(map[string]cty.Value{"content": cty.StringVal("Welcome\n")}), state)
	plan := f.plan(state, cfg)
	if len(plan.RequiresReplace) != 0 || !plan.PlannedState.Equals(state).True() {
		t.Fatalf("plan after import changes something:\n%#v\nwas\n%#v", plan.PlannedState, state)
	}
	changed := f.plan(state, sameSSH(f.config(map[string]cty.Value{"content": cty.StringVal("Managed\n")}), state)).PlannedState
	if changed.GetAttr("content").RawEquals(state.GetAttr("content")) {
		t.Fatal("a different content plans no change")
	}
}

func TestImportWriteOnlyFileKeepsContentOutOfState(t *testing.T) {
	f := newWOTest(t)
	if err := os.WriteFile(f.path, []byte("s3cret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	resp := f.importAs("conn3x_file", f.importID(fmt.Sprintf(`{"path":%q}`, f.path), true))
	if resp.Diagnostics.HasErrors() {
		t.Fatal(resp.Diagnostics.Err())
	}
	state := f.read(resp.ImportedResources[0].State)
	if strings.Contains(fmt.Sprintf("%#v", state), "s3cret") {
		t.Fatal("the secret reached state")
	}
	cfg := sameSSH(f.config(map[string]cty.Value{"content_wo": cty.StringVal("s3cret\n")}), state)
	if planned := f.plan(state, cfg).PlannedState; !planned.Equals(state).True() {
		t.Fatalf("plan after import changes something:\n%#v\nwas\n%#v", planned, state)
	}
}

func TestImportMissingObjectSaysWhatToDo(t *testing.T) {
	f := newFileTest(t)
	resp := f.importAs("conn3x_file", f.importID(fmt.Sprintf(`{"path":%q}`, f.path), false))
	err := resp.Diagnostics.Err()
	if err == nil || !strings.Contains(err.Error(), "Nothing to import on web1") || !strings.Contains(err.Error(), "Remove web1 from the step's import") {
		t.Fatalf("err = %v", err)
	}
}

// A cron step's read says only whether the job matches, so the import asks
// the host first whether the job is there at all.
func TestImportMissingCronSaysWhatToDo(t *testing.T) {
	f := newFileTest(t)
	resp := f.importAs("conn3x_cron", f.importID(`{"name":"conn3x-import-test-none","schedule":"@daily","command":"true"}`, false))
	err := resp.Diagnostics.Err()
	if err == nil || !strings.Contains(err.Error(), "Nothing to import on web1") || !strings.Contains(err.Error(), "cron job conn3x-import-test-none") {
		t.Fatalf("err = %v", err)
	}
}

func TestImportDirectoryAndLink(t *testing.T) {
	f := newFileTest(t)
	dir, link := filepath.Join(f.server.Dir, "app"), filepath.Join(f.server.Dir, "current")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	d := f.importAs("conn3x_directory", f.importID(fmt.Sprintf(`{"path":%q}`, dir), false))
	if d.Diagnostics.HasErrors() {
		t.Fatal(d.Diagnostics.Err())
	}
	if got := d.ImportedResources[0].State.GetAttr("mode"); !got.RawEquals(cty.StringVal("0750")) {
		t.Fatalf("directory mode = %#v", got)
	}
	l := f.importAs("conn3x_link", f.importID(fmt.Sprintf(`{"path":%q}`, link), false))
	if l.Diagnostics.HasErrors() {
		t.Fatal(l.Diagnostics.Err())
	}
	if got := l.ImportedResources[0].State.GetAttr("target"); !got.RawEquals(cty.StringVal(dir)) {
		t.Fatalf("link target = %#v", got)
	}
}

func TestImportUnsupportedType(t *testing.T) {
	p, _ := New()
	resp := p.ImportResourceState(ctx, providers.ImportResourceStateRequest{TypeName: "conn3x_command", Target: providers.ImportTarget{ID: "{}"}})
	if !resp.Diagnostics.HasErrors() {
		t.Fatal("importing a command should fail")
	}
}
