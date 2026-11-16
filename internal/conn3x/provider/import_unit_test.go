// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"fmt"
	"strings"
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/providers"
)

// unitImportID is the import ID a circuit writes for a step on a unitHost.
func unitImportID(ssh map[string]cty.Value, args string) string {
	return fmt.Sprintf(`{"v":1,"key":"web1","ssh":{"host":%q,"port":%s,"user":"root","private_key_file":%q,"known_hosts_file":%q,"agent":false},"args":%s}`,
		ssh["host"].AsString(), ssh["port"].AsBigFloat().String(), ssh["private_key_file"].AsString(), ssh["known_hosts_file"].AsString(), args)
}

func unitImport(typeName, id string) providers.ImportResourceStateResponse {
	p, _ := New()
	return p.ImportResourceState(ctx, providers.ImportResourceStateRequest{TypeName: typeName, Target: providers.ImportTarget{ID: id}})
}

var unitStorageImports = map[string]string{
	"conn3x_filesystem":         `{"device":"/dev/data/www","type":"ext4","earlier_revisions":[null,null]}`,
	"conn3x_lvm_volume_group":   `{"name":"data","pvs":["/dev/vdb1"]}`,
	"conn3x_lvm_logical_volume": `{"vg":"data","name":"www","size":"512M"}`,
}

// A storage step imports what the disk already holds, and on a blank disk
// says there is nothing to adopt.
func TestImportStorageAsksTheDisk(t *testing.T) {
	full := unitHost(t, (&unitDisk{fs: "ext4", vg: true, lv: true}).answer)
	blank := unitHost(t, (&unitDisk{vg: true}).answer)
	for typeName, args := range unitStorageImports {
		resp := unitImport(typeName, unitImportID(full, args))
		if err := resp.Diagnostics.Err(); err != nil || len(resp.ImportedResources) != 1 {
			t.Errorf("%s: %v", typeName, err)
			continue
		}
		if typeName == "conn3x_filesystem" {
			// The circuit's nulls arrive untyped; state has them as strings.
			if r := resp.ImportedResources[0].State.GetAttr("earlier_revisions"); !r.Type().Equals(cty.Tuple([]cty.Type{cty.String, cty.String})) {
				t.Errorf("earlier_revisions = %#v", r)
			}
		}
		if typeName == "conn3x_lvm_volume_group" {
			continue // the blank disk has the group, to read the volume
		}
		if err := unitImport(typeName, unitImportID(blank, args)).Diagnostics.Err(); err == nil || !strings.Contains(err.Error(), "Nothing to import on web1") {
			t.Errorf("%s on a blank disk: %v", typeName, err)
		}
	}
}

// A probe the host fails is that error, not "nothing to import"; a probe
// that only finds nothing says what's missing.
func TestImportProbesOnAFailingHost(t *testing.T) {
	ssh := unitHost(t, (&unitDisk{gone: true}).answer)
	for typeName, args := range map[string]string{
		"conn3x_filesystem":       unitStorageImports["conn3x_filesystem"],
		"conn3x_firewalld":        `{"service":"http","zone":"public"}`,
		"conn3x_selinux_fcontext": `{"target":"/srv/www(/.*)?","setype":"httpd_sys_content_t"}`,
	} {
		err := unitImport(typeName, unitImportID(ssh, args)).Diagnostics.Err()
		if err == nil || strings.Contains(err.Error(), "Nothing to import") {
			t.Errorf("%s: %v", typeName, err)
		}
	}
	for typeName, c := range map[string]struct{ args, want string }{
		"conn3x_selinux_boolean": {`{"name":"httpd_can_network_connect","value":true}`, "SELinux boolean httpd_can_network_connect"},
		"conn3x_authorized_key":  {`{"user":"nobody-here","key":"ssh-ed25519 AAAA deploy"}`, "Nothing to import on web1"},
	} {
		if err := unitImport(typeName, unitImportID(ssh, c.args)).Diagnostics.Err(); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", typeName, err)
		}
	}
}

// A ufw rule that isn't there is described by all its fields.
func TestImportMissingUFWRuleNamesIt(t *testing.T) {
	ssh := unitHost(t, (&unitScripts{}).on("ufw", "Status: active\n").answer)
	err := unitImport("conn3x_ufw_rule", unitImportID(ssh, `{"action":"allow","port":"22/tcp","from":"10.0.0.0/8"}`)).Diagnostics.Err()
	if err == nil || !strings.Contains(err.Error(), "the ufw rule allow 22/tcp from 10.0.0.0/8") {
		t.Errorf("err = %v", err)
	}
}

func TestReadExisting(t *testing.T) {
	if _, err := ReadExisting(ctx, "conn3x_nope", "{}"); err == nil {
		t.Error("an unknown type read")
	}
	if _, err := ReadExisting(ctx, "conn3x_file", "not json"); err == nil || !strings.Contains(err.Error(), "doesn't read") {
		t.Errorf("a bad id: %v", err)
	}
	full := unitHost(t, (&unitDisk{vg: true}).answer)
	state, err := ReadExisting(ctx, "conn3x_lvm_volume_group", unitImportID(full, unitStorageImports["conn3x_lvm_volume_group"]))
	if err != nil || state.GetAttr("name").AsString() != "data" {
		t.Errorf("state %#v, %v", state, err)
	}
	blank := unitHost(t, (&unitDisk{}).answer)
	if _, err := ReadExisting(ctx, "conn3x_lvm_volume_group", unitImportID(blank, unitStorageImports["conn3x_lvm_volume_group"])); err == nil || !strings.Contains(err.Error(), "web1 doesn't have") {
		t.Errorf("a missing group: %v", err)
	}
}

func TestImportPriorDefaults(t *testing.T) {
	_, v, err := importPrior("conn3x_mysql_user", `{"v":1,"key":"db1","ssh":`+testSSH+`,"args":{"name":"app"}}`)
	if err != nil || v.GetAttr("host").AsString() != "localhost" {
		t.Errorf("mysql_user host: %#v, %v", v, err)
	}
	if _, _, err := importPrior("conn3x_windows_file", `{"v":1,"key":"w1","ssh":`+testSSH+`,"args":{"path":"C:\\x"},"write_only":true}`); err == nil || !strings.Contains(err.Error(), "can't import yet") {
		t.Errorf("windows_file write_only: %v", err)
	}
	if _, _, err := importPrior("conn3x_file", `{"v":1,"key":"web1","ssh":{"user":"root"},"args":{"path":"/x"}}`); err == nil || !strings.Contains(err.Error(), "no ssh host") {
		t.Errorf("no host: %v", err)
	}
	if _, _, err := importPrior("conn3x_filesystem", `{"v":1,"key":"web1","ssh":`+testSSH+`,"args":{"device":"/dev/vdb","type":"ext4","earlier_revisions":[1,}}`); err == nil {
		t.Error("broken earlier_revisions read")
	}
}

func TestAllNull(t *testing.T) {
	for _, c := range []struct {
		v    cty.Value
		want bool
	}{
		{cty.NullVal(cty.String), true},
		{cty.TupleVal([]cty.Value{cty.NullVal(cty.String)}), true},
		{cty.TupleVal([]cty.Value{cty.NullVal(cty.String), cty.True}), false},
		{cty.UnknownVal(cty.List(cty.String)), false},
		{cty.StringVal("x"), false},
	} {
		if got := allNull(c.v); got != c.want {
			t.Errorf("allNull(%#v) = %t", c.v, got)
		}
	}
}
