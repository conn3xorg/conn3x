// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"encoding/base64"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/providers"
)

// brData is a typeName data source config with attrs set, everything else
// null, and an ssh block with sshAttrs over a placeholder host.
func brData(typeName string, attrs, sshAttrs map[string]cty.Value) cty.Value {
	p, _ := New()
	vals := objFor(p.GetProviderSchema(ctx).DataSources[typeName], attrs).AsValueMap()
	conn := vals["ssh"].AsValueMap()
	for k, v := range sshAttrs {
		conn[k] = v
	}
	vals["ssh"] = cty.ObjectVal(conn)
	return cty.ObjectVal(vals)
}

func brReadData(typeName string, cfg cty.Value) providers.ReadDataSourceResponse {
	p, _ := New()
	return p.ReadDataSource(ctx, providers.ReadDataSourceRequest{TypeName: typeName, Config: cfg})
}

// brAway is ssh with a private key file that isn't there, so no login works.
func brAway(t *testing.T, ssh map[string]cty.Value) map[string]cty.Value {
	away := map[string]cty.Value{}
	for k, v := range ssh {
		away[k] = v
	}
	away["private_key_file"] = cty.StringVal(filepath.Join(t.TempDir(), "missing"))
	return away
}

func TestFileDataReadsTheFile(t *testing.T) {
	content := "token=abc\n"
	host := (&unitScripts{}).
		on("'/etc/token'", "present\n0640 root app\n"+base64.StdEncoding.EncodeToString([]byte(content))).
		on("'/etc/none'", "missing\n").
		on("'/etc/broken'", "!stat: I/O error")
	ssh := unitHost(t, host.answer)

	resp := brReadData("conn3x_file", brData("conn3x_file", map[string]cty.Value{"path": cty.StringVal("/etc/token")}, ssh))
	if resp.Diagnostics.HasErrors() {
		t.Fatal(resp.Diagnostics.Err())
	}
	s := resp.State
	if !s.GetAttr("exists").True() || s.GetAttr("content").AsString() != content || s.GetAttr("mode").AsString() != "0640" || s.GetAttr("group").AsString() != "app" || !strings.HasSuffix(s.GetAttr("id").AsString(), ":/etc/token") {
		t.Errorf("state %#v", s)
	}
	if size, _ := s.GetAttr("size").AsBigFloat().Int64(); size != int64(len(content)) || len(s.GetAttr("sha256").AsString()) != 64 {
		t.Errorf("size %v sha256 %v", s.GetAttr("size"), s.GetAttr("sha256"))
	}

	// A missing file is no error: exists is false and the rest null.
	resp = brReadData("conn3x_file", brData("conn3x_file", map[string]cty.Value{"path": cty.StringVal("/etc/none")}, ssh))
	if resp.Diagnostics.HasErrors() || resp.State.GetAttr("exists").True() || !resp.State.GetAttr("content").IsNull() || !resp.State.GetAttr("size").IsNull() {
		t.Errorf("missing: %#v, %v", resp.State, resp.Diagnostics.Err())
	}

	for name, c := range map[string]struct {
		attrs map[string]cty.Value
		ssh   map[string]cty.Value
		want  string
	}{
		"over max_size": {map[string]cty.Value{"path": cty.StringVal("/etc/token"), "max_size": cty.NumberIntVal(4)}, ssh, "over max_size (4)"},
		"a failed read": {map[string]cty.Value{"path": cty.StringVal("/etc/broken")}, ssh, "conn3x_file:"},
		"no login":      {map[string]cty.Value{"path": cty.StringVal("/etc/token")}, brAway(t, ssh), "missing"},
	} {
		resp := brReadData("conn3x_file", brData("conn3x_file", c.attrs, c.ssh))
		if !resp.Diagnostics.HasErrors() || !strings.Contains(resp.Diagnostics.Err().Error(), c.want) {
			t.Errorf("%s: %v", name, resp.Diagnostics.Err())
		}
	}
}

// A command's output and exit status are its result, a failing one
// included; only a host that can't be reached is an error.
func TestCommandDataRunsTheCommand(t *testing.T) {
	host := (&unitScripts{}).on("kubeadm token create", "join 10.0.0.1:6443\n").on("false", "!nope")
	ssh := unitHost(t, host.answer)
	resp := brReadData("conn3x_command", brData("conn3x_command", map[string]cty.Value{"command": cty.StringVal("kubeadm token create --print-join-command")}, ssh))
	if resp.Diagnostics.HasErrors() || resp.State.GetAttr("stdout").AsString() != "join 10.0.0.1:6443\n" {
		t.Fatalf("%#v, %v", resp.State, resp.Diagnostics.Err())
	}
	resp = brReadData("conn3x_command", brData("conn3x_command", map[string]cty.Value{"command": cty.StringVal("false")}, ssh))
	if code, _ := resp.State.GetAttr("exit_code").AsBigFloat().Int64(); resp.Diagnostics.HasErrors() || code != 1 {
		t.Errorf("a failing command: exit %v, %v", resp.State.GetAttr("exit_code"), resp.Diagnostics.Err())
	}
	resp = brReadData("conn3x_command", brData("conn3x_command", map[string]cty.Value{"command": cty.StringVal("true")}, brAway(t, ssh)))
	if !resp.Diagnostics.HasErrors() {
		t.Error("ran over a login with a missing key")
	}
}

func TestPackagesAndServicesData(t *testing.T) {
	host := (&unitScripts{}).
		on("cat /etc/os-release", "ID=rocky\nID_LIKE=\"rhel centos fedora\"\n").
		on("rpm -qa", "x86_64\nkernel\tx86_64\t0:5.14-1\nkernel\tx86_64\t0:5.14-2\n").
		on("list-unit-files", "sshd.service\nghost.service\n--\nId=sshd.service\nNames=sshd.service\nLoadState=loaded\nActiveState=active\nUnitFileState=enabled\n\nId=ghost.service\nNames=ghost.service\nLoadState=not-found\n")
	ssh := unitHost(t, host.answer)
	resp := brReadData("conn3x_packages", brData("conn3x_packages", nil, ssh))
	if resp.Diagnostics.HasErrors() {
		t.Fatal(resp.Diagnostics.Err())
	}
	if v := resp.State.GetAttr("packages").Index(cty.StringVal("kernel")); v.AsString() != "0:5.14-2" {
		t.Errorf("newest kernel %v", v)
	}
	if n := resp.State.GetAttr("versions").Index(cty.StringVal("kernel")).LengthInt(); n != 2 {
		t.Errorf("%d kernels", n)
	}
	resp = brReadData("conn3x_services", brData("conn3x_services", nil, ssh))
	if resp.Diagnostics.HasErrors() {
		t.Fatal(resp.Diagnostics.Err())
	}
	svcs := resp.State.GetAttr("services")
	if svcs.LengthInt() != 1 || !svcs.Index(cty.StringVal("sshd")).GetAttr("enabled").True() {
		t.Errorf("services %#v", svcs)
	}

	// A host with nothing installed has empty maps, not null ones.
	empty := unitHost(t, (&unitScripts{}).on("cat /etc/os-release", "ID=debian\n").on("dpkg", "amd64\n").on("list-unit-files", "\n--\n").answer)
	resp = brReadData("conn3x_packages", brData("conn3x_packages", nil, empty))
	if resp.Diagnostics.HasErrors() || resp.State.GetAttr("packages").IsNull() || resp.State.GetAttr("packages").LengthInt() != 0 {
		t.Errorf("no packages: %#v, %v", resp.State, resp.Diagnostics.Err())
	}
	resp = brReadData("conn3x_services", brData("conn3x_services", nil, empty))
	if resp.Diagnostics.HasErrors() || resp.State.GetAttr("services").LengthInt() != 0 {
		t.Errorf("no services: %#v, %v", resp.State, resp.Diagnostics.Err())
	}

	broken := unitHost(t, (&unitScripts{}).on("", "!the host broke").answer)
	for _, typeName := range []string{"conn3x_packages", "conn3x_services"} {
		for name, s := range map[string]map[string]cty.Value{"broken": broken, "no login": brAway(t, ssh)} {
			if resp := brReadData(typeName, brData(typeName, nil, s)); !resp.Diagnostics.HasErrors() {
				t.Errorf("%s on a %s host: no error", typeName, name)
			}
		}
	}
}
