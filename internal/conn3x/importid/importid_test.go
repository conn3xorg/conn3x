// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package importid

import (
	"strings"
	"testing"

	"github.com/zclconf/go-cty/cty"
)

var testSSH = cty.ObjectVal(map[string]cty.Value{"host": cty.StringVal("203.0.113.10"), "port": cty.NumberIntVal(2222), "user": cty.StringVal("root"), "become": cty.NullVal(cty.Bool)})

func TestBuild(t *testing.T) {
	for name, tc := range map[string]struct {
		args cty.Value
		want string
	}{
		"plain": {cty.ObjectVal(map[string]cty.Value{"path": cty.StringVal("/etc/motd"), "content": cty.StringVal("hi"), "mode": cty.NullVal(cty.String)}),
			`{"args":{"path":"/etc/motd"},"key":"web1","ssh":{"host":"203.0.113.10","port":2222,"user":"root"},"v":1}`},
		"write-only": {cty.ObjectVal(map[string]cty.Value{"path": cty.StringVal("/etc/token"), "content_wo": cty.StringVal("s3cret"), "validate": cty.StringVal("true %s")}),
			`{"args":{"path":"/etc/token"},"key":"web1","ssh":{"host":"203.0.113.10","port":2222,"user":"root"},"v":1,"write_only":true}`},
		"windows password": {cty.ObjectVal(map[string]cty.Value{"name": cty.StringVal("svc"), "password_wo": cty.StringVal("s3cret")}),
			`{"args":{"name":"svc"},"key":"web1","ssh":{"host":"203.0.113.10","port":2222,"user":"root"},"v":1}`},
		"registry data": {cty.ObjectVal(map[string]cty.Value{"key": cty.StringVal(`HKLM\SOFTWARE\App`), "name": cty.StringVal("Token"), "type": cty.StringVal("string"), "data_wo": cty.StringVal("s3cret")}),
			`{"args":{"key":"HKLM\\SOFTWARE\\App","name":"Token","type":"string"},"key":"web1","ssh":{"host":"203.0.113.10","port":2222,"user":"root"},"v":1}`},
		"map": {cty.MapVal(map[string]cty.Value{"name": cty.StringVal("nginx")}),
			`{"args":{"name":"nginx"},"key":"web1","ssh":{"host":"203.0.113.10","port":2222,"user":"root"},"v":1}`},
	} {
		got, err := Build("web1", testSSH, tc.args)
		if err != nil || got != tc.want {
			t.Errorf("%s: got %s, %v\nwant %s", name, got, err, tc.want)
		}
		if strings.Contains(got, "s3cret") {
			t.Errorf("%s: the write-only content is in the ID", name)
		}
	}
}

func TestBuildRejects(t *testing.T) {
	path := cty.ObjectVal(map[string]cty.Value{"path": cty.StringVal("/x")})
	for name, tc := range map[string]struct {
		ssh, args cty.Value
		want      string
	}{
		"ssh not an object":  {cty.StringVal("203.0.113.10"), path, "ssh must be an object"},
		"no host":            {cty.ObjectVal(map[string]cty.Value{"user": cty.StringVal("root")}), path, "ssh needs a host"},
		"args not an object": {testSSH, cty.StringVal("/x"), "args must be an object"},
		"null args":          {testSSH, cty.NullVal(cty.DynamicPseudoType), "args must be an object"},
	} {
		if _, err := Build("web1", tc.ssh, tc.args); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", name, err, tc.want)
		}
	}
}
