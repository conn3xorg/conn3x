// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"strings"
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/function"
	"github.com/zclconf/go-cty/cty/function/stdlib"
)

// key_options go in front of every key the task gives, as Ansible puts
// them.
func TestConvertAuthorizedKeyOptions(t *testing.T) {
	for task, want := range map[string]string{
		`authorized_key: {user: deploy, key: "ssh-ed25519 AAAA a@b", key_options: 'from="10.0.0.0/8",no-pty'}`: `key = "from=\"10.0.0.0/8\",no-pty ssh-ed25519 AAAA a@b"`,
		`authorized_key: {user: deploy, key: "ssh-ed25519 AAAA a@b\nssh-rsa BBBB c@d\n", key_options: no-pty}`: `key = "no-pty ssh-ed25519 AAAA a@b\nno-pty ssh-rsa BBBB c@d\n"`,
	} {
		res := convertString(t, "- hosts: all\n  tasks:\n    - "+task+"\n")
		if hcl := strings.Join(strings.Fields(string(res.HCL)), " "); res.Converted != 1 || len(res.Review) != 0 || !strings.Contains(hcl, want) {
			t.Errorf("%s: converted %d, review %+v, want %s:\n%s", task, res.Converted, res.Review, want, res.HCL)
		}
	}
	res := convertString(t, "- hosts: all\n  tasks:\n    - authorized_key: {user: deploy, key: \"ssh-ed25519 AAAA\", key_options: no-pty, exclusive: true}\n")
	if res.Converted != 0 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, "key_options with exclusive") {
		t.Errorf("exclusive: converted %d, review %+v", res.Converted, res.Review)
	}
}

// A key from a variable may hold any number of keys, so the options go in
// by an expression that prefixes each line; evaluated, it gives what
// Ansible writes.
func TestKeyWithOptionsExpression(t *testing.T) {
	a := keyWithOptions(`from="10.0.0.0/8"`, "\x00var.keys\x00")
	expr, diags := hclsyntax.ParseExpression([]byte(a.raw), "key", hcl.InitialPos)
	if diags.HasErrors() {
		t.Fatalf("%s: %s", a.raw, diags)
	}
	ctx := &hcl.EvalContext{
		Variables: map[string]cty.Value{"var": cty.ObjectVal(map[string]cty.Value{"keys": cty.StringVal("ssh-ed25519 AAAA a@b\nssh-rsa BBBB c@d\n")})},
		Functions: map[string]function.Function{"join": stdlib.JoinFunc, "split": stdlib.SplitFunc, "trimspace": stdlib.TrimSpaceFunc},
	}
	got, diags := expr.Value(ctx)
	if want := "from=\"10.0.0.0/8\" ssh-ed25519 AAAA a@b\nfrom=\"10.0.0.0/8\" ssh-rsa BBBB c@d\n"; diags.HasErrors() || got.AsString() != want {
		t.Errorf("%s gave %q, %s; want %q", a.raw, got.GoString(), diags, want)
	}
}
