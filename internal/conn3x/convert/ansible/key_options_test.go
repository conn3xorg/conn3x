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

	"github.com/opentofu/opentofu/internal/conn3x/modules/sshkey"
)

const (
	keyA = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBhk/QT4Ep7z0XHAvbFIFXTP+OGH0uYMvE/4KP9GUO/e a@b"
	keyC = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICwrEDD/Mep4zgGnm337CVmTh0KgfOjCdNC9MU4V3lgw c@d"
)

// key_options replaces a key's options, as Ansible's does, and the line
// that comes out is one the step's own editor takes.
func TestConvertAuthorizedKeyOptions(t *testing.T) {
	for task, want := range map[string]string{
		`authorized_key: {user: deploy, key: "` + keyA + `", key_options: 'from="10.0.0.0/8",no-pty'}`:                    `from="10.0.0.0/8",no-pty ` + keyA,
		`authorized_key: {user: deploy, key: 'command="/usr/bin/backup" ` + keyA + `', key_options: 'from="10.0.0.0/8"'}`: `from="10.0.0.0/8" ` + keyA,
		`authorized_key: {user: deploy, key: "# the laptop\n\n` + keyA + `\n", key_options: no-pty}`:                      `no-pty ` + keyA,
	} {
		res := convertString(t, "- hosts: all\n  tasks:\n    - "+task+"\n")
		if res.Converted != 1 || len(res.Review) != 0 || !strings.Contains(string(res.HCL), hclString(want)) {
			t.Errorf("%s: converted %d, review %+v, want %s:\n%s", task, res.Converted, res.Review, want, res.HCL)
			continue
		}
		if _, err := sshkey.Edit("", want, false); err != nil {
			t.Errorf("%s: the step refuses %q: %v", task, want, err)
		}
	}
	for task, reason := range map[string]string{
		`authorized_key: {user: deploy, key: "ssh-ed25519 AAAA", key_options: no-pty, exclusive: true}`: "key_options with exclusive",
		`authorized_key: {user: deploy, key: "` + keyA + `\n` + keyC + `", key_options: no-pty}`:        "gives 2 keys without exclusive",
		`authorized_key: {user: deploy, key: "` + keyA + `\n` + keyC + `"}`:                             "gives 2 keys without exclusive",
		`authorized_key: {user: deploy, key: "not a key", key_options: no-pty}`:                         "isn't a public key",
	} {
		res := convertString(t, "- hosts: all\n  tasks:\n    - "+task+"\n")
		if res.Converted != 0 || len(res.Review) != 1 || !strings.Contains(res.Review[0].Reason, reason) {
			t.Errorf("%s: converted %d, review %+v, want %q", task, res.Converted, res.Review, reason)
		}
	}
	// Two keys with exclusive still convert as they did, without options.
	res := convertString(t, "- hosts: all\n  tasks:\n    - authorized_key: {user: deploy, key: \""+keyA+"\\n"+keyC+"\", exclusive: true}\n")
	if res.Converted != 1 || len(res.Review) != 0 {
		t.Errorf("two keys with exclusive: converted %d, review %+v", res.Converted, res.Review)
	}
}

// A key from a variable may hold any number of keys, so the options go in
// by an expression that puts them on each key line and drops blank and #
// lines, as Ansible does. Evaluated, it gives what Ansible writes.
func TestKeyWithOptionsExpression(t *testing.T) {
	line := keyOptionsExpr(`from="10.0.0.0/8"`, "\x00var.deploy_keys\x00").raw
	expr, diags := hclsyntax.ParseExpression([]byte(line), "key", hcl.InitialPos)
	if diags.HasErrors() {
		t.Fatalf("%s: %s", line, diags)
	}
	startswith := function.New(&function.Spec{
		Params: []function.Parameter{{Name: "s", Type: cty.String}, {Name: "p", Type: cty.String}},
		Type:   function.StaticReturnType(cty.Bool),
		Impl: func(args []cty.Value, _ cty.Type) (cty.Value, error) {
			return cty.BoolVal(strings.HasPrefix(args[0].AsString(), args[1].AsString())), nil
		},
	})
	ctx := &hcl.EvalContext{
		Variables: map[string]cty.Value{"var": cty.ObjectVal(map[string]cty.Value{"deploy_keys": cty.StringVal("# laptop\n" + keyA + "\n\n " + keyC + "\n")})},
		Functions: map[string]function.Function{"join": stdlib.JoinFunc, "split": stdlib.SplitFunc, "trimspace": stdlib.TrimSpaceFunc, "startswith": startswith},
	}
	got, diags := expr.Value(ctx)
	if want := `from="10.0.0.0/8" ` + keyA + "\n" + `from="10.0.0.0/8" ` + keyC; diags.HasErrors() || got.AsString() != want {
		t.Errorf("%s gave %q, %s; want %q", line, got.GoString(), diags, want)
	}
}
