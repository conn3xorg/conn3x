// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"strings"
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/conn3x/modules/pam"
)

func TestPAMRuleValidate(t *testing.T) {
	base := func(extra map[string]cty.Value) map[string]cty.Value {
		m := map[string]cty.Value{"service": cty.StringVal("sshd"), "type": cty.StringVal("auth"), "control": cty.StringVal("required"), "module": cty.StringVal("pam_faillock.so")}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	for name, attrs := range map[string]map[string]cty.Value{
		"service with /":      base(map[string]cty.Value{"service": cty.StringVal("../shadow")}),
		"service ..":          base(map[string]cty.Value{"service": cty.StringVal("..")}),
		"relative path":       base(map[string]cty.Value{"path": cty.StringVal("pam.d")}),
		"control":             base(map[string]cty.Value{"control": cty.StringVal("requried")}),
		"args_absent, delete": base(map[string]cty.Value{"state": cty.StringVal("args_absent"), "arguments": cty.ListVal([]cty.Value{cty.StringVal("nullok")}), "on_remove": cty.StringVal("delete")}),
		"absent, delete":      base(map[string]cty.Value{"state": cty.StringVal("absent"), "on_remove": cty.StringVal("delete")}),
		"absent, arguments":   base(map[string]cty.Value{"state": cty.StringVal("absent"), "arguments": cty.ListValEmpty(cty.String)}),
		"before and after":    base(map[string]cty.Value{"before": cty.StringVal("auth sufficient pam_unix.so"), "after": cty.StringVal("auth required pam_env.so")}),
	} {
		if diags := pamRuleKind.validate(objFor(pamRuleKind.schema(), attrs)); !diags.HasErrors() {
			t.Errorf("%s: no error", name)
		}
	}
	ok := base(map[string]cty.Value{"path": cty.StringVal("/etc/pam.d"), "before": cty.StringVal("auth [success=1 default=ignore] pam_unix.so"), "arguments": cty.ListVal([]cty.Value{cty.StringVal("preauth")}), "on_remove": cty.StringVal("delete")})
	if diags := pamRuleKind.validate(objFor(pamRuleKind.schema(), ok)); diags.HasErrors() {
		t.Error(diags.Err())
	}
	v := objFor(pamRuleKind.schema(), ok)
	if got := pamRuleKind.path(v); got != "/etc/pam.d/sshd" {
		t.Errorf("path %q", got)
	}
	// Unset arguments leave the rule's own; an empty list sets none.
	if r := pamRuleFrom(objFor(pamRuleKind.schema(), base(nil))); r.Arguments != nil {
		t.Errorf("unset arguments: %#v", r.Arguments)
	}
	if r := pamRuleFrom(objFor(pamRuleKind.schema(), base(map[string]cty.Value{"arguments": cty.ListValEmpty(cty.String)}))); r.Arguments == nil {
		t.Error("an empty list read as unset")
	}
}

// Removing a step with on_remove = "delete" takes out the rule it added,
// or the arguments it added.
func TestPAMRuleRemove(t *testing.T) {
	in := "auth required pam_faillock.so preauth\nauth sufficient pam_unix.so nullok remember=5\n"
	attrs := map[string]cty.Value{"service": cty.StringVal("sshd"), "type": cty.StringVal("auth"), "control": cty.StringVal("required"), "module": cty.StringVal("pam_faillock.so")}
	if got, err := pamRuleKind.remove(objFor(pamRuleKind.schema(), attrs))(in); err != nil || got != "auth sufficient pam_unix.so nullok remember=5\n" {
		t.Errorf("present: %v %q", err, got)
	}
	attrs["module"], attrs["control"] = cty.StringVal("pam_unix.so"), cty.StringVal("sufficient")
	attrs["state"], attrs["arguments"] = cty.StringVal(string(pam.ArgsPresent)), cty.ListVal([]cty.Value{cty.StringVal("remember=5")})
	if got, err := pamRuleKind.remove(objFor(pamRuleKind.schema(), attrs))(in); err != nil || got != "auth required pam_faillock.so preauth\nauth sufficient pam_unix.so nullok\n" {
		t.Errorf("args_present: %v %q", err, got)
	}
}

// A file authselect manages is refused at refresh, before it's read.
func TestPAMRuleRefusesAuthselect(t *testing.T) {
	for file, code := range map[string]int{"system-auth": 4, "sshd": 3} {
		host := unitHost(t, func(script string) (string, int) {
			if strings.Contains(script, "/etc/authselect/authselect.conf") {
				return "", code
			}
			return "", 0
		})
		state := eosStep("conn3x_pam_rule", map[string]cty.Value{
			"id": cty.StringVal("x"), "service": cty.StringVal(file), "type": cty.StringVal("auth"), "control": cty.StringVal("required"),
			"module": cty.StringVal("pam_faillock.so"), "before": cty.StringVal("auth sufficient pam_unix.so"), "on_remove": cty.StringVal("forget"), "in_sync": cty.True,
		}, host)
		if _, err := unitRead("conn3x_pam_rule", state); err == nil || !strings.Contains(err.Error(), "managed by authselect") {
			t.Errorf("%s: %v", file, err)
		}
	}
	// With authselect there but the file its own, the check passes.
	if err := authselectRefusal("/etc/pam.d/sshd", 4, ""); err != nil {
		t.Error(err)
	}
}
