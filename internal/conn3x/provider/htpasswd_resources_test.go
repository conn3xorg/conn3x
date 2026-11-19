// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"strings"
	"testing"

	"github.com/zclconf/go-cty/cty"
)

func TestHtpasswdValidate(t *testing.T) {
	cfg := func(name string, pw cty.Value) cty.Value {
		vals := htpasswdKind.schema().Block.EmptyValue().AsValueMap()
		vals["path"], vals["name"], vals["password_wo"] = cty.StringVal("/etc/htpasswd"), cty.StringVal(name), pw
		vals["ssh"] = cty.NullVal(vals["ssh"].Type())
		return cty.ObjectVal(vals)
	}
	for want, c := range map[string]cty.Value{
		"password_wo is required": cfg("admin", cty.NullVal(cty.String)),
		"has a :":                 cfg("ad:min", cty.StringVal("pw")),
		"bcrypt reads only":       cfg("admin", cty.StringVal(strings.Repeat("x", 73))),
	} {
		if d := htpasswdKind.validate(c); !d.HasErrors() || !strings.Contains(d.Err().Error(), want) {
			t.Errorf("want %q, got %v", want, d.Err())
		}
	}
	if d := htpasswdKind.validate(cfg("admin", cty.StringVal("pw"))); d.HasErrors() {
		t.Error(d.Err())
	}
}

// The read only needs the user's line to be there; it can't see the password.
func TestHtpasswdReadEdit(t *testing.T) {
	v := cty.ObjectVal(map[string]cty.Value{"name": cty.StringVal("admin")})
	for content, inSync := range map[string]bool{"admin:$2y$10$x\n": true, "other:x\n": false, "": false} {
		got, _ := htpasswdKind.edit(v)(content)
		if (got == content) != inSync {
			t.Errorf("%q: in sync %v", content, got == content)
		}
	}
}
