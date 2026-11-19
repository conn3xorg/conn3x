// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"strings"
	"testing"

	"github.com/zclconf/go-cty/cty"
)

func TestValidateUserPasswordHash(t *testing.T) {
	cfg := func(pw, hash cty.Value) cty.Value {
		vals := userSchema().Block.EmptyValue().AsValueMap()
		vals["name"], vals["password_wo"], vals["password_hash_wo"] = cty.StringVal("app"), pw, hash
		vals["ssh"] = cty.ObjectVal(map[string]cty.Value{"user": cty.StringVal("root"), "become": cty.NullVal(cty.Bool)})
		return cty.ObjectVal(vals)
	}
	none := cty.NullVal(cty.String)
	for want, c := range map[string]cty.Value{
		"":                         cfg(none, cty.StringVal("$6$salt$abcDEF./")),
		"not both":                 cfg(cty.StringVal("pw"), cty.StringVal("$6$salt$abc")),
		"isn't a crypt hash":       cfg(none, cty.StringVal("plain password")),
		"isn't a crypt hash ":      cfg(none, cty.StringVal("!$6$salt$abc")),
		"isn't a crypt hash  ":     cfg(none, cty.StringVal("$6$salt$abc\nroot:x")),
		"yescrypt is a hash, fine": cfg(none, cty.StringVal("$y$j9T$salt$hash")),
	} {
		err := validateUserPassword(c)
		switch {
		case strings.HasSuffix(want, "fine") || want == "":
			if err != nil {
				t.Errorf("%q: %v", want, err)
			}
		case err == nil || !strings.Contains(err.Error(), strings.TrimSpace(want)):
			t.Errorf("want %q, got %v", want, err)
		}
		if err != nil && strings.Contains(err.Error(), "plain password") {
			t.Errorf("the error echoes the value: %v", err)
		}
	}
}
