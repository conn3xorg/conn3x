// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"testing"

	"github.com/zclconf/go-cty/cty"
)

// Password aging days are whole numbers from 0 to 99999, or -1 for no
// limit, as chage takes them (#1184).
func TestUserAgingValidates(t *testing.T) {
	for _, k := range agingAttrs {
		for days, ok := range map[float64]bool{0: true, 365: true, 99999: true, -1: true, -2: false, 1.5: false, 100000: false} {
			cfg := objFor(userSchema(), map[string]cty.Value{"name": cty.StringVal("bob"), k: cty.NumberFloatVal(days)})
			if diags := validateUserLock(cfg); diags.HasErrors() == ok {
				t.Errorf("%s = %v: errors %v, want ok %v", k, days, diags.Err(), ok)
			}
		}
	}
	a, set := userAging(objFor(userSchema(), map[string]cty.Value{"name": cty.StringVal("bob"), "password_max_days": cty.NumberIntVal(90)}))
	if !set || a.MinDays != nil || a.WarnDays != nil || a.MaxDays == nil || *a.MaxDays != 90 {
		t.Errorf("only password_max_days set: %+v, set %v", a, set)
	}
	if _, set := userAging(objFor(userSchema(), map[string]cty.Value{"name": cty.StringVal("bob")})); set {
		t.Error("a user step with no aging reads /etc/shadow for it")
	}
}
