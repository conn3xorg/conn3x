// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"strings"
	"testing"
	"time"

	"github.com/zclconf/go-cty/cty"
)

func TestParseConfirmAfter(t *testing.T) {
	for in, want := range map[string]time.Duration{"": 0, "60s": time.Minute, "10s": 10 * time.Second, "1h": time.Hour} {
		v := cty.NullVal(cty.String)
		if in != "" {
			v = cty.StringVal(in)
		}
		if got, err := parseConfirmAfter(v); err != nil || got != want {
			t.Errorf("parseConfirmAfter(%q) = %v, %v", in, got, err)
		}
	}
	for _, bad := range []string{"5s", "2h", "soon"} {
		if _, err := parseConfirmAfter(cty.StringVal(bad)); err == nil {
			t.Errorf("parseConfirmAfter(%q) passed", bad)
		}
	}
}

func TestValidateFileConfirmAfter(t *testing.T) {
	f := newFileTest(t)
	for want, attrs := range map[string]map[string]cty.Value{
		"between 10s and 1h0m0s":  {"content": cty.StringVal("x"), "confirm_after": cty.StringVal("1s")},
		"reload goes with":        {"content": cty.StringVal("x"), "reload": cty.StringVal("systemctl reload sshd")},
		"can't be set with state": {"state": cty.StringVal("absent"), "confirm_after": cty.StringVal("60s")},
	} {
		diags := validateFile(f.config(attrs))
		if !diags.HasErrors() || !strings.Contains(diags.Err().Error(), strings.TrimSpace(want)) {
			t.Errorf("%s: %v", want, diags.Err())
		}
	}
	ok := validateFile(f.config(map[string]cty.Value{"content": cty.StringVal("x"), "confirm_after": cty.StringVal("60s"), "reload": cty.StringVal("systemctl reload sshd")}))
	if ok.HasErrors() {
		t.Errorf("a valid confirm_after: %v", ok.Err())
	}
}
