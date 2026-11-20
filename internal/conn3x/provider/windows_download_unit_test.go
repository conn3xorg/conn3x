// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"strings"
	"testing"

	"github.com/zclconf/go-cty/cty"
)

func TestWinDownloadValidate(t *testing.T) {
	r := resourceTypes["conn3x_windows_download"]
	const sum = "ec6af1ea0367d16dde6639a89a080a524cebc4d4bedfe00ed0cac4b865a918d8"
	base := func(extra map[string]cty.Value) cty.Value {
		attrs := map[string]cty.Value{"url": cty.StringVal("https://example.com/a.zip"), "dest": cty.StringVal(`C:\Tools\a.zip`), "sha256": cty.StringVal(sum)}
		for k, v := range extra {
			attrs[k] = v
		}
		return objFor(r.schema(), attrs)
	}
	if diags := r.validate(base(nil)); diags.HasErrors() {
		t.Fatal(diags.Err())
	}
	if diags := r.validate(base(map[string]cty.Value{"url": cty.StringVal("http://mirror/a.zip"), "allow_http": cty.True, "max_size_mb": cty.NumberIntVal(10), "timeout": cty.StringVal("5m")})); diags.HasErrors() {
		t.Errorf("http with allow_http: %v", diags.Err())
	}
	for want, extra := range map[string]map[string]cty.Value{
		"https address": {"url": cty.StringVal("http://mirror/a.zip")},
		"dest":          {"dest": cty.StringVal("a.zip")},
		"64 hex":        {"sha256": cty.StringVal("abc")},
		"max_size_mb":   {"max_size_mb": cty.NumberIntVal(-1)},
		"timeout":       {"timeout": cty.StringVal("soon")},
		"on_remove":     {"on_remove": cty.StringVal("burn")},
	} {
		diags := r.validate(base(extra))
		if !diags.HasErrors() || !strings.Contains(diags.Err().Error(), want) {
			t.Errorf("%s: %v", want, diags.Err())
		}
	}
}
