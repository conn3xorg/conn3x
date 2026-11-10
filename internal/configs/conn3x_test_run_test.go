// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package configs

import (
	"strings"
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
)

func TestDecodeIdempotent(t *testing.T) {
	for src, want := range map[string]string{
		"run \"a\" {\nidempotent = true\n}":                                                 "",
		"run \"a\" {\nidempotent = false\n}":                                                "",
		"run \"a\" {\ncommand = plan\nidempotent = true\n}":                                 "needs command = apply",
		"run \"a\" {\nidempotent = true\nplan_options {\nreplace = [test_resource.a]\n}\n}": "plans a change every time",
		"run \"a\" {\nidempotent = \"yes please\"\n}":                                       "Unsuitable value type",
	} {
		f, diags := hclsyntax.ParseConfig([]byte(src), "main.tftest.hcl", hcl.InitialPos)
		if diags.HasErrors() {
			t.Fatalf("%s: %s", src, diags)
		}
		file, diags := loadTestFile(f.Body)
		switch {
		case want == "" && diags.HasErrors():
			t.Errorf("%s: %s", src, diags)
		case want == "" && file.Runs[0].Idempotent != strings.Contains(src, "true"):
			t.Errorf("%s: Idempotent = %v", src, file.Runs[0].Idempotent)
		case want != "" && !strings.Contains(diags.Error(), want):
			t.Errorf("%s: want %q, got %v", src, want, diags)
		}
	}
}
