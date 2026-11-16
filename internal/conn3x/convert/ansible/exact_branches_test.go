// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ansible

import (
	"regexp"
	"regexp/syntax"
	"strings"
	"testing"
)

// What can match nothing, and what repeats something that can.
func TestNullableAndLoopsOnEmpty(t *testing.T) {
	for p, want := range map[string][2]bool{
		"a":                    {false, false},
		".":                    {false, false},
		"(?s).":                {false, false},
		"[^\\x00-\\x{10FFFF}]": {false, false},
		"a?":                   {true, false},
		"(a?)?":                {true, true},
		"(a*)+":                {true, true},
		"(a|b?)":               {true, false},
		"a{2}":                 {false, false},
		"a{0,2}":               {true, false},
		"(a?){2}":              {true, true},
		"ab":                   {false, false},
		"^":                    {true, false},
	} {
		re, err := syntax.Parse(p, syntax.Perl)
		if err != nil {
			t.Fatal(err)
		}
		if got := [2]bool{nullable(re), loopsOnEmpty(re)}; got != want {
			t.Errorf("%s: nullable, loops = %v, want %v", p, got, want)
		}
	}
	for p, want := range map[string]string{
		"[^":     "Go can't compile",
		"x?":     "a pattern that can match nothing",
		"y(a?)+": "a repeat of something that can match nothing",
		"[^]a]b": "",
	} {
		if got := unprovableRegexp(p); !strings.Contains(got, want) || want == "" && got != "" {
			t.Errorf("%s: %q, want %q", p, got, want)
		}
	}
}

func TestGoTemplateGroups(t *testing.T) {
	re := regexp.MustCompile(`(?P<k>\w+)=(\w+)`)
	for py, want := range map[string]string{
		`\g<k>:\2 $x`: "${k}:${2} $$x",
		`\g<0>`:       "${0}",
	} {
		if got, why := goTemplate(py, re); why != "" || got != want {
			t.Errorf("%s: %q, %s; want %q", py, got, why, want)
		}
	}
	for py, want := range map[string]string{
		`\g<1x>`: `has a replace with the reference \g<1x>, which the converter can't read`,
		`\g<z>`:  "naming group z, which regexp doesn't have",
		`\3`:     "naming group 3, which regexp doesn't have",
	} {
		if _, why := goTemplate(py, re); !strings.Contains(why, want) {
			t.Errorf("%s: %q, want %q", py, why, want)
		}
	}
}
