// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
)

func TestGenerateStepName(t *testing.T) {
	for want, tc := range map[string]struct {
		module string
		given  map[string]cty.Value
	}{
		"etc_motd":   {"file", map[string]cty.Value{"path": cty.StringVal("/etc/motd")}},
		"nginx":      {"service", map[string]cty.Value{"name": cty.StringVal("nginx")}},
		"sysctl_2fa": {"sysctl", map[string]cty.Value{"name": cty.StringVal("2fa")}},
		"timezone":   {"timezone", map[string]cty.Value{"name": cty.StringVal("Europe/Dublin")}},
		"srv_www":    {"selinux_fcontext", map[string]cty.Value{"target": cty.StringVal("/srv/www(/.*)?")}},
		"ufw_22_tcp": {"ufw", map[string]cty.Value{"port": cty.StringVal("22/tcp")}},
		"firewalld":  {"firewalld", map[string]cty.Value{}},
		"deploy":     {"authorized_key", map[string]cty.Value{"user": cty.StringVal("deploy"), "key": cty.StringVal("ssh-ed25519 AAAA")}},
	} {
		if got := stepName(tc.module, tc.given); got != want {
			t.Errorf("stepName(%s, %v) = %s, want %s", tc.module, tc.given, got, want)
		}
	}
}

func TestGenerateArgValue(t *testing.T) {
	for _, tc := range []struct {
		text string
		ty   cty.Type
		want cty.Value
	}{
		{"1000", cty.Number, cty.NumberIntVal(1000)},
		{"true", cty.Bool, cty.True},
		{`["ops"]`, cty.List(cty.String), cty.TupleVal([]cty.Value{cty.StringVal("ops")})},
		{"nginx", cty.String, cty.StringVal("nginx")},
		{"/etc/x", cty.String, cty.StringVal("/etc/x")},
		{"a b", cty.String, cty.StringVal("a b")},
		{`"quoted"`, cty.String, cty.StringVal("quoted")},
		// A string argument keeps the text: HCL would read these as numbers.
		{"1.10", cty.String, cty.StringVal("1.10")},
		{"0640", cty.String, cty.StringVal("0640")},
		{"true", cty.String, cty.StringVal("true")},
	} {
		if got := argValue(tc.text, tc.ty); !got.RawEquals(tc.want) {
			t.Errorf("argValue(%q, %s) = %#v, want %#v", tc.text, tc.ty.FriendlyName(), got, tc.want)
		}
	}
}

func TestGenerateContent(t *testing.T) {
	render := func(content cty.Value, writeOnly bool) string {
		f := hclwrite.NewEmptyFile()
		renderContent(f.Body(), content, writeOnly)
		return string(f.Bytes())
	}
	for name, tc := range map[string]struct {
		content   cty.Value
		writeOnly bool
		want      []string
		not       string
	}{
		"text":         {cty.StringVal("a ${b} %{c}\n"), false, []string{"<<EOT\n", "a $${b} %%{c}\n", "EOT"}, ""},
		"no newline":   {cty.StringVal("x"), false, []string{`content = "x"`}, "<<EOT"},
		"EOT inside":   {cty.StringVal("a\nEOT\nb\n"), false, []string{`content = "a\nEOT\nb\n"`}, "<<EOT"},
		"indented EOT": {cty.StringVal("a\n  EOT\nb\n"), false, []string{`content = "a\n  EOT\nb\n"`}, "<<EOT"},
		"binary":       {cty.StringVal("\xff\xfe"), false, []string{"isn't UTF-8", `content_wo = "REPLACE ME"`}, "content ="},
		"large":        {cty.StringVal(strings.Repeat("x", maxContent+1)), false, []string{"over 64 KiB", `content_wo = "REPLACE ME"`}, "xxx"},
		"write-only":   {cty.NullVal(cty.String), true, []string{"stayed on the host", `content_wo = "REPLACE ME"`}, ""},
		"no content":   {cty.NullVal(cty.String), false, nil, "content"},
	} {
		got := render(tc.content, tc.writeOnly)
		for _, w := range tc.want {
			if !strings.Contains(got, w) {
				t.Errorf("%s: missing %q in\n%s", name, w, got)
			}
		}
		if tc.not != "" && strings.Contains(got, tc.not) {
			t.Errorf("%s: %q shouldn't be in\n%s", name, tc.not, got)
		}
	}
}

func TestGenerateRefusesBeforeReadingTheHost(t *testing.T) {
	for want, o := range map[string]generateOptions{
		"-host is required":            {module: "file", args: []string{"path=/x"}},
		`"command" can't be generated`: {host: "h", module: "command"},
		"-write-only is for file":      {host: "h", module: "package", writeOnly: true, args: []string{"name=x"}},
		`file has no argument "nope"`:  {host: "h", module: "file", args: []string{"nope=1"}},
		"content isn't read":           {host: "h", module: "file", args: []string{"content=x"}},
		`"path" isn't NAME=VALUE`:      {host: "h", module: "file", args: []string{"path"}},
		"doesn't read Windows hosts":   {host: "h", module: "windows_service", args: []string{"name=Spooler"}},
	} {
		var out, errOut bytes.Buffer
		if code := runGenerateStep(context.Background(), o, &out, &errOut); code != 1 || !strings.Contains(errOut.String(), want) {
			t.Errorf("%+v: exit %d, %q, want %q", o, code, errOut.String(), want)
		}
	}
}
