// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package windows

import (
	"context"
	"strings"
	"testing"
	"time"
)

const goodSum = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestPackageValidate(t *testing.T) {
	code := "{23170f69-40c1-2702-2409-000001000000}"
	for name, p := range map[string]Package{
		"url":    {ProductCode: code, URL: "https://example.com/a.msi", SHA256: goodSum},
		"source": {ProductCode: code, Source: `C:\pkgs\a b.msi`, SHA256: strings.ToUpper(goodSum)},
		"absent": {ProductCode: code, Absent: true},
		"http":   {ProductCode: code, URL: "http://example.com/a.msi", SHA256: goodSum, AllowHTTP: true},
	} {
		if err := p.Validate(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, p := range map[string]Package{
		"no braces":   {ProductCode: "23170F69-40C1-2702-2409-000001000000", URL: "https://e/a.msi", SHA256: goodSum},
		"both":        {ProductCode: code, URL: "https://e/a.msi", Source: `C:\a.msi`, SHA256: goodSum},
		"neither":     {ProductCode: code, SHA256: goodSum},
		"no sha":      {ProductCode: code, URL: "https://e/a.msi"},
		"short sha":   {ProductCode: code, URL: "https://e/a.msi", SHA256: "abc"},
		"file url":    {ProductCode: code, URL: `file:///C:/a.msi`, SHA256: goodSum},
		"spaced url":  {ProductCode: code, URL: "https://e/a b.msi", SHA256: goodSum},
		"unc source":  {ProductCode: code, Source: `\\srv\share\a.msi`, SHA256: goodSum},
		"rel source":  {ProductCode: code, Source: `a.msi`, SHA256: goodSum},
		"lower prop":  {ProductCode: code, URL: "https://e/a.msi", SHA256: goodSum, Properties: map[string]string{"installdir": "x"}},
		"prop equals": {ProductCode: code, URL: "https://e/a.msi", SHA256: goodSum, Properties: map[string]string{"A=B": "x"}},
		"newline":     {ProductCode: code, URL: "https://e/a.msi", SHA256: goodSum, Properties: map[string]string{"A": "x\ny"}},
		"http":        {ProductCode: code, URL: "http://e/a.msi", SHA256: goodSum},
		"transform":   {ProductCode: code, URL: "https://e/a.msi", SHA256: goodSum, Properties: map[string]string{"TRANSFORMS": `C:\t.mst`}},
		"force boot":  {ProductCode: code, URL: "https://e/a.msi", SHA256: goodSum, Properties: map[string]string{"REBOOT": "Force"}},
		"source dir":  {ProductCode: code, URL: "https://e/a.msi", SHA256: goodSum, Properties: map[string]string{"SOURCEDIR": `C:\Users\Public`}},
		"source list": {ProductCode: code, URL: "https://e/a.msi", SHA256: goodSum, Properties: map[string]string{"SOURCELIST": `C:\Users\Public`}},
		"negative":    {ProductCode: code, URL: "https://e/a.msi", SHA256: goodSum, MaxSizeMB: -1},
	} {
		if p.Validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// msiexec reads its own command line: a value is one quoted string, with a
// quote inside doubled, whatever else it holds.
func TestMsiProperties(t *testing.T) {
	for in, want := range map[string]string{
		`plain`:                `A="plain"`,
		`two words`:            `A="two words"`,
		`say "hi"`:             `A="say ""hi"""`,
		`C:\Program Files\X\`:  `A="C:\Program Files\X\"`,
		`$(New-Item C:\m) %P%`: `A="$(New-Item C:\m) %P%"`,
		`" B="injected`:        `A=""" B=""injected"`,
		``:                     `A=""`,
	} {
		got, err := msiProperties(map[string]string{"A": in})
		if err != nil || got != want {
			t.Errorf("%q: %q, %v", in, got, err)
		}
	}
	got, _ := msiProperties(map[string]string{"B": "2", "A": "1"})
	if got != `A="1" B="2"` {
		t.Errorf("order: %q", got)
	}
}

func TestApplyPackageSends(t *testing.T) {
	f := &fake{answers: []map[string]any{{"ok": true, "value": map[string]any{"restart": true}}}}
	p := Package{ProductCode: "{23170f69-40c1-2702-2409-000001000000}", URL: "https://example.com/a.msi", SHA256: strings.ToUpper(goodSum), Properties: map[string]string{"X": "1"}}
	restart, err := ApplyPackage(context.Background(), f, p, time.Minute)
	if err != nil || !restart {
		t.Fatalf("%v, %v", restart, err)
	}
	a := f.sent[0]["args"].(map[string]any)
	if a["product_code"] != "{23170F69-40C1-2702-2409-000001000000}" || a["sha256"] != goodSum || a["properties"] != `ALLUSERS="1" X="1"` || a["max_bytes"] != float64(2048<<20) || a["present"] != true {
		t.Errorf("sent %v", a)
	}
	if _, err := ApplyPackage(context.Background(), &fake{}, Package{ProductCode: "x"}, time.Minute); err == nil {
		t.Error("sent an invalid package")
	}
}

// ALLUSERS defaults to per machine, and a value given wins.
func TestApplyPackageAllUsers(t *testing.T) {
	f := &fake{answers: []map[string]any{{"ok": true, "value": map[string]any{"restart": false}}}}
	p := Package{ProductCode: "{23170F69-40C1-2702-2409-000001000000}", URL: "https://e/a.msi", SHA256: goodSum, Properties: map[string]string{"ALLUSERS": "2"}, MaxSizeMB: 10}
	if _, err := ApplyPackage(context.Background(), f, p, time.Minute); err != nil {
		t.Fatal(err)
	}
	if a := f.sent[0]["args"].(map[string]any); a["properties"] != `ALLUSERS="2"` || a["max_bytes"] != float64(10<<20) {
		t.Errorf("sent %v", a)
	}
}
