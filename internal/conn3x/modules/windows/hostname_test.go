// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package windows

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestHostname(t *testing.T) {
	ctx := context.Background()
	for _, n := range []string{"WEB01", "web-01", "a", "SQL2022-NODE-02"} {
		if err := ValidateHostname(n); err != nil {
			t.Errorf("%s: %v", n, err)
		}
	}
	for n, want := range map[string]string{
		"web01.example.com": "has a dot",
		"ABCDEFGHIJKLMNOP":  "longer than 15",
		"-web":              "letters, digits and hyphens",
		"web-":              "letters, digits and hyphens",
		"web_01":            "letters, digits and hyphens",
		"":                  "letters, digits and hyphens",
		"12345":             "all digits",
	} {
		if err := ValidateHostname(n); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v, want %s", n, err, want)
		}
	}

	for name, c := range map[string]struct {
		answer         map[string]any
		inSync, reboot bool
	}{
		"both match":           {map[string]any{"running": "WEB01", "pending": "WEB01"}, true, false},
		"other case":           {map[string]any{"running": "web01", "pending": "web01"}, true, false},
		"pending matches":      {map[string]any{"running": "FV-AZ12", "pending": "WEB01"}, true, true},
		"running name differs": {map[string]any{"running": "FV-AZ12", "pending": "FV-AZ12"}, false, false},
		"renamed elsewhere":    {map[string]any{"running": "WEB01", "pending": "OTHER"}, false, true},
	} {
		st, err := ReadHostname(ctx, &fake{answers: []map[string]any{ok(c.answer)}})
		if err != nil || st.InSync("web01") != c.inSync || st.RebootRequired() != c.reboot {
			t.Errorf("%s: %+v in sync %v reboot %v, %v", name, st, st.InSync("web01"), st.RebootRequired(), err)
		}
	}
	if _, err := ReadHostname(ctx, &fake{answers: []map[string]any{ok(map[string]any{"running": "", "pending": "X"})}}); err == nil {
		t.Error("an empty name was taken")
	}
	if _, err := ReadHostname(ctx, &fake{answers: []map[string]any{ok(1)}}); err == nil || !strings.Contains(err.Error(), "reading the computer name") {
		t.Errorf("bad answer: %v", err)
	}
	if _, err := ReadHostname(ctx, &fake{err: errors.New("down")}); err == nil {
		t.Error("runner error ignored")
	}

	f := &fake{answers: []map[string]any{ok(map[string]any{"pending": "WEB01"})}}
	if err := ApplyHostname(ctx, f, HostnameState{Running: "X", Pending: "X"}, "web01"); err != nil || args(f, 0)["name"] != "web01" {
		t.Errorf("apply: %v, sent %v", err, f.sent)
	}
	f = &fake{}
	if err := ApplyHostname(ctx, f, HostnameState{DomainMember: true, Domain: "corp.example"}, "web01"); err == nil || !strings.Contains(err.Error(), "member of corp.example") || len(f.sent) != 0 {
		t.Errorf("a domain member: %v, sent %v", err, f.sent)
	}
	f = &fake{answers: []map[string]any{ok(map[string]any{"pending": "X"})}}
	if err := ApplyHostname(ctx, f, HostnameState{Running: "X", Pending: "X"}, "web01"); err == nil || !strings.Contains(err.Error(), `is "X" after renaming it`) {
		t.Errorf("a rename that didn't take: %v", err)
	}
}
