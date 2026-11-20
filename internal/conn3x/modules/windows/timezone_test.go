// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package windows

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestTimeZone(t *testing.T) {
	ctx := context.Background()
	for _, bad := range []string{"", "  ", "a\nb", strings.Repeat("x", 129)} {
		if ValidateTimeZone(bad) == nil {
			t.Errorf("%q: no error", bad)
		}
	}
	if err := ValidateTimeZone("W. Europe Standard Time"); err != nil {
		t.Error(err)
	}
	ids := []string{"UTC", "Mountain Standard Time", "US Mountain Standard Time", "Mountain Standard Time (Mexico)", "Pacific Standard Time", "W. Europe Standard Time"}
	for name, c := range map[string]struct {
		zone   string
		answer map[string]any
		inSync bool
		err    string
	}{
		"same":                {"UTC", map[string]any{"current": "UTC", "known": true}, true, ""},
		"same, other case":    {"utc", map[string]any{"current": "UTC", "known": true}, true, ""},
		"other zone":          {"Pacific Standard Time", map[string]any{"current": "UTC", "known": true}, false, ""},
		"unknown, suggestion": {"Mountian Standard Time", map[string]any{"current": "UTC", "known": false, "ids": ids}, false, `Windows has no time zone "Mountian Standard Time"; the closest it has are "Mountain Standard Time", "Mountain Standard Time (Mexico)", "US Mountain Standard Time"`},
	} {
		f := &fake{answers: []map[string]any{ok(c.answer)}}
		inSync, err := ReadTimeZone(ctx, f, c.zone)
		if c.err != "" {
			if err == nil || err.Error() != c.err {
				t.Errorf("%s: %v, want %s", name, err, c.err)
			}
			continue
		}
		if err != nil || inSync != c.inSync || args(f, 0)["name"] != c.zone {
			t.Errorf("%s: in sync %v, %v, sent %v", name, inSync, err, f.sent)
		}
	}
	if _, err := ReadTimeZone(ctx, &fake{answers: []map[string]any{ok(1)}}, "UTC"); err == nil || !strings.Contains(err.Error(), "reading the time zone") {
		t.Errorf("a bad answer: %v", err)
	}
	if _, err := ReadTimeZone(ctx, &fake{err: errors.New("down")}, "UTC"); err == nil {
		t.Error("runner error ignored")
	}

	f := &fake{answers: []map[string]any{ok(map[string]any{"current": "Pacific Standard Time"})}}
	if err := ApplyTimeZone(ctx, f, "pacific standard time"); err != nil || args(f, 0)["name"] != "pacific standard time" {
		t.Errorf("apply: %v, sent %v", err, f.sent)
	}
	f = &fake{answers: []map[string]any{ok(map[string]any{"current": "UTC"})}}
	if err := ApplyTimeZone(ctx, f, "Pacific Standard Time"); err == nil || !strings.Contains(err.Error(), `is "UTC" after setting it`) {
		t.Errorf("apply that didn't take: %v", err)
	}
}

func TestEditDistance(t *testing.T) {
	for _, c := range []struct {
		a, b string
		d    int
	}{{"", "", 0}, {"abc", "", 3}, {"kitten", "sitting", 3}, {"mountian", "mountain", 2}, {"é", "e", 1}} {
		if got := editDistance(c.a, c.b); got != c.d {
			t.Errorf("%q %q: %d, want %d", c.a, c.b, got, c.d)
		}
	}
}
