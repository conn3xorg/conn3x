// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package account

import (
	"strings"
	"testing"
)

func TestReadShadow(t *testing.T) {
	for out, want := range map[string]Shadow{
		"$6$s$h::::\n":        {Hash: "$6$s$h", MinDays: -1, MaxDays: -1, WarnDays: -1},
		"!$6$s$h:::::20818\n": {},
		"!$6$s$h::::20818\n":  {Hash: "!$6$s$h", Expires: "2026-12-31", MinDays: -1, MaxDays: -1, WarnDays: -1},
		"!:0:99999:7:0\n":     {Hash: "!", Expires: "1970-01-01", MinDays: 0, MaxDays: 99999, WarnDays: 7},
		"*:1:90:14:-1\n":      {Hash: "*", MinDays: 1, MaxDays: 90, WarnDays: 14},
		"$6$s$h:-1:-1:-1:\n":  {Hash: "$6$s$h", MinDays: -1, MaxDays: -1, WarnDays: -1},
	} {
		if want == (Shadow{}) {
			// Six fields: not the line cut gives, so it's refused.
			if _, err := ReadShadow(ctx, &host{answers: map[string]string{"getent shadow": out}}, "u"); err == nil {
				t.Errorf("%q: a line with the wrong number of fields was read", out)
			}
			continue
		}
		got, err := ReadShadow(ctx, &host{answers: map[string]string{"getent shadow": out}}, "u")
		if err != nil || got != want {
			t.Errorf("%q: %+v, %v", out, got, err)
		}
	}
	for _, bad := range []string{"!::::soon\n", "!:x:::\n", "!::-2::\n"} {
		if _, err := ReadShadow(ctx, &host{answers: map[string]string{"getent shadow": bad}}, "u"); err == nil {
			t.Errorf("%q was read", bad)
		}
	}
}

func TestSetLock(t *testing.T) {
	for _, c := range []struct {
		lock bool
		hash string
		want string // the usermod flag run, "" for none
	}{
		{true, "$6$s$h", "-L"},
		{true, "!$6$s$h", ""},
		{true, "!", ""}, // no password: nothing to log in with already
		{false, "!$6$s$h", "-U"},
		{false, "$6$s$h", ""},
	} {
		h := &host{}
		if err := SetLock(ctx, h, "u", c.lock, Shadow{Hash: c.hash}); err != nil {
			t.Errorf("%t on %q: %v", c.lock, c.hash, err)
			continue
		}
		ran := strings.Join(h.ran, "\n")
		if c.want == "" && ran != "" || c.want != "" && !strings.Contains(ran, "usermod "+c.want+" -- 'u'") {
			t.Errorf("%t on %q ran %q, want %q", c.lock, c.hash, ran, c.want)
		}
	}
	// usermod -U on an account without a password refuses but exits 0.
	for _, hash := range []string{"!", "!!", "!*"} {
		h := &host{}
		if err := SetLock(ctx, h, "u", false, Shadow{Hash: hash}); err == nil || len(h.ran) != 0 || !strings.Contains(err.Error(), "no password") {
			t.Errorf("unlocking %q: %v, ran %v", hash, err, h.ran)
		}
	}
}

func TestSetExpiry(t *testing.T) {
	for date, want := range map[string]string{
		"2026-12-31": "usermod -e 20818 -- 'u'",
		"1970-01-01": "usermod -e 0 -- 'u'",
		"":           "usermod -e '' -- 'u'",
	} {
		h := &host{}
		if err := SetExpiry(ctx, h, "u", date); err != nil || len(h.ran) != 1 || !strings.Contains(h.ran[0], want) {
			t.Errorf("%q: %v, ran %v", date, err, h.ran)
		}
	}
	for _, bad := range []string{"2026-13-01", "31/12/2026", "tomorrow"} {
		if ValidExpiry(bad) {
			t.Errorf("%q passed as a date", bad)
		}
		if err := SetExpiry(ctx, &host{}, "u", bad); err == nil {
			t.Errorf("%q was set", bad)
		}
	}
}

// SetAging runs one chage with only the fields that differ (#1184).
func TestSetAging(t *testing.T) {
	n := func(i int) *int { return &i }
	now := Shadow{MinDays: 0, MaxDays: 99999, WarnDays: 7}
	for _, c := range []struct {
		want Aging
		ran  string // the chage run, "" for none
	}{
		{Aging{MaxDays: n(90)}, "chage -M 90 -- 'u'"},
		{Aging{MinDays: n(1), MaxDays: n(365), WarnDays: n(7)}, "chage -m 1 -M 365 -- 'u'"},
		{Aging{MaxDays: n(99999), WarnDays: n(7)}, ""},
		{Aging{MaxDays: n(-1)}, "chage -M -1 -- 'u'"},
		{Aging{}, ""},
	} {
		h := &host{}
		if err := SetAging(ctx, h, "u", c.want, now); err != nil {
			t.Fatal(err)
		}
		ran := ""
		for _, l := range h.ran {
			if strings.Contains(l, "chage") {
				ran = l[strings.Index(l, "chage"):]
			}
		}
		if ran != c.ran {
			t.Errorf("%+v: ran %q, want %q", c.want, ran, c.ran)
		}
	}
}
