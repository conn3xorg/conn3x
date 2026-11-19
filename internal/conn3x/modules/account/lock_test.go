// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package account

import (
	"strings"
	"testing"
)

func TestReadShadow(t *testing.T) {
	for out, want := range map[string]Shadow{
		"$6$s$h:\n":       {Hash: "$6$s$h"},
		"!$6$s$h:20818\n": {Hash: "!$6$s$h", Expires: "2026-12-31"},
		"!:0\n":           {Hash: "!", Expires: "1970-01-01"},
		"*:-1\n":          {Hash: "*"},
	} {
		got, err := ReadShadow(ctx, &host{answers: map[string]string{"getent shadow": out}}, "u")
		if err != nil || got != want {
			t.Errorf("%q: %+v, %v", out, got, err)
		}
	}
	if _, err := ReadShadow(ctx, &host{answers: map[string]string{"getent shadow": "!:soon\n"}}, "u"); err == nil {
		t.Error("an expiry that isn't a number was read")
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
