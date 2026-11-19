// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package account

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/opentofu/opentofu/internal/conn3x/modules"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// Shadow is what /etc/shadow holds for a user's lock and expiry.
type Shadow struct {
	Hash    string // the password field, ! in front when it's locked
	Expires string // the account's last day as YYYY-MM-DD, "" for never
}

// IsLocked reports whether the password field is locked, with the ! that
// usermod -L puts in front, as Ansible's password_lock reads it. A new
// account's bare ! counts as locked: it has no password to log in with.
func (s Shadow) IsLocked() bool { return strings.HasPrefix(s.Hash, "!") }

// ReadShadow reads name's password field and expiry from /etc/shadow,
// which needs root.
func ReadShadow(ctx context.Context, r modules.Runner, name string) (Shadow, error) {
	res, err := r.Run(ctx, needsRoot+"getent shadow -- "+ssh.Quote(name)+" | cut -d: -f2,8", nil)
	if err != nil {
		return Shadow{}, err
	}
	if res.ExitCode == 3 {
		return Shadow{}, ErrNeedsRoot
	}
	if res.ExitCode != 0 {
		return Shadow{}, fmt.Errorf("reading the shadow entry of %s: %s", name, strings.TrimSpace(string(res.Stderr)))
	}
	hash, days, _ := strings.Cut(strings.TrimSpace(string(res.Stdout)), ":")
	expires, err := expiryDate(days)
	if err != nil {
		return Shadow{}, fmt.Errorf("reading the expiry of %s: %w", name, err)
	}
	return Shadow{Hash: hash, Expires: expires}, nil
}

// expiryDate turns shadow's days since 1970-01-01 into a date in UTC, as
// usermod -e counts them. Empty or negative is no expiry.
func expiryDate(days string) (string, error) {
	if days == "" {
		return "", nil
	}
	d, err := strconv.ParseInt(days, 10, 64)
	if err != nil {
		return "", fmt.Errorf("%q isn't a number of days", days)
	}
	if d < 0 {
		return "", nil
	}
	return time.Unix(d*86400, 0).UTC().Format(time.DateOnly), nil
}

// ValidExpiry reports whether s is a date usermod -e can take: YYYY-MM-DD,
// or "" for no expiry.
func ValidExpiry(s string) bool {
	if s == "" {
		return true
	}
	_, err := time.Parse(time.DateOnly, s)
	return err == nil
}

// SetLock locks or unlocks name's password with usermod -L or -U, when it
// isn't already. usermod -U on an account with no password refuses but
// exits 0, so that is refused here instead.
func SetLock(ctx context.Context, r modules.Runner, name string, lock bool, now Shadow) error {
	if lock == now.IsLocked() {
		return nil
	}
	flag := "-L"
	if !lock {
		if _, ok := Locked(now.Hash); !ok {
			return errors.New("can't unlock it: it has no password, so unlocking would let anyone log in without one. Set password_wo or password_hash_wo")
		}
		flag = "-U"
	}
	return run(ctx, r, "usermod "+flag+" -- "+ssh.Quote(name))
}

// SetExpiry sets name's last day, YYYY-MM-DD in UTC, or no expiry for "".
// usermod gets the day count, which no time zone can shift.
func SetExpiry(ctx context.Context, r modules.Runner, name, date string) error {
	days := "''"
	if date != "" {
		t, err := time.Parse(time.DateOnly, date)
		if err != nil {
			return fmt.Errorf("expires %q isn't a date as YYYY-MM-DD", date)
		}
		days = strconv.FormatInt(t.Unix()/86400, 10)
	}
	return run(ctx, r, "usermod -e "+days+" -- "+ssh.Quote(name))
}
