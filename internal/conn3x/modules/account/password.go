// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package account

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/opentofu/opentofu/internal/conn3x/modules"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// ErrNeedsRoot is what reading or setting a password returns when the
// commands don't run as root, which /etc/shadow and chpasswd need.
var ErrNeedsRoot = errors.New("reading and setting a user's password needs root: log in as root, or set become in the ssh block")

// needsRoot fails a script run by anyone but root with exit code 3.
const needsRoot = `[ "$(id -u)" = 0 ] || exit 3` + "\n"

// cryptHash is a crypt(3) hash as /etc/shadow holds one, such as
// $6$salt$hash: what SetPassword writes, so a line break can't reach chpasswd.
var cryptHash = regexp.MustCompile(`^\$[0-9a-z]+\$[./A-Za-z0-9$=,]+$`)

// ReadPasswordHash returns the hash /etc/shadow holds for name: "" when the
// user has none, and something that isn't a hash, such as ! or *, when the
// account is locked or has no password.
func ReadPasswordHash(ctx context.Context, r modules.Runner, name string) (string, error) {
	res, err := r.Run(ctx, needsRoot+"getent shadow -- "+ssh.Quote(name)+" | cut -d: -f2", nil)
	if err != nil {
		return "", err
	}
	if res.ExitCode == 3 {
		return "", ErrNeedsRoot
	}
	if res.ExitCode != 0 {
		return "", fmt.Errorf("reading the password of %s: %s", name, strings.TrimSpace(string(res.Stderr)))
	}
	return strings.TrimSpace(string(res.Stdout)), nil
}

// SetPassword gives name the crypt hash, sent to chpasswd -e on standard
// input, so it never appears in the process list.
func SetPassword(ctx context.Context, r modules.Runner, name, hash string) error {
	if !cryptHash.MatchString(hash) {
		return errors.New("the password hash isn't a crypt hash")
	}
	res, err := r.Run(ctx, needsRoot+"chpasswd -e", []byte(name+":"+hash+"\n"))
	if err != nil {
		return err
	}
	if res.ExitCode == 3 {
		return ErrNeedsRoot
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("setting the password of %s: %s", name, strings.TrimSpace(string(res.Stderr)))
	}
	return nil
}
