// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package storage makes what a mount needs: a file system on a device, and
// LVM volume groups and logical volumes to put it on. Nothing here destroys
// data unless told to with Force, and removing a step leaves the host's
// disks as they are.
package storage

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/opentofu/opentofu/internal/conn3x/modules"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

var (
	devicePath = regexp.MustCompile(`^/dev/[A-Za-z0-9._+:/-]+$`)
	lvmName    = regexp.MustCompile(`^[A-Za-z0-9_.+][A-Za-z0-9_.+-]*$`)
	mkfsOpt    = regexp.MustCompile(`^[A-Za-z0-9_.,:=/+-]+$`)
)

// validDevice checks a device path before it reaches a shell.
func validDevice(label, d string) error {
	if !devicePath.MatchString(d) || strings.Contains(d, "/../") || strings.HasSuffix(d, "/..") {
		return fmt.Errorf("%s %q must be a device path under /dev, such as /dev/sdb or /dev/vg0/data", label, d)
	}
	return nil
}

func validLVMName(label, n string) error {
	if !lvmName.MatchString(n) || n == "." || n == ".." || len(n) > 127 {
		return fmt.Errorf("%s %q must be an LVM name: letters, digits and _ . + -, not starting with -", label, n)
	}
	return nil
}

// run runs a root-only script and returns its output, or what went wrong.
func run(ctx context.Context, r modules.Runner, script string) (string, error) {
	res, err := r.Run(ctx, modules.GuardRoot(script), nil)
	if err != nil {
		return "", err
	}
	if res.ExitCode != 0 {
		return "", errors.New(strings.TrimSpace(string(res.Stderr) + string(res.Stdout)))
	}
	return string(res.Stdout), nil
}

// fields reads key=value lines.
func fields(out string) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			m[k] = v
		}
	}
	return m
}

func number(s string) int64 {
	n, _ := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	return n
}

// bytes renders a size for messages.
func bytes(n int64) string {
	for _, u := range []struct {
		unit string
		size int64
	}{{"TiB", 1 << 40}, {"GiB", 1 << 30}, {"MiB", 1 << 20}, {"KiB", 1 << 10}} {
		if n >= u.size {
			return strconv.FormatFloat(float64(n)/float64(u.size), 'f', -1, 64) + " " + u.unit
		}
	}
	return strconv.FormatInt(n, 10) + " bytes"
}

// needLVM stops a script on a host without the LVM tools.
const needLVM = `command -v lvm >/dev/null 2>&1 || { echo "the LVM tools aren't installed; add a package step for lvm2 before this one" >&2; exit 1; }
`

// signature is the shell for "what does device $d hold": a file system
// type, LVM2_member, or nothing.
const signature = `sig() { blkid -p -o value -s TYPE "$1" 2>/dev/null; }
`

// quoteAll quotes each word.
func quoteAll(words []string) string {
	q := make([]string, len(words))
	for i, w := range words {
		q[i] = ssh.Quote(w)
	}
	return strings.Join(q, " ")
}
