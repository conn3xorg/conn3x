// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"strconv"
	"syscall"
	"time"

	sddbus "github.com/coreos/go-systemd/v22/dbus"

	"github.com/opentofu/opentofu/internal/conn3x/agent/agentpb"
)

// readFile reads path as file.Read's shell command does: the mode and
// owner of the path itself (stat without -L), and the type and content of
// what it points to. Any error means the agent can't be sure it would give
// the shell's answer, and the shell is asked instead. Nothing is written.
func readFile(path string) (*agentpb.FileStat, error) {
	var ls syscall.Stat_t
	if err := syscall.Lstat(path, &ls); err != nil {
		if errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ENOTDIR) {
			return &agentpb.FileStat{}, nil
		}
		return nil, &os.PathError{Op: "lstat", Path: path, Err: err}
	}
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		if ls.Mode&syscall.S_IFMT == syscall.S_IFLNK {
			// Dangling, a loop or out of reach: test -f is false.
			return &agentpb.FileStat{Exists: true}, nil
		}
		return nil, &os.PathError{Op: "stat", Path: path, Err: err}
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFREG {
		return &agentpb.FileStat{Exists: true}, nil
	}
	if st.Size > int64(MaxOutput) {
		return nil, fmt.Errorf("%s is over %d MiB, the most the agent returns", path, MaxOutput>>20)
	}
	owner, group, err := names(ls.Uid, ls.Gid)
	if err != nil {
		// The shell asks NSS, which may know names /etc/passwd doesn't.
		return nil, err
	}

	// Non-blocking, in case something other than the file checked above
	// is there by now, such as a FIFO.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var fst syscall.Stat_t
	if err := syscall.Fstat(int(f.Fd()), &fst); err != nil {
		return nil, err
	}
	if fst.Dev != st.Dev || fst.Ino != st.Ino {
		return nil, fmt.Errorf("%s changed while it was read", path)
	}
	content, err := io.ReadAll(io.LimitReader(f, int64(MaxOutput)+1))
	if err != nil {
		return nil, err
	}
	if len(content) > MaxOutput {
		return nil, fmt.Errorf("%s is over %d MiB, the most the agent returns", path, MaxOutput>>20)
	}
	return &agentpb.FileStat{
		Exists:  true,
		Regular: true,
		Mode:    uint32(ls.Mode) & 0o7777,
		Owner:   owner,
		Group:   group,
		Content: content,
	}, nil
}

// names finds the owner's and group's names; tests swap it.
var names = lookupNames

// lookupNames reads /etc/passwd and /etc/group: the agent is built without
// cgo, so it can't ask NSS. An id they don't name is an error, and the
// shell, which asks NSS, answers instead.
func lookupNames(uid, gid uint32) (owner, group string, err error) {
	u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err != nil {
		return "", "", err
	}
	g, err := user.LookupGroupId(strconv.FormatUint(uint64(gid), 10))
	if err != nil {
		return "", "", err
	}
	return u.Username, g.Name, nil
}

// unitTimeout is how long a unit read waits for systemd, as long as
// systemctl show does. After that the shell is asked instead; tests
// shorten it.
var unitTimeout = 25 * time.Second

// readUnit asks systemd over D-Bus for unit's properties, keeping the
// strings and booleans in the form "systemctl show" prints them. Without
// D-Bus, or on any D-Bus error, the shell is asked instead.
//
// ponytail: one D-Bus connection per read; keep one open if reads of many
// units show up in a profile.
func readUnit(ctx context.Context, unit string) (map[string]string, error) {
	ctx, cancel := context.WithTimeout(ctx, unitTimeout)
	defer cancel()
	c, err := sddbus.NewWithContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("no D-Bus connection to systemd: %w", err)
	}
	defer c.Close()
	props, err := c.GetUnitPropertiesContext(ctx, unit)
	if err != nil {
		return nil, fmt.Errorf("asking systemd about %s: %w", unit, err)
	}
	out := make(map[string]string, len(props))
	for k, v := range props {
		switch v := v.(type) {
		case string:
			out[k] = v
		case bool:
			out[k] = "no"
			if v {
				out[k] = "yes"
			}
		}
	}
	return out, nil
}
