// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package selinux

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/opentofu/opentofu/internal/conn3x/modules"
	"github.com/opentofu/opentofu/internal/conn3x/modules/file"
)

// ConfigFile is where the mode is kept across reboots.
const ConfigFile = "/etc/selinux/config"

// ValidateMode takes enforcing or permissive. Disabling isn't here yet.
func ValidateMode(m string) error {
	if m != "enforcing" && m != "permissive" {
		return fmt.Errorf(`mode must be "enforcing" or "permissive", not %q`, m)
	}
	return nil
}

// ModeState is the mode in the config file and the one running now:
// "enforcing", "permissive" or "disabled".
type ModeState struct{ Config, Running string }

// RebootRequired reports whether mode takes a reboot to be running: it
// does when SELinux is off, since setenforce can't turn it on.
func (s ModeState) RebootRequired(mode string) bool {
	return s.Running != mode && s.Running == "disabled"
}

// Matches reports whether the host has mode, as far as it can without a
// reboot.
func (s ModeState) Matches(mode string) bool {
	return s.Config == mode && (s.Running == mode || s.Running == "disabled")
}

var modeLine = regexp.MustCompile(`(?m)^[ \t]*SELINUX[ \t]*=[ \t]*([A-Za-z]*)[ \t]*$`)

// ReadMode reads the config file and the running mode.
func ReadMode(ctx context.Context, r modules.Runner) (ModeState, error) {
	a, err := file.Read(ctx, r, ConfigFile)
	if err != nil {
		return ModeState{}, err
	}
	if !a.Exists {
		return ModeState{}, fmt.Errorf("there's no %s, so SELinux isn't installed on this host", ConfigFile)
	}
	var s ModeState
	if m := modeLine.FindAllStringSubmatch(a.Content, -1); m != nil {
		s.Config = strings.ToLower(m[len(m)-1][1])
	}
	res, err := r.Run(ctx, "if test -f /sys/fs/selinux/enforce; then cat /sys/fs/selinux/enforce; else echo off; fi", nil)
	if err := check(res, err); err != nil {
		return ModeState{}, err
	}
	switch strings.TrimSpace(string(res.Stdout)) {
	case "1":
		s.Running = "enforcing"
	case "0":
		s.Running = "permissive"
	default:
		s.Running = "disabled"
	}
	return s, nil
}

// withMode is config with its SELINUX= line set to mode, added if missing.
// The last line wins when there are several, as it does for the loader.
func withMode(config, mode string) string {
	locs := modeLine.FindAllStringIndex(config, -1)
	if locs == nil {
		if config != "" && !strings.HasSuffix(config, "\n") {
			config += "\n"
		}
		return config + "SELINUX=" + mode + "\n"
	}
	l := locs[len(locs)-1]
	return config[:l[0]] + "SELINUX=" + mode + config[l[1]:]
}

// ApplyMode writes mode to the config file and, when SELinux is on, sets
// it now with setenforce. It returns whether a reboot is still needed.
func ApplyMode(ctx context.Context, r modules.Runner, mode string) (bool, error) {
	if err := ValidateMode(mode); err != nil {
		return false, err
	}
	s, err := ReadMode(ctx, r)
	if err != nil {
		return false, err
	}
	if s.Config != mode {
		a, err := file.Read(ctx, r, ConfigFile)
		if err != nil {
			return false, err
		}
		if err := file.Apply(ctx, r, file.Desired{Path: ConfigFile, Content: withMode(a.Content, mode), Mode: a.Mode, Owner: "root", Group: "root"}); err != nil {
			return false, err
		}
	}
	if s.Running == "disabled" {
		return true, nil
	}
	if s.Running != mode {
		v := "0"
		if mode == "enforcing" {
			v = "1"
		}
		res, err := r.Run(ctx, "setenforce "+v, nil)
		if err := check(res, err); err != nil {
			return false, err
		}
	}
	return false, nil
}
