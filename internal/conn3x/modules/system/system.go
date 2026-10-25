// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package system sets host-wide basics: kernel parameters, the hostname and
// the time zone.
package system

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/opentofu/opentofu/internal/conn3x/modules"
	"github.com/opentofu/opentofu/internal/conn3x/modules/file"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

var sysctlKey = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]*([./][A-Za-z0-9_-]+)+$`)

// Sysctl is one kernel parameter, kept in its own file in /etc/sysctl.d.
type Sysctl struct{ Key, Value string }

// Validate checks a Sysctl before anything is written.
func (s Sysctl) Validate() error {
	if !sysctlKey.MatchString(s.Key) {
		return fmt.Errorf("name %q is not a sysctl key such as net.ipv4.ip_forward", s.Key)
	}
	if strings.TrimSpace(s.Value) == "" {
		return errors.New("value must not be empty")
	}
	if strings.ContainsAny(s.Value, "\r\n") {
		return errors.New("value must be a single line")
	}
	return nil
}

// Path is the drop-in file that keeps the setting across reboots. A / in a
// key (an interface name such as eth0/100) is not allowed in a file name.
func (s Sysctl) Path() string {
	return "/etc/sysctl.d/90-conn3x-" + strings.ReplaceAll(s.Key, "/", "_") + ".conf"
}

// Content renders the drop-in file.
func (s Sysctl) Content() string {
	return fmt.Sprintf("# Managed by Conn3x.\n%s = %s\n", s.Key, normalize(s.Value))
}

// Matches reports whether live, as printed by sysctl -n, is the wanted value.
func (s Sysctl) Matches(live string) bool { return normalize(live) == normalize(s.Value) }

func normalize(v string) string { return strings.Join(strings.Fields(v), " ") }

// ReadSysctl returns the live value of a key.
func ReadSysctl(ctx context.Context, r modules.Runner, key string) (string, error) {
	res, err := r.Run(ctx, "sysctl -n -- "+ssh.Quote(key), nil)
	if err != nil {
		return "", err
	}
	if res.ExitCode != 0 {
		return "", fmt.Errorf("sysctl %s: %s", key, strings.TrimSpace(string(res.Stderr)))
	}
	return string(res.Stdout), nil
}

// ApplySysctl writes the drop-in file and loads it into the running kernel.
func ApplySysctl(ctx context.Context, r modules.Runner, s Sysctl) error {
	if err := s.Validate(); err != nil {
		return err
	}
	if err := file.Apply(ctx, r, file.Desired{Path: s.Path(), Content: s.Content(), Mode: "0644", Owner: "root", Group: "root"}); err != nil {
		return err
	}
	return check(r.Run(ctx, "sysctl -p "+ssh.Quote(s.Path()), nil))
}

var hostLabel = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

// ValidateHostname checks a name against RFC 1123 and Linux's 64-byte limit.
func ValidateHostname(name string) error {
	if name == "" || len(name) > 64 {
		return fmt.Errorf("hostname %q must be 1 to 64 characters", name)
	}
	for _, label := range strings.Split(name, ".") {
		if !hostLabel.MatchString(label) {
			return fmt.Errorf("hostname %q may only use letters, digits and inner hyphens between dots", name)
		}
	}
	return nil
}

// ReadHostname returns the name in /etc/hostname and the running kernel's.
func ReadHostname(ctx context.Context, r modules.Runner) (static, live string, err error) {
	res, err := r.Run(ctx, "cat /etc/hostname 2>/dev/null; echo; uname -n", nil)
	if err != nil {
		return "", "", err
	}
	lines := strings.Split(strings.TrimSpace(string(res.Stdout)), "\n")
	return strings.TrimSpace(lines[0]), strings.TrimSpace(lines[len(lines)-1]), nil
}

// ApplyHostname sets the hostname now and across reboots.
func ApplyHostname(ctx context.Context, r modules.Runner, name string) error {
	if err := ValidateHostname(name); err != nil {
		return err
	}
	return check(r.Run(ctx, "hostnamectl set-hostname "+ssh.Quote(name), nil))
}

var zoneName = regexp.MustCompile(`^[A-Za-z0-9_+-]+(/[A-Za-z0-9_+-]+)*$`)

// ValidateTimezone checks the shape of an IANA zone name such as Europe/Dublin.
func ValidateTimezone(zone string) error {
	if !zoneName.MatchString(zone) {
		return fmt.Errorf("time zone %q is not an IANA name such as Europe/Dublin or UTC", zone)
	}
	return nil
}

// ReadTimezone returns the zone /etc/localtime points at, or "" if none.
func ReadTimezone(ctx context.Context, r modules.Runner) (string, error) {
	res, err := r.Run(ctx, "readlink /etc/localtime", nil)
	if err != nil {
		return "", err
	}
	return zoneFromLink(string(res.Stdout)), nil
}

func zoneFromLink(link string) string {
	link = strings.TrimSpace(link)
	if i := strings.Index(link, "zoneinfo/"); i >= 0 {
		return link[i+len("zoneinfo/"):]
	}
	return link
}

// ApplyTimezone points /etc/localtime at the zone. It uses timedatectl where
// systemd-timedated runs, and links the file itself where it does not.
func ApplyTimezone(ctx context.Context, r modules.Runner, zone string) error {
	if err := ValidateTimezone(zone); err != nil {
		return err
	}
	q := ssh.Quote(zone)
	script := fmt.Sprintf(`test -f /usr/share/zoneinfo/%[1]s || { echo "unknown time zone %[1]s; is the tzdata package installed?" >&2; exit 1; }
timedatectl set-timezone %[1]s 2>/dev/null || ln -sfn /usr/share/zoneinfo/%[1]s /etc/localtime || exit 1
if [ -f /etc/timezone ]; then echo %[1]s > /etc/timezone; fi`, q)
	return check(r.Run(ctx, script, nil))
}

func check(res ssh.Result, err error) error {
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return errors.New(strings.TrimSpace(string(res.Stderr) + string(res.Stdout)))
	}
	return nil
}
