// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package schedule builds scheduled jobs: cron.d entries and systemd timers.
// It only renders their files; the file and service modules apply them.
package schedule

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/opentofu/opentofu/internal/conn3x/modules/account"
)

// cron.d ignores files whose names contain anything but these.
var cronName = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

var cronField = regexp.MustCompile(`^[A-Za-z0-9*/,-]+$`)

var cronMacros = map[string]bool{"@reboot": true, "@yearly": true, "@annually": true, "@monthly": true, "@weekly": true, "@daily": true, "@midnight": true, "@hourly": true}

// Cron is one job in /etc/cron.d.
type Cron struct {
	Name, Schedule, User, Command string
}

// Path is where the job lives.
func (c Cron) Path() string { return "/etc/cron.d/" + c.Name }

// Validate checks a Cron before anything is written.
func (c Cron) Validate() error {
	if !cronName.MatchString(c.Name) {
		return fmt.Errorf("name %q may only use letters, digits, - and _ (cron ignores other file names)", c.Name)
	}
	if fields := strings.Fields(c.Schedule); len(fields) != 1 || !cronMacros[fields[0]] {
		if len(fields) != 5 {
			return fmt.Errorf("schedule %q needs five fields, or a macro such as @daily", c.Schedule)
		}
		for _, f := range fields {
			if !cronField.MatchString(f) {
				return fmt.Errorf("schedule field %q is not valid", f)
			}
		}
	}
	if c.User != "" {
		if err := (account.UserSpec{Name: c.User}).Validate(); err != nil {
			return err
		}
	}
	return singleLine("command", c.Command)
}

// Content renders the cron.d file.
func (c Cron) Content() (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	user := c.User
	if user == "" {
		user = "root"
	}
	// cron turns an unescaped % into a newline and feeds the rest to stdin.
	return fmt.Sprintf("# Managed by Conn3x.\nSHELL=/bin/sh\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n%s %s %s\n",
		strings.Join(strings.Fields(c.Schedule), " "), user, strings.ReplaceAll(c.Command, "%", `\%`)), nil
}

var unitName = regexp.MustCompile(`^[A-Za-z0-9:_.-]+$`)

// Timer is a systemd timer and the oneshot service it runs.
type Timer struct {
	Name, OnCalendar, User, Command, Description string
	Persistent                                   bool
}

// Paths returns where the service and timer units live.
func (t Timer) Paths() (service, timer string) {
	return "/etc/systemd/system/" + t.Name + ".service", "/etc/systemd/system/" + t.Name + ".timer"
}

// Validate checks a Timer before anything is written.
func (t Timer) Validate() error {
	if !unitName.MatchString(t.Name) || strings.HasSuffix(t.Name, ".timer") || strings.HasSuffix(t.Name, ".service") {
		return fmt.Errorf("name %q is not a valid unit name (leave off .service and .timer)", t.Name)
	}
	if t.OnCalendar == "" {
		return errors.New("on_calendar is required, such as \"daily\" or \"*-*-* 02:30:00\"")
	}
	if t.User != "" {
		if err := (account.UserSpec{Name: t.User}).Validate(); err != nil {
			return err
		}
	}
	for label, v := range map[string]string{"on_calendar": t.OnCalendar, "command": t.Command, "description": t.Description} {
		if err := singleLine(label, v); err != nil && (label != "description" || v != "") {
			return err
		}
	}
	return nil
}

// Units renders the service and timer unit files.
func (t Timer) Units() (service, timer string, err error) {
	if err := t.Validate(); err != nil {
		return "", "", err
	}
	user := t.User
	if user == "" {
		user = "root"
	}
	desc := t.Description
	if desc == "" {
		desc = t.Name + " (managed by Conn3x)"
	}
	// systemd reads % as the start of a specifier, such as %h.
	esc := func(s string) string { return strings.ReplaceAll(s, "%", "%%") }
	service = fmt.Sprintf("[Unit]\nDescription=%s\n\n[Service]\nType=oneshot\nUser=%s\nExecStart=%s\n", esc(desc), user, esc(t.Command))
	timer = fmt.Sprintf("[Unit]\nDescription=%s\n\n[Timer]\nOnCalendar=%s\nPersistent=%t\n\n[Install]\nWantedBy=timers.target\n", esc(desc), t.OnCalendar, t.Persistent)
	return service, timer, nil
}

func singleLine(label, v string) error {
	if strings.TrimSpace(v) == "" {
		return fmt.Errorf("%s must not be empty", label)
	}
	if strings.ContainsAny(v, "\r\n") {
		return fmt.Errorf("%s must be a single line", label)
	}
	return nil
}
