// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package schedule builds scheduled jobs: cron.d entries and systemd timers.
// It only renders their files; the file and service modules apply them.
package schedule

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/opentofu/opentofu/internal/conn3x/modules"
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
	if err := validSchedule(c.Schedule); err != nil {
		return err
	}
	if c.User != "" {
		if err := (account.UserSpec{Name: c.User}).Validate(); err != nil {
			return err
		}
	}
	return singleLine("command", c.Command)
}

// validSchedule checks a cron schedule: five fields, or a macro such as
// @daily.
func validSchedule(schedule string) error {
	fields := strings.Fields(schedule)
	if len(fields) == 1 && cronMacros[fields[0]] {
		return nil
	}
	if len(fields) != 5 {
		return fmt.Errorf("schedule %q needs five fields, or a macro such as @daily", schedule)
	}
	for _, f := range fields {
		if !cronField.MatchString(f) {
			return fmt.Errorf("schedule field %q is not valid", f)
		}
	}
	return nil
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

// ParseTimer reads a timer's units, as a host has them, back into the
// Timer a timer step would write them as. It returns why not when the
// units hold something the step can't say, such as a second OnCalendar
// or an OnBootSec, so generate leaves that timer out rather than adopt
// it as something else.
func ParseTimer(name, service, timer string) (Timer, string) {
	t := Timer{Name: name}
	unesc := func(s string) string { return strings.ReplaceAll(s, "%%", "%") }
	seen := map[string]int{}
	read := func(text string, keep map[string]*string) string {
		section := ""
		for _, raw := range strings.Split(text, "\n") {
			line := strings.TrimSpace(raw)
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
				continue
			}
			if strings.HasPrefix(line, "[") {
				section = line
				continue
			}
			k, v, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			k, v = strings.TrimSpace(k), strings.TrimSpace(v)
			key := section + k
			seen[key]++
			if dst, ok := keep[key]; ok {
				*dst = v
				continue
			}
			switch key {
			case "[Unit]Description", "[Install]WantedBy", "[Service]Type":
			default:
				return section + " " + k + " is something a timer step doesn't set"
			}
		}
		return ""
	}
	var persistent, typ string
	if why := read(timer, map[string]*string{"[Timer]OnCalendar": &t.OnCalendar, "[Timer]Persistent": &persistent}); why != "" {
		return Timer{}, why
	}
	var desc string
	if why := read(service, map[string]*string{"[Service]ExecStart": &t.Command, "[Service]User": &t.User, "[Unit]Description": &desc, "[Service]Type": &typ}); why != "" {
		return Timer{}, why
	}
	switch {
	case t.OnCalendar == "":
		return Timer{}, "it has no OnCalendar"
	case seen["[Timer]OnCalendar"] > 1:
		return Timer{}, "it has more than one OnCalendar"
	case t.Command == "":
		return Timer{}, "its service has no ExecStart"
	case seen["[Service]ExecStart"] > 1:
		return Timer{}, "its service has more than one ExecStart"
	case typ != "" && typ != "oneshot":
		return Timer{}, "its service is Type=" + typ + ", and a timer step's is oneshot"
	}
	t.Command, t.Persistent = unesc(t.Command), persistent == "true" || persistent == "yes"
	if d := unesc(desc); d != name+" (managed by Conn3x)" {
		t.Description = d
	}
	if t.User == "root" {
		t.User = ""
	}
	if err := t.Validate(); err != nil {
		return Timer{}, err.Error()
	}
	return t, ""
}

// DropIns are the drop-in directories, holding a .conf, for the timer and
// its service. systemd applies them over the units, so with any there the
// units aren't what runs (#850).
func (t Timer) DropIns(ctx context.Context, r modules.Runner) ([]string, error) {
	res, err := r.Run(ctx, fmt.Sprintf(`for d in /etc/systemd/system /run/systemd/system; do
  for u in %s.timer %s.service; do
    ls "$d/$u.d/"*.conf >/dev/null 2>&1 && echo "$d/$u.d"
  done
done; true`, t.Name, t.Name), nil)
	if err != nil {
		return nil, err
	}
	return strings.Fields(string(res.Stdout)), nil
}

// DropInError is a timer step refusing a timer whose drop-ins change it.
type DropInError struct{ Dirs []string }

func (e DropInError) Error() string {
	return "drop-ins in " + strings.Join(e.Dirs, " and ") + " change what this timer's units say, so the step can't make it run as written. Fold them into the step's arguments and remove them, then apply again"
}

// ParseCron reads the /etc/cron.d file name as the Cron a cron step would
// write it as. It returns why not when the file holds something the step
// can't say: more than one job, a variable such as MAILTO, a SHELL or PATH
// other than the step's, or a % cron would turn into stdin.
func ParseCron(name, content string) (Cron, string) {
	if !cronName.MatchString(name) {
		return Cron{}, "cron skips a file named like this, so it never runs"
	}
	var job string
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok && !strings.ContainsAny(k, " \t") {
			v = strings.Trim(strings.TrimSpace(v), `"'`)
			switch {
			case k == "SHELL" && v == "/bin/sh", k == "PATH" && v == "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin":
				continue
			}
			return Cron{}, "sets " + k + ", which a cron step doesn't"
		}
		if job != "" {
			return Cron{}, "holds more than one job, and a cron step's file holds one"
		}
		job = line
	}
	if job == "" {
		return Cron{}, "holds no job"
	}
	f := strings.Fields(job)
	n := 5
	if strings.HasPrefix(f[0], "@") {
		n = 1
	}
	if len(f) < n+2 {
		return Cron{}, "has a job line that isn't a schedule, a user and a command"
	}
	c := Cron{Name: name, Schedule: strings.Join(f[:n], " "), User: f[n]}
	// The command is the rest of the line as written, spaces and all.
	rest := job
	for range n + 1 {
		rest = strings.TrimLeft(rest, " \t")
		rest = rest[strings.IndexAny(rest, " \t"):]
	}
	cmd := strings.TrimSpace(rest)
	if strings.Contains(strings.ReplaceAll(cmd, `\%`, ""), "%") {
		return Cron{}, "has a % in its command, which cron turns into stdin, and a cron step's command can't"
	}
	c.Command = strings.ReplaceAll(cmd, `\%`, "%")
	if c.User == "root" {
		c.User = ""
	}
	if err := c.Validate(); err != nil {
		return Cron{}, err.Error()
	}
	return c, ""
}
