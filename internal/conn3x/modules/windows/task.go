// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package windows

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/opentofu/opentofu/internal/conn3x/modules/windows/ps"
)

var (
	// Get-ScheduledTask expands wildcards in names, so they stay out.
	taskName   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._()-]{0,127}$`)
	taskFolder = regexp.MustCompile(`^\\([A-Za-z0-9][A-Za-z0-9 ._()-]{0,127}\\)*$`)
	// Local time, as Task Scheduler stores it, so it reads back the same.
	taskTime = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$`)
)

// serviceAccounts run without a password. The host decides from the SID; this
// is only for refusing a password early.
var serviceAccounts = map[string]string{
	"system": "S-1-5-18", "nt authority\\system": "S-1-5-18", "s-1-5-18": "S-1-5-18",
	"local service": "S-1-5-19", "nt authority\\local service": "S-1-5-19", "s-1-5-19": "S-1-5-19",
	"network service": "S-1-5-20", "nt authority\\network service": "S-1-5-20", "s-1-5-20": "S-1-5-20",
}

// TaskTrigger is when a task runs.
type TaskTrigger struct {
	Type         string // boot, logon, daily or once
	At           string // daily and once: local time, 2026-01-01T03:00:00
	DaysInterval int    // daily: every this many days; 0 means 1
}

var triggerKinds = map[string]string{"boot": "MSFT_TaskBootTrigger", "logon": "MSFT_TaskLogonTrigger", "daily": "MSFT_TaskDailyTrigger", "once": "MSFT_TaskTimeTrigger"}

// Task is a scheduled task with one program to run.
type Task struct {
	Path, Name       string // Path is the folder, such as \ or \Conn3x\
	Description      *string
	Execute          string // absolute path of the program
	Arguments        string
	WorkingDirectory string
	Triggers         []TaskTrigger
	User             string
	HasPassword      bool // a password logon; the password itself never sits here
	AllowInterpreter bool // the program runs code from its arguments, as cmd.exe does
	Highest          bool
	Enabled          bool
}

// logonFor is the logon Windows shows for the task, given the SID the host
// resolved its user to: the account decides, not how it's spelled.
func (t Task) logonFor(sid string) string {
	switch {
	case t.HasPassword:
		return "Password"
	case sid == "S-1-5-18" || sid == "S-1-5-19" || sid == "S-1-5-20":
		return "ServiceAccount"
	}
	return "S4U"
}

var (
	argToken  = regexp.MustCompile(`"([^"]*)"|'([^']*)'|(\S+)`)
	pathStart = regexp.MustCompile(`[A-Za-z]:[\\/]|\\\\|//`)
	urlStart  = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*://`)
)

// ArgumentPaths finds every path in a task's arguments, for the host to check
// like the program: whatever the task runs, it may run from there. It refuses
// what it can't read as a full local path, rather than guess, and it never
// trusts a file extension, since cmd.exe tries several and rundll32 needs none.
func ArgumentPaths(args string) ([]string, error) {
	// cmd.exe and Task Scheduler expand these after Conn3x has looked.
	if strings.ContainsAny(args, "%^!") {
		return nil, errors.New("arguments must not contain %, ^ or !: they're expanded after Conn3x checks, so write the value out")
	}
	var paths []string
	for _, m := range argToken.FindAllStringSubmatch(args, -1) {
		// A quoted string stays whole, so a quoted path with spaces is one path.
		tok := m[1] + m[2] + m[3]
		for _, piece := range strings.FieldsFunc(tok, func(r rune) bool { return strings.ContainsRune(";&()|,=@<>'\"", r) }) {
			piece = strings.TrimSpace(piece)
			if piece == "" || urlStart.MatchString(piece) {
				continue
			}
			rest := piece
			if at := pathStart.FindStringIndex(piece); at != nil {
				p := strings.ReplaceAll(piece[at[0]:], "/", `\`)
				if strings.HasPrefix(p, `\\`) {
					return nil, fmt.Errorf("arguments name %s, a share or device path, which Conn3x can't check", p)
				}
				paths = append(paths, p)
				rest = piece[:at[0]]
			}
			if strings.Contains(rest, `\`) || strings.Index(rest, "/") > 0 {
				return nil, fmt.Errorf("arguments name %s, a path that isn't a full local one; give the full path, such as C:\\scripts\\job.bat", piece)
			}
		}
	}
	return paths, nil
}

// interpreters run code their arguments hold or name, which no scan of the
// arguments can see into: -EncodedCommand, -Command text, script names a
// shell resolves itself.
var interpreters = map[string]bool{
	"cmd.exe": true, "powershell.exe": true, "powershell_ise.exe": true, "pwsh.exe": true, "wscript.exe": true, "cscript.exe": true,
	"mshta.exe": true, "rundll32.exe": true, "regsvr32.exe": true, "py.exe": true, "pyw.exe": true, "perl.exe": true, "ruby.exe": true,
	"node.exe": true, "java.exe": true, "javaw.exe": true, "msbuild.exe": true, "installutil.exe": true, "regasm.exe": true,
	"regsvcs.exe": true, "msiexec.exe": true, "bash.exe": true, "sh.exe": true, "wsl.exe": true, "forfiles.exe": true,
	"wmic.exe": true, "cmstp.exe": true, "msxsl.exe": true, "hh.exe": true, "conhost.exe": true, "schtasks.exe": true,
}

// IsInterpreter reports whether a program runs code from its arguments.
func IsInterpreter(execute string) bool {
	base := strings.ToLower(execute[strings.LastIndexAny(execute, `\/`)+1:])
	return interpreters[base] || ((strings.HasPrefix(base, "python") || strings.HasPrefix(base, "pythonw")) && strings.HasSuffix(base, ".exe"))
}

// Validate checks a task before anything reaches a host.
func (t Task) Validate() error {
	if !taskName.MatchString(t.Name) {
		return fmt.Errorf("task name %q must start with a letter or digit and use only letters, digits, spaces and . _ ( ) -", t.Name)
	}
	if !taskFolder.MatchString(t.Path) {
		return fmt.Errorf(`path %q must be a task folder such as \ or \Conn3x\, with the same characters as a name`, t.Path)
	}
	for attr, p := range map[string]string{"execute": t.Execute, "working_directory": t.WorkingDirectory} {
		if p == "" && attr == "working_directory" {
			continue
		}
		if err := ValidatePath(attr, p); err != nil {
			return err
		}
		// Task Scheduler expands %NAME%, so the path checked wouldn't be the one run.
		if strings.Contains(p, "%") {
			return fmt.Errorf("%s %q must not contain %%: Task Scheduler expands environment variables, so write the path out", attr, p)
		}
	}
	for attr, v := range map[string]string{"arguments": t.Arguments, "user": t.User} {
		if strings.ContainsFunc(v, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
			return fmt.Errorf("%s must not contain control characters", attr)
		}
	}
	if t.Description != nil && strings.ContainsFunc(*t.Description, func(r rune) bool { return r == 0 }) {
		return errors.New("description must not contain NUL")
	}
	if _, err := ArgumentPaths(t.Arguments); err != nil {
		return err
	}
	if IsInterpreter(t.Execute) && !t.AllowInterpreter {
		return fmt.Errorf("%s runs code from its arguments, which Conn3x can't check: set allow_interpreter = true if every script it runs is admin-only, or run a program instead", t.Execute)
	}
	if strings.TrimSpace(t.User) == "" {
		return errors.New("user must be set, such as SYSTEM or LAB\\svc")
	}
	if t.HasPassword && serviceAccounts[strings.ToLower(t.User)] != "" {
		return fmt.Errorf("%s is a service account, which has no password: remove password_wo", t.User)
	}
	for _, tr := range t.Triggers {
		if _, ok := triggerKinds[tr.Type]; !ok {
			return fmt.Errorf(`trigger type %q must be "boot", "logon", "daily" or "once"`, tr.Type)
		}
		timed := tr.Type == "daily" || tr.Type == "once"
		if timed != (tr.At != "") {
			return fmt.Errorf("a %s trigger %s at", tr.Type, map[bool]string{true: "needs", false: "takes no"}[timed])
		}
		if timed && !taskTime.MatchString(tr.At) {
			return fmt.Errorf("at %q must be a local time such as 2026-01-01T03:00:00", tr.At)
		}
		if tr.DaysInterval < 0 || tr.DaysInterval > 365 || (tr.Type != "daily" && tr.DaysInterval != 0) {
			return errors.New("days_interval is for daily triggers, from 1 to 365")
		}
	}
	return nil
}

// ActualTask is a task as the host has it. Only the fields Conn3x manages are
// read, never the task's XML, which Windows rewrites in its own way.
type ActualTask struct {
	Exists      bool   `json:"exists"`
	Description string `json:"description"`
	Actions     []struct {
		Execute          string `json:"execute"`
		Arguments        string `json:"arguments"`
		WorkingDirectory string `json:"working_directory"`
	} `json:"actions"`
	Triggers []struct {
		Kind    string `json:"kind"`
		Start   string `json:"start"`
		Days    int    `json:"days"`
		Enabled bool   `json:"enabled"`
	} `json:"triggers"`
	UserSID  string `json:"user_sid"`
	WantSID  string `json:"want_sid"`
	Logon    string `json:"logon"`
	RunLevel string `json:"run_level"`
	Enabled  bool   `json:"enabled"`
}

// ReadTask reads a task, and resolves the configured user to compare by SID.
func ReadTask(ctx context.Context, r ps.Runner, t Task) (ActualTask, error) {
	res, err := ps.Read(ctx, r, script("read_task.ps1"), map[string]any{"path": t.Path, "name": t.Name, "user": t.User})
	if err != nil {
		return ActualTask{}, err
	}
	var a ActualTask
	if err := json.Unmarshal(res.Value, &a); err != nil {
		return ActualTask{}, fmt.Errorf("reading task %s%s: the host's answer wasn't valid", t.Path, t.Name)
	}
	return a, nil
}

// Matches reports whether the host has the task as configured.
func (t Task) Matches(a ActualTask) bool {
	if !a.Exists || len(a.Actions) != 1 || len(a.Triggers) != len(t.Triggers) || a.Enabled != t.Enabled {
		return false
	}
	if t.Description != nil && *t.Description != a.Description {
		return false
	}
	act := a.Actions[0]
	if !strings.EqualFold(act.Execute, t.Execute) || act.Arguments != t.Arguments || !strings.EqualFold(act.WorkingDirectory, t.WorkingDirectory) {
		return false
	}
	for i, tr := range t.Triggers {
		got := a.Triggers[i]
		days := tr.DaysInterval
		if tr.Type == "daily" && days == 0 {
			days = 1
		}
		if got.Kind != triggerKinds[tr.Type] || !got.Enabled || !strings.HasPrefix(got.Start, tr.At) || (tr.Type == "daily" && got.Days != days) {
			return false
		}
	}
	level := map[bool]string{true: "Highest", false: "Limited"}[t.Highest]
	return a.WantSID != "" && strings.EqualFold(a.UserSID, a.WantSID) && a.Logon == t.logonFor(a.WantSID) && a.RunLevel == level
}

// ApplyTask creates or replaces a task. password is for a password logon; it
// goes on stdin and to Task Scheduler through a COM call, and errors have it
// blanked.
func ApplyTask(ctx context.Context, r ps.Runner, t Task, password string) error {
	if err := t.Validate(); err != nil {
		return err
	}
	if t.HasPassword != (password != "") {
		return errors.New("a password logon needs password_wo, and only it")
	}
	var triggers []map[string]any
	for _, tr := range t.Triggers {
		days := tr.DaysInterval
		if days == 0 {
			days = 1
		}
		triggers = append(triggers, map[string]any{"type": tr.Type, "at": tr.At, "days": days})
	}
	paths, _ := ArgumentPaths(t.Arguments)
	args := map[string]any{
		"check_paths": paths,
		"path": t.Path, "name": t.Name, "description": t.Description, "execute": t.Execute, "arguments": t.Arguments,
		"working_directory": t.WorkingDirectory, "triggers": triggers, "user": t.User, "has_password": t.HasPassword,
		"highest": t.Highest, "enabled": t.Enabled,
	}
	var secrets []string
	if password != "" {
		args["password"] = password
		secrets = []string{password}
	}
	if _, err := ps.Apply(ctx, r, script("apply_task.ps1"), args, 2*time.Minute); err != nil {
		return errors.New(Scrub(err.Error(), secrets))
	}
	return nil
}

// ApplyTaskRemove deletes a task, if it's there.
func ApplyTaskRemove(ctx context.Context, r ps.Runner, path, name string) error {
	if !taskName.MatchString(name) || !taskFolder.MatchString(path) {
		return errors.New("not a task name")
	}
	_, err := ps.Apply(ctx, r, script("apply_task_remove.ps1"), map[string]any{"path": path, "name": name}, 2*time.Minute)
	return err
}
