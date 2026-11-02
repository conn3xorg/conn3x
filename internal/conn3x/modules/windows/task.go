// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package windows

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
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
	HasPassword      bool     // a password logon; the password itself never sits here
	AllowInterpreter bool     // the program runs code from its arguments, as cmd.exe does
	DataPaths        []string // argument paths only read or written as data, not admin-only
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
	argToken = regexp.MustCompile(`"([^"]*)"|'([^']*)'|(\S+)`)
	// The four kinds of field arguments may hold. Nothing else passes.
	argSwitch = regexp.MustCompile(`^--?[A-Za-z0-9?][A-Za-z0-9_.?-]*(?:=(.*))?$`)
	argSlash  = regexp.MustCompile(`^/[A-Za-z0-9?][^/\\:]*(?::(.*))?$`)
	// No \ ; or , either, so a path can't ride inside a URL unchecked.
	argURL       = regexp.MustCompile(`^https?://[^\s"'<>|^\\;,]+$`)
	argDrivePath = regexp.MustCompile(`^[A-Za-z]:[\\/]`)
	// A quoted path taken whole, spaces and all, may hold none of the
	// characters a shell acts on.
	quotedPath = regexp.MustCompile(`^[A-Za-z]:\\[^;&|<>,"'%^!:/*?]*$`)
)

// argPunct separates fields that sit together without spaces, such as
// rundll32's x.dll,Entry or a redirection >C:\out.txt.
const argPunct = ";&|<>,\"'()@"

// cleanSegments reports whether a path's folders and file name are plain:
// none empty mid-path, and none ending in a space or a dot, which Windows
// drops, so the name checked wouldn't be the one used.
func cleanSegments(p string) bool {
	parts := strings.Split(p[3:], `\`)
	for i, seg := range parts {
		if seg == "" {
			if i == len(parts)-1 {
				continue
			}
			return false
		}
		if strings.HasSuffix(seg, " ") || strings.HasSuffix(seg, ".") || strings.HasPrefix(seg, " ") || shortName.MatchString(seg) {
			return false
		}
	}
	return true
}

// ArgumentPaths reads a task's arguments against an allowlist and returns
// every path in them, for the host to check like the program. Each field
// must be a switch (-x, --x, -x=value, /x), a plain word with no \, / or :,
// an http or https URL, or a full path on a drive. Anything else is
// refused rather than guessed at: Windows reads more forms as paths than
// any scan for paths can list.
func ArgumentPaths(args string) ([]string, error) {
	// cmd.exe and Task Scheduler expand these after Conn3x has looked.
	if strings.ContainsAny(args, "%^!") {
		return nil, errors.New("arguments must not contain %, ^ or !: they're expanded after Conn3x checks, so write the value out")
	}
	var paths []string
	var field func(f string) error
	field = func(f string) error {
		// Split before matching URLs: cmd runs what follows an & in one.
		for _, sub := range strings.FieldsFunc(f, func(r rune) bool { return strings.ContainsRune(argPunct, r) }) {
			switch {
			case argURL.MatchString(sub):
			case argSwitch.MatchString(sub):
				if m := argSwitch.FindStringSubmatch(sub); m[1] != "" {
					if err := field(m[1]); err != nil {
						return err
					}
				}
			case argSlash.MatchString(sub):
				// /x:value gets the same rules as -x=value.
				if m := argSlash.FindStringSubmatch(sub); m[1] != "" {
					if err := field(m[1]); err != nil {
						return err
					}
				}
			case !strings.ContainsAny(sub, `\/:`):
			case argDrivePath.MatchString(sub):
				p := strings.ReplaceAll(sub, "/", `\`)
				if strings.Contains(p[2:], ":") || !cleanSegments(p) {
					return fmt.Errorf("arguments name %s, which isn't a plain full path: no short names, and no folder ending in a space or a dot", sub)
				}
				paths = append(paths, p)
			default:
				return fmt.Errorf("arguments hold %s, which isn't a switch, a plain word, an http or https URL or a full path on a drive, such as C:\\scripts\\job.bat", sub)
			}
		}
		return nil
	}
	for _, m := range argToken.FindAllStringSubmatch(args, -1) {
		if m[3] != "" {
			if err := field(m[3]); err != nil {
				return nil, err
			}
			continue
		}
		// A quoted string: one path with spaces in it, or else fields.
		q := strings.TrimSpace(m[1] + m[2])
		if quotedPath.MatchString(q) && cleanSegments(q) {
			paths = append(paths, q)
			continue
		}
		for _, f := range strings.Fields(q) {
			if err := field(f); err != nil {
				return nil, err
			}
		}
	}
	return paths, nil
}

// splitData takes out the argument paths data_paths lists, matched exactly
// but for case, so the host checks only that they're plain paths on a fixed
// NTFS drive, not who can change them.
func (t Task) splitData(paths []string) (check, data []string) {
	for _, p := range paths {
		if slices.ContainsFunc(t.DataPaths, func(d string) bool { return strings.EqualFold(strings.ReplaceAll(d, "/", `\`), p) }) {
			data = append(data, p)
		} else {
			check = append(check, p)
		}
	}
	return check, data
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
	"explorer.exe": true, "pcalua.exe": true, "syncappvpublishingserver.exe": true, "scriptrunner.exe": true, "msdt.exe": true,
	"ssh.exe": true, "php.exe": true, "rscript.exe": true, "dotnet.exe": true, "csc.exe": true, "vbc.exe": true,
	"odbcconf.exe": true, "runas.exe": true, "git.exe": true,
}

// Interpreters is the list, for the host to match against a program's own
// name for itself, which a renamed copy keeps.
func Interpreters() []string {
	out := make([]string, 0, len(interpreters))
	for k := range interpreters {
		out = append(out, k)
	}
	return out
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
		// A short name such as PROGRA~1 points wherever Windows decides now.
		for _, seg := range strings.Split(p, `\`) {
			if shortName.MatchString(seg) {
				return fmt.Errorf("%s %q uses the short name %s; write the full name", attr, p, seg)
			}
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
	paths, err := ArgumentPaths(t.Arguments)
	if err != nil {
		return err
	}
	for _, p := range t.DataPaths {
		n := strings.ReplaceAll(p, "/", `\`)
		// ASCII only: Go's case folding matches names NTFS keeps apart.
		if !argDrivePath.MatchString(p) || strings.Contains(n[2:], ":") || strings.ContainsAny(n, "%^!") || !cleanSegments(n) || strings.ContainsFunc(n, func(r rune) bool { return r > 0x7e }) {
			return fmt.Errorf("data_paths entry %q must be a plain full path on a drive in ASCII, such as C:\\logs\\job.log", p)
		}
		// Exactly once, so a typo shows and one use can't vouch for another.
		if uses := len(slices.DeleteFunc(slices.Clone(paths), func(a string) bool { return !strings.EqualFold(n, a) })); uses != 1 {
			return fmt.Errorf("data_paths entry %q must appear exactly once in arguments, not %d times", p, uses)
		}
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
	paths, data := t.splitData(paths)
	args := map[string]any{
		"check_paths": paths, "data_paths": data, "allow_interpreter": t.AllowInterpreter, "interpreters": Interpreters(),
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
