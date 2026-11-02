// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package windows

import (
	"context"
	"strings"
	"testing"
)

func baseTask() Task {
	return Task{Path: `\`, Name: "Nightly", Execute: `C:\Windows\System32\cmd.exe`, Arguments: "/c echo hi", User: "SYSTEM", Enabled: true, AllowInterpreter: true,
		Triggers: []TaskTrigger{{Type: "daily", At: "2026-01-01T03:00:00"}, {Type: "boot"}}}
}

func TestTaskValidate(t *testing.T) {
	if err := baseTask().Validate(); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*Task){
		"wildcard name":       func(t *Task) { t.Name = "Night*" },
		"bad folder":          func(t *Task) { t.Path = `Conn3x` },
		"folder wildcard":     func(t *Task) { t.Path = `\Con*\` },
		"relative program":    func(t *Task) { t.Execute = "cmd.exe" },
		"unc program":         func(t *Task) { t.Execute = `\\srv\share\x.exe` },
		"no user":             func(t *Task) { t.User = "" },
		"password on SYSTEM":  func(t *Task) { t.HasPassword = true },
		"daily without at":    func(t *Task) { t.Triggers = []TaskTrigger{{Type: "daily"}} },
		"boot with at":        func(t *Task) { t.Triggers = []TaskTrigger{{Type: "boot", At: "2026-01-01T03:00:00"}} },
		"zoned time":          func(t *Task) { t.Triggers = []TaskTrigger{{Type: "once", At: "2026-01-01T03:00:00Z"}} },
		"interval on once":    func(t *Task) { t.Triggers = []TaskTrigger{{Type: "once", At: "2026-01-01T03:00:00", DaysInterval: 2}} },
		"unknown trigger":     func(t *Task) { t.Triggers = []TaskTrigger{{Type: "idle"}} },
		"newline in argument": func(t *Task) { t.Arguments = "a\nb" },
	} {
		tk := baseTask()
		change(&tk)
		if tk.Validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for _, p := range []string{`%SystemRoot%\System32\cmd.exe`, `C:\%USERNAME%\x.exe`} {
		tk := baseTask()
		tk.Execute = p
		if tk.Validate() == nil {
			t.Errorf("accepted %s", p)
		}
	}
}

func TestTaskMatches(t *testing.T) {
	tk := baseTask()
	a := ActualTask{Exists: true, UserSID: "S-1-5-18", WantSID: "S-1-5-18", Logon: "ServiceAccount", RunLevel: "Limited", Enabled: true}
	a.Actions = append(a.Actions, struct {
		Execute          string `json:"execute"`
		Arguments        string `json:"arguments"`
		WorkingDirectory string `json:"working_directory"`
	}{Execute: `c:\windows\system32\cmd.exe`, Arguments: "/c echo hi"})
	type trig = struct {
		Kind    string `json:"kind"`
		Start   string `json:"start"`
		Days    int    `json:"days"`
		Enabled bool   `json:"enabled"`
	}
	a.Triggers = []trig{{Kind: "MSFT_TaskDailyTrigger", Start: "2026-01-01T03:00:00", Days: 1, Enabled: true}, {Kind: "MSFT_TaskBootTrigger", Enabled: true}}
	if !tk.Matches(a) {
		t.Fatal("didn't match")
	}
	for name, change := range map[string]func(*ActualTask){
		"disabled":      func(a *ActualTask) { a.Enabled = false },
		"other program": func(a *ActualTask) { a.Actions[0].Execute = `C:\evil.exe` },
		"arguments":     func(a *ActualTask) { a.Actions[0].Arguments = "/c evil" },
		"other user":    func(a *ActualTask) { a.UserSID = "S-1-5-21-1-500" },
		"elevated":      func(a *ActualTask) { a.RunLevel = "Highest" },
		"logon":         func(a *ActualTask) { a.Logon = "Password" },
		"not SYSTEM":    func(a *ActualTask) { a.WantSID, a.UserSID = "S-1-5-21-1-1001", "S-1-5-21-1-1001" },
		"trigger time":  func(a *ActualTask) { a.Triggers[0].Start = "2026-01-01T04:00:00" },
		"interval":      func(a *ActualTask) { a.Triggers[0].Days = 2 },
		"extra trigger": func(a *ActualTask) {
			a.Triggers = append(a.Triggers, trig{Kind: "MSFT_TaskLogonTrigger", Enabled: true})
		},
		"no user found": func(a *ActualTask) { a.WantSID = "" },
	} {
		b := a
		b.Actions = append(b.Actions[:0:0], a.Actions...)
		b.Triggers = append(b.Triggers[:0:0], a.Triggers...)
		change(&b)
		if tk.Matches(b) {
			t.Errorf("%s: matched", name)
		}
	}
}

// The password goes as an argument on stdin and nowhere else, and errors that
// echo it come back blanked.
func TestApplyTaskPassword(t *testing.T) {
	const secret = "s3ntinel-Task!"
	tk := baseTask()
	tk.User, tk.HasPassword = `LAB\svc`, true
	f := &fake{answers: []map[string]any{{"ok": false, "error": "logon failed for " + secret}}}
	err := ApplyTask(context.Background(), f, tk, secret)
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("err = %v", err)
	}
	if f.sent[0]["args"].(map[string]any)["password"] != secret || strings.Contains(f.sent[0]["script"].(string), secret) {
		t.Error("the password went somewhere other than args")
	}
	if ApplyTask(context.Background(), &fake{}, tk, "") == nil {
		t.Error("a password logon went without a password")
	}
	if ApplyTask(context.Background(), &fake{}, baseTask(), secret) == nil {
		t.Error("a password went with a service account")
	}
}

// Ordinary arguments pass, and give the paths for the host to check.
func TestArgumentPaths(t *testing.T) {
	for args, want := range map[string][]string{
		`--config C:\ProgramData\App\cfg.json`: {`C:\ProgramData\App\cfg.json`},
		`-v`:                                   nil,
		`/quiet`:                               nil,
		`--port=8080`:                          nil,
		`https://example.com/x`:                nil,
		`--url=https://example.com/a?b=1 /p:Config`:      nil,
		`--out=C:\out\x.log`:                             {`C:\out\x.log`},
		`/c echo hi`:                                     nil,
		`-Command "& C:\Users\Public\x.ps1; whoami"`:     {`C:\Users\Public\x.ps1`},
		`-Command "& 'C:\Users\Public\x.ps1'"`:           {`C:\Users\Public\x.ps1`},
		`/c C:\Users\Public\job`:                         {`C:\Users\Public\job`},
		`C:\Users\Public\evil,Entry`:                     {`C:\Users\Public\evil`},
		`/c C:/Users/Public/job`:                         {`C:\Users\Public\job`},
		`/c "C:\Program Files (x86)\App\run.bat" --fast`: {`C:\Program Files (x86)\App\run.bat`},
		`/c whoami >C:\out\who.txt`:                      {`C:\out\who.txt`},
		`"http://a C:\Users\Public\x"`:                   {`C:\Users\Public\x`},
		`https://host/p;C:\Users\Public\x.exe`:           {`C:\Users\Public\x.exe`},
		`https://example.com/a,b`:                        nil,
		`https://host/x&C:/Users/Public/evil.bat`:        {`C:\Users\Public\evil.bat`},
		`/log:C:\Logs\job.log /p:Config`:                 {`C:\Logs\job.log`},
	} {
		got, err := ArgumentPaths(args)
		if err != nil || strings.Join(got, "|") != strings.Join(want, "|") {
			t.Errorf("%s: %q, %v", args, got, err)
		}
	}
}

// Every way past the check that reviews found: each is refused outright.
func TestArgumentPathsRefused(t *testing.T) {
	for name, args := range map[string]string{
		"percent":                     `/c %PUBLIC%\job`,
		"caret":                       `/c job.b^at`,
		"bang":                        `/c !x!`,
		"relative":                    `/c ..\..\Users\Public\job`,
		"relative slash":              `/c Public/job`,
		"rooted backslash":            `/c \Users\Public\job.bat`,
		"rooted forward slash":        `/Users/Public/evil.dll,Entry`,
		"share":                       `-File \\server\share\x.ps1`,
		"forward share":               `-File //server/share/x.ps1`,
		"device":                      `\\?\C:\Users\Public\x.dll,Entry`,
		"file URL":                    `file:///C:/Users/Public/x.ps1`,
		"other scheme":                `ftp://host/x.ps1`,
		"drive-relative":              `D:evil.dll,Entry`,
		"colon switch with a path":    `-File:C:\Users\Public\x.ps1`,
		"second path in one quote":    `"C:\Windows\System32\cmd.exe /c \Users\Public\job.bat"`,
		"shell metas in a quote":      `"C:\Windows\System32\x &\Users\Public\evil.bat"`,
		"short name":                  `C:\PROGRA~1\App\x.exe`,
		"folder ending in a dot":      `C:\Windows.\System32\x.dll`,
		"quoted folder ending space":  `"C:\Windows \System32\x.dll"`,
		"switch value that's a share": `--config=\\server\share\x`,
		"slash switch drive-relative": `/sw:D:evil.dll`,
		"slash switch rooted":         `/sw:\Users\Public\evil.dll`,
		"slash switch forward rooted": `/sw:/Users/Public/evil.dll`,
		"path inside a URL":           `https://host/p;D:evil.dll`,
		"backslash inside a URL":      `https://host\Users\Public\x`,
	} {
		if _, err := ArgumentPaths(args); err == nil {
			t.Errorf("%s: accepted %s", name, args)
		}
	}
}

func TestInterpretersNeedOptIn(t *testing.T) {
	for _, exe := range []string{`C:\Windows\System32\cmd.exe`, `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, `C:\Windows\System32\RUNDLL32.EXE`,
		`C:\Windows\System32\mshta.exe`, `C:\Python312\python.exe`, `C:\Python312\pythonw3.12.exe`, `C:\Windows\explorer.exe`,
		`C:\Windows\System32\pcalua.exe`, `C:\Windows\System32\msdt.exe`, `C:\Program Files\Git\cmd\git.exe`, `C:\Program Files\dotnet\dotnet.exe`} {
		tk := baseTask()
		tk.Execute, tk.AllowInterpreter = exe, false
		if err := tk.Validate(); err == nil || !strings.Contains(err.Error(), "allow_interpreter") {
			t.Errorf("%s: %v", exe, err)
		}
	}
	tk := baseTask()
	tk.Execute, tk.AllowInterpreter, tk.Arguments = `C:\Program Files\App\app.exe`, false, "--quiet"
	if err := tk.Validate(); err != nil {
		t.Errorf("a plain program: %v", err)
	}
	tk.Execute = `C:\PROGRA~1\App\app.exe`
	if tk.Validate() == nil {
		t.Error("a short name in execute was accepted")
	}
}

// data_paths skips the admin-only check only for an exact match.
func TestTaskSplitData(t *testing.T) {
	task := Task{DataPaths: []string{`C:\Logs\job.log`, `c:/data/in.csv`}}
	paths, _ := ArgumentPaths(`--log C:\logs\JOB.log --in C:\Data\in.csv --plugin C:\Logs\job.log.dll --dir C:\Logs`)
	check, data := task.splitData(paths)
	if strings.Join(data, "|") != `C:\logs\JOB.log|C:\Data\in.csv` || strings.Join(check, "|") != `C:\Logs\job.log.dll|C:\Logs` {
		t.Errorf("check %q, data %q", check, data)
	}
	task = Task{Name: "t", Path: `\`, Execute: `C:\App\app.exe`, User: "SYSTEM", Enabled: true,
		Arguments: `--log C:\Logs\job.log --twice C:\Logs\twice.log --again C:\Logs\twice.log --key C:\Logs\key.log`}
	task.DataPaths = []string{`C:\Logs\job.log`}
	if err := task.Validate(); err != nil {
		t.Errorf("plain data path refused: %v", err)
	}
	for _, bad := range []string{`D:job.log`, `\\server\share\x.log`, `C:\PROGRA~1\x.log`, `C:\logs\x.log:s`, `logs\x.log`, `C:\%TEMP%\x.log`,
		"C:\\Logs\\\u212aey.log", `C:\Logs\unused.log`, `C:\Logs\twice.log`} {
		task.DataPaths = []string{bad}
		if err := task.Validate(); err == nil {
			t.Errorf("data_paths %s accepted", bad)
		}
	}
}
