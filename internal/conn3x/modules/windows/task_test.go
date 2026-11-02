// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package windows

import (
	"context"
	"strings"
	"testing"
)

func baseTask() Task {
	return Task{Path: `\`, Name: "Nightly", Execute: `C:\Windows\System32\cmd.exe`, Arguments: "/c echo hi", User: "SYSTEM", Enabled: true,
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
	for user, want := range map[string]string{"SYSTEM": "service", `NT AUTHORITY\Network Service`: "service", `LAB\svc`: "s4u"} {
		if got := (Task{User: user}).LogonType(); got != want {
			t.Errorf("%s: %s", user, got)
		}
	}
	if (Task{User: `LAB\svc`, HasPassword: true}).LogonType() != "password" {
		t.Error("password logon")
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
