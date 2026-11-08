// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package eos

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// fakeSwitch records what it was sent and answers the way cEOS-lab 4.37.0F
// does: a script with a line containing refuse gets "% Invalid input" and
// exit status 1.
type fakeSwitch struct {
	name     string
	sent     *[]string
	refuse   string
	down     bool    // every command fails, as on a connection that's gone
	running  *string // show running-config; nil is ""
	sessions string  // show configuration sessions | json; "" is none
}

func (f fakeSwitch) RunRaw(ctx context.Context, cmd string, stdin []byte) (ssh.Result, error) {
	if _, ok := ctx.Deadline(); !ok {
		return ssh.Result{}, errors.New("no deadline")
	}
	what := cmd
	if cmd == "" {
		what = strings.TrimSpace(string(stdin))
	}
	*f.sent = append(*f.sent, f.name+": "+strings.ReplaceAll(what, "\n", " / "))
	if f.down {
		return ssh.Result{}, errors.New("connection lost")
	}
	if f.refuse != "" && strings.Contains(what, f.refuse) {
		return ssh.Result{Stdout: []byte("\n> " + f.refuse + "\n% Invalid input at line 2\n"), ExitCode: 1}, nil
	}
	switch {
	case strings.HasSuffix(cmd, " diffs"):
		return ssh.Result{Stdout: []byte("+hostname leaf1\n")}, nil
	case cmd == "show configuration sessions | json":
		if f.sessions == "" {
			return ssh.Result{Stdout: []byte(`{"sessions": {}, "maxOpenSessions": 5}`)}, nil
		}
		return ssh.Result{Stdout: []byte(f.sessions)}, nil
	case cmd == "show running-config" && f.running != nil:
		return ssh.Result{Stdout: []byte(*f.running)}, nil
	}
	return ssh.Result{}, nil
}

// quiet drops the reads from sent, leaving what changes the switch.
func quiet(sent []string) []string {
	var out []string
	for _, s := range sent {
		if !strings.Contains(s, ": show ") {
			out = append(out, s)
		}
	}
	return out
}

func reconnectTo(f fakeSwitch, err error) func(context.Context) (Device, error) {
	return func(context.Context) (Device, error) { return f, err }
}

func TestApplyCommitsConfirmsAndSaves(t *testing.T) {
	var sent []string
	d := fakeSwitch{name: "pool", sent: &sent}
	diff, err := Apply(context.Background(), d, reconnectTo(fakeSwitch{name: "fresh", sent: &sent}, nil), "", []string{"hostname leaf1"}, time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if diff != "+hostname leaf1\n" {
		t.Errorf("diff = %q", diff)
	}
	if len(sent) != 7 {
		t.Fatalf("sent %d commands: %q", len(sent), sent)
	}
	name := strings.Fields(sent[1])[3]
	want := []string{
		"pool: show configuration sessions | json",
		"pool: configure session " + name + " / hostname leaf1 / end",
		"pool: show running-config",
		"pool: show session-config named " + name + " diffs",
		"pool: configure session " + name + " commit timer 00:05:00",
		"fresh: configure session " + name + " commit",
		"pool: copy running-config startup-config",
	}
	for i := range want {
		if sent[i] != want[i] {
			t.Errorf("command %d = %q, want %q", i, sent[i], want[i])
		}
	}
	if !strings.HasPrefix(name, "conn3x-") {
		t.Errorf("session name %q", name)
	}
}

func TestApplyAbortsWhenALineIsRefused(t *testing.T) {
	var sent []string
	d := fakeSwitch{name: "pool", sent: &sent, refuse: "bogus"}
	_, err := Apply(context.Background(), d, reconnectTo(d, nil), "", []string{"interface Ethernet1", "bogus line"}, time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "% Invalid input") || !strings.Contains(err.Error(), "Nothing was changed") {
		t.Fatalf("err = %v", err)
	}
	if sent = quiet(sent); len(sent) != 2 || !strings.HasSuffix(sent[1], " abort") || strings.Contains(sent[1], " / ") {
		t.Errorf("sent %q, want the session then its abort", sent)
	}
}

func TestApplyLeavesTheRevertTimerWhenConfirmFails(t *testing.T) {
	var sent []string
	d := fakeSwitch{name: "pool", sent: &sent}
	for _, reconnect := range []func(context.Context) (Device, error){
		reconnectTo(d, errors.New("connection refused")),
		reconnectTo(fakeSwitch{name: "fresh", sent: &sent, down: true}, nil),
	} {
		sent = nil
		_, err := Apply(context.Background(), d, reconnect, "", []string{"hostname leaf1"}, time.Millisecond)
		if err == nil || !strings.Contains(err.Error(), "roll the change back on its own") {
			t.Fatalf("err = %v", err)
		}
		for _, s := range sent {
			if strings.Contains(s, "copy running-config") || strings.Contains(s, "abort") {
				t.Errorf("after a failed confirm, sent %q", s)
			}
		}
	}
}

func TestApplyWithNothingToDoSendsNothing(t *testing.T) {
	var sent []string
	if _, err := Apply(context.Background(), fakeSwitch{sent: &sent}, nil, "", nil, time.Millisecond); err != nil || len(sent) != 0 {
		t.Errorf("err %v, sent %q", err, sent)
	}
}

func TestTimerText(t *testing.T) {
	for d, want := range map[time.Duration]string{5 * time.Minute: "00:05:00", 90 * time.Minute: "01:30:00", 61 * time.Second: "00:01:01"} {
		if got := timerText(d); got != want {
			t.Errorf("timerText(%v) = %q, want %q", d, got, want)
		}
	}
}

type jsonSwitch map[string]string

func (j jsonSwitch) RunRaw(_ context.Context, cmd string, _ []byte) (ssh.Result, error) {
	return ssh.Result{Stdout: []byte(j[cmd])}, nil
}

func TestReadFacts(t *testing.T) {
	f, err := ReadFacts(context.Background(), jsonSwitch{
		"show version | json":  `{"modelName": "cEOSLab", "version": "4.37.0F-1234.4370F", "serialNumber": "", "systemMacAddress": "00:1c:73:00:00:01"}`,
		"show hostname | json": `{"hostname": "leaf1", "fqdn": "leaf1"}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if f.Model != "cEOSLab" || f.Version != "4.37.0F-1234.4370F" || f.Hostname != "leaf1" || f.SystemMAC != "00:1c:73:00:00:01" {
		t.Errorf("facts = %+v", f)
	}
	if _, err := ReadFacts(context.Background(), jsonSwitch{"show version | json": "bash: show: command not found"}); err == nil || !strings.Contains(err.Error(), "Arista EOS") {
		t.Errorf("a shell, not EOS: %v", err)
	}
}

func TestRunStripsTheEchoAndNamesTheLoginProblem(t *testing.T) {
	out, err := Show(context.Background(), jsonSwitch{"show running-config": "> show running-config\n! Command: show running-config\nhostname leaf1\n"}, "show running-config")
	if err != nil || strings.Contains(out, "> show") || !strings.Contains(out, "hostname leaf1") {
		t.Errorf("out %q, err %v", out, err)
	}
	_, err = Show(context.Background(), exitSwitch{"\n> show running-config\n% Invalid input (privileged mode required) at line 1\n"}, "show running-config")
	if !errors.Is(err, ErrNotPrivileged) {
		t.Errorf("err = %v", err)
	}
}

type exitSwitch struct{ out string }

func (e exitSwitch) RunRaw(context.Context, string, []byte) (ssh.Result, error) {
	return ssh.Result{Stdout: []byte(e.out), ExitCode: 1}, nil
}

func TestApplyWaitsBeforeConfirming(t *testing.T) {
	var sent []string
	var committedAt, confirmedAt time.Time
	d := fakeSwitch{name: "pool", sent: &sent}
	reconnect := func(context.Context) (Device, error) {
		confirmedAt = time.Now()
		return fakeSwitch{name: "fresh", sent: &sent}, nil
	}
	committedAt = time.Now()
	if _, err := Apply(context.Background(), d, reconnect, "", []string{"hostname leaf1"}, 200*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if waited := confirmedAt.Sub(committedAt); waited < 200*time.Millisecond {
		t.Errorf("confirmed after %s, want at least 200ms", waited)
	}

	sent = nil
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	_, err := Apply(ctx, d, reconnectTo(fakeSwitch{name: "fresh", sent: &sent}, nil), "", []string{"hostname leaf1"}, time.Minute)
	if err == nil || !strings.Contains(err.Error(), "roll the change back on its own") {
		t.Fatalf("cancelled during the wait: %v", err)
	}
	for _, s := range sent {
		if strings.HasPrefix(s, "fresh:") || strings.Contains(s, "copy running-config") {
			t.Errorf("after a cancel during the wait, sent %q", s)
		}
	}
}

func TestCheckConfirmAfter(t *testing.T) {
	for d, ok := range map[time.Duration]bool{
		4 * time.Second: false, 5 * time.Second: true, 30 * time.Second: true,
		3*time.Minute + 59*time.Second: true, 4 * time.Minute: false, 10 * time.Minute: false,
	} {
		if err := CheckConfirmAfter(d); (err == nil) != ok {
			t.Errorf("CheckConfirmAfter(%s) = %v", d, err)
		}
	}
}

// Lines from several steps go into one session, and one commit makes them
// live with one wait and one confirm.
func TestSessionCommitsEveryStepOnce(t *testing.T) {
	var sent []string
	d := fakeSwitch{name: "pool", sent: &sent}
	s, err := Open(context.Background(), d, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{"hostname leaf1", "vlan 10", "vlan 20"} {
		if err := s.Add(context.Background(), d, []string{line}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Commit(context.Background(), d, reconnectTo(fakeSwitch{name: "fresh", sent: &sent}, nil), time.Millisecond); err != nil {
		t.Fatal(err)
	}
	var commits, confirms int
	for _, c := range sent {
		commits += strings.Count(c, "commit timer")
		if strings.HasPrefix(c, "fresh:") && strings.HasSuffix(c, " commit") {
			confirms++
		}
		if strings.Contains(c, "configure session") && !strings.Contains(c, s.Name) {
			t.Errorf("%q is not the run's session %s", c, s.Name)
		}
	}
	if commits != 1 || confirms != 1 {
		t.Errorf("%d commits and %d confirms, want 1 each: %q", commits, confirms, sent)
	}
}

// A session that never got lines commits nothing.
func TestSessionWithoutLinesSendsNothing(t *testing.T) {
	var sent []string
	d := fakeSwitch{name: "pool", sent: &sent}
	s, err := Open(context.Background(), d, "")
	if err != nil {
		t.Fatal(err)
	}
	sent = nil
	if _, err := s.Commit(context.Background(), d, nil, time.Millisecond); err != nil || len(sent) != 0 {
		t.Errorf("err %v, sent %q", err, sent)
	}
	if err := s.Abort(context.Background(), d); err != nil || len(sent) != 0 {
		t.Errorf("abort: err %v, sent %q", err, sent)
	}
}

// EOS commits a session by replacing running-config with it, so a change
// made since the session started would be undone: Commit aborts instead.
func TestSessionAbortsWhenRunningConfigChanged(t *testing.T) {
	var sent []string
	running := "! Command: show running-config\nhostname leaf1\n"
	d := fakeSwitch{name: "pool", sent: &sent, running: &running}
	s, err := Open(context.Background(), d, running)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Add(context.Background(), d, []string{"vlan 10"}); err != nil {
		t.Fatal(err)
	}
	running = "! Command: show running-config at line 1\nhostname leaf1\n" // only a comment changed
	if _, err := s.Commit(context.Background(), d, reconnectTo(d, nil), time.Millisecond); err != nil {
		t.Fatalf("a comment line changed: %v", err)
	}

	s, _ = Open(context.Background(), d, running)
	_ = s.Add(context.Background(), d, []string{"vlan 20"})
	running += "vlan 99\n" // by hand, mid-run
	sent = nil
	_, err = s.Commit(context.Background(), d, reconnectTo(d, nil), time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "undo that change") || !strings.Contains(err.Error(), "Nothing was changed") {
		t.Fatalf("err = %v", err)
	}
	for _, c := range sent {
		if strings.Contains(c, "commit") {
			t.Errorf("committed after running-config changed: %q", sent)
		}
	}
	if !strings.HasSuffix(sent[len(sent)-1], s.Name+" abort") {
		t.Errorf("session not aborted: %q", sent)
	}
}

// Open refuses while a commit waits on its timer, and aborts pending
// sessions an earlier run left, but no one else's.
func TestOpenChecksOtherSessions(t *testing.T) {
	var sent []string
	waiting := fakeSwitch{name: "pool", sent: &sent, sessions: `{"sessions": {"conn3x-aaaa": {"state": "committed"}}, "commitTimerSessionName": "conn3x-aaaa", "commitTimerExpireTime": 1}`}
	if _, err := Open(context.Background(), waiting, ""); err == nil || !strings.Contains(err.Error(), "conn3x-aaaa is waiting to be confirmed") {
		t.Errorf("err = %v", err)
	}
	sent = nil
	left := fakeSwitch{name: "pool", sent: &sent, sessions: `{"sessions": {"conn3x-bbbb": {"state": "pending"}, "ops-change": {"state": "pending"}, "conn3x-cccc": {"state": "completed"}}}`}
	if _, err := Open(context.Background(), left, ""); err != nil {
		t.Fatal(err)
	}
	if got := quiet(sent); len(got) != 1 || got[0] != "pool: configure session conn3x-bbbb abort" {
		t.Errorf("sent %q, want only the leftover conn3x session aborted", got)
	}
}
