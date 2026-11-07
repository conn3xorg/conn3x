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
	name   string
	sent   *[]string
	refuse string
	down   bool // every command fails, as on a connection that's gone
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
	if strings.HasSuffix(cmd, " diffs") {
		return ssh.Result{Stdout: []byte("+hostname leaf1\n")}, nil
	}
	return ssh.Result{}, nil
}

func reconnectTo(f fakeSwitch, err error) func(context.Context) (Device, error) {
	return func(context.Context) (Device, error) { return f, err }
}

func TestApplyCommitsConfirmsAndSaves(t *testing.T) {
	var sent []string
	d := fakeSwitch{name: "pool", sent: &sent}
	diff, err := Apply(context.Background(), d, reconnectTo(fakeSwitch{name: "fresh", sent: &sent}, nil), []string{"hostname leaf1"}, time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if diff != "+hostname leaf1\n" {
		t.Errorf("diff = %q", diff)
	}
	if len(sent) != 5 {
		t.Fatalf("sent %d commands: %q", len(sent), sent)
	}
	name := strings.Fields(sent[0])[3]
	want := []string{
		"pool: configure session " + name + " / hostname leaf1 / end",
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
	_, err := Apply(context.Background(), d, reconnectTo(d, nil), []string{"interface Ethernet1", "bogus line"}, time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "% Invalid input") || !strings.Contains(err.Error(), "Nothing was changed") {
		t.Fatalf("err = %v", err)
	}
	if len(sent) != 2 || !strings.HasSuffix(sent[1], " abort") || strings.Contains(sent[1], " / ") {
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
		_, err := Apply(context.Background(), d, reconnect, []string{"hostname leaf1"}, time.Millisecond)
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
	if _, err := Apply(context.Background(), fakeSwitch{sent: &sent}, nil, nil, time.Millisecond); err != nil || len(sent) != 0 {
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
	if _, err := Apply(context.Background(), d, reconnect, []string{"hostname leaf1"}, 200*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if waited := confirmedAt.Sub(committedAt); waited < 200*time.Millisecond {
		t.Errorf("confirmed after %s, want at least 200ms", waited)
	}

	sent = nil
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	_, err := Apply(ctx, d, reconnectTo(fakeSwitch{name: "fresh", sent: &sent}, nil), []string{"hostname leaf1"}, time.Minute)
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
