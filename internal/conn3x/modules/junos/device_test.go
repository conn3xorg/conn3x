// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package junos

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// fakeDevice answers the way vJunos-switch 26.2R1.7 did over SSH: exit 0
// every time, with the CLI's words in stdout.
type fakeDevice struct {
	sent      *[]string
	config    *string // show configuration | display set
	refuse    string  // a script holding this gets a syntax error at it
	refuseIn  string  // "" for both passes, or "private" or "exclusive" only
	checkFail bool    // commit check fails, as for a missing mandatory statement
	locked    bool    // someone else holds configure exclusive
	shell     bool    // the login lands in csh, as root's does
	down      bool    // every call fails, as on a connection that's gone
	dropLive  bool    // the live script loses its session, as a lockout's commit does
	pending   bool    // a commit confirmed waits for its confirm
	onConfig  func()  // runs after each config read
}

const (
	checkOK   = "\n[edit]\nconn3x# commit check \nconfiguration check succeeds\n"
	checkBad  = "\n[edit]\nconn3x# commit check \n[edit protocols]\n  'bgp'\n    Error in neighbor 10.0.0.1 of group g:\nmust define local autonomous system when enabling BGP\nerror: configuration check-out failed\n"
	committed = "\n[edit]\nconn3x# commit confirmed 5 and-quit \ncommit confirmed will be automatically rolled back in 5 minutes unless confirmed\ncommit complete\nExiting configuration mode\n\nconn3x> \n"
)

func (f fakeDevice) RunShell(ctx context.Context, stdin []byte) (ssh.Result, error) {
	return f.RunRaw(ctx, "", stdin)
}

func (f fakeDevice) RunRaw(ctx context.Context, cmd string, stdin []byte) (ssh.Result, error) {
	if _, ok := ctx.Deadline(); !ok {
		return ssh.Result{}, errors.New("no deadline")
	}
	what := cmd
	if cmd == "" {
		what = string(stdin)
	}
	*f.sent = append(*f.sent, what)
	if f.down {
		return ssh.Result{}, errors.New("connection lost")
	}
	if f.shell {
		return ssh.Result{Stdout: []byte("show: Command not found.\n")}, nil
	}
	if strings.HasPrefix(cmd, "show configuration | display set") {
		defer func() {
			if f.onConfig != nil {
				f.onConfig()
			}
		}()
		return ssh.Result{Stdout: []byte(*f.config)}, nil
	}
	if strings.HasPrefix(cmd, "show version | display json") {
		return ssh.Result{Stdout: []byte(`{"software-information" : [{"host-name" : [{"data" : "sw1"}], "product-model" : [{"data" : "ex9214"}], "junos-version" : [{"data" : "26.2R1.7"}]}]}`)}, nil
	}
	if cmd != "" {
		return ssh.Result{Stdout: []byte("error: syntax error, expecting <command>: " + cmd + "\n")}, nil
	}
	mode := strings.Fields(what)[1]
	if mode == "exclusive" && f.dropLive && strings.Contains(what, "commit confirmed") {
		return ssh.Result{}, errors.New("connection lost")
	}
	var b strings.Builder
	b.WriteString("Entering configuration mode\n")
	if f.pending {
		b.WriteString("\n# commit confirmed will be rolled back in 4 minutes\n")
	}
	if mode == "exclusive" && f.locked {
		return ssh.Result{Stdout: []byte("error: configuration database locked by:\n  ops terminal p0 (pid 4242) on since 2026-11-13 03:10:00 UTC\n      exclusive [edit]\n")}, nil
	}
	for _, line := range strings.Split(strings.TrimSpace(what), "\n")[1:] {
		b.WriteString("\n[edit]\nconn3x# " + line + " \n")
		if f.refuse != "" && strings.Contains(line, f.refuse) && (f.refuseIn == "" || f.refuseIn == mode) {
			b.WriteString(strings.Repeat(" ", 20) + "^\nsyntax error.\n")
		}
		switch {
		case line == "commit check" && f.checkFail:
			b.WriteString(checkBad)
		case line == "commit check":
			b.WriteString(checkOK)
		case strings.HasPrefix(line, "commit confirmed"):
			b.WriteString(committed)
		}
	}
	return ssh.Result{Stdout: []byte(b.String())}, nil
}

func newFake() (fakeDevice, *[]string) {
	sent := []string{}
	config := "set version 26.2R1.7\nset system host-name sw1\n"
	return fakeDevice{sent: &sent, config: &config}, &sent
}

func reconnectTo(d Device) func(context.Context) (Device, error) {
	return func(context.Context) (Device, error) { return d, nil }
}

func TestApplyRunsDryThenConfirmedThenConfirms(t *testing.T) {
	d, sent := newFake()
	diff, err := Apply(context.Background(), d, reconnectTo(d), *d.config, []string{"set system host-name sw2"}, time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if diff != "set system host-name sw2" {
		t.Errorf("diff = %q", diff)
	}
	want := []string{
		"configure private\nset system host-name sw2\ncommit check\nrollback 0\nexit\n",
		"show configuration | display set | no-more",
		"configure exclusive\nset system host-name sw2\ncommit confirmed 5 and-quit\n",
		"configure exclusive\ncommit check\nexit\n",
	}
	if strings.Join(*sent, "|") != strings.Join(want, "|") {
		t.Errorf("sent:\n%q\nwant:\n%q", *sent, want)
	}
}

func TestApplyStopsAtTheDryRun(t *testing.T) {
	for name, f := range map[string]func(*fakeDevice){
		"syntax error": func(d *fakeDevice) { d.refuse = "bogus" },
		"commit check": func(d *fakeDevice) { d.checkFail = true },
	} {
		t.Run(name, func(t *testing.T) {
			d, sent := newFake()
			f(&d)
			_, err := Apply(context.Background(), d, reconnectTo(d), *d.config, []string{"set interfaces ge-0/0/3 bogus-knob 1"}, time.Millisecond)
			if !errors.As(err, new(NotLiveError)) {
				t.Fatalf("err = %v, want NotLiveError", err)
			}
			if len(*sent) != 1 {
				t.Errorf("sent %d calls after a failed dry run, want 1: %q", len(*sent), *sent)
			}
		})
	}
}

func TestApplyRefusesWhenTheConfigChanged(t *testing.T) {
	d, sent := newFake()
	base := *d.config
	*d.config += "set system ntp server 10.0.0.1\n"
	_, err := Apply(context.Background(), d, reconnectTo(d), base, []string{"set system host-name sw2"}, time.Millisecond)
	if !errors.As(err, new(NotLiveError)) || !strings.Contains(err.Error(), "changed while") {
		t.Fatalf("err = %v", err)
	}
	for _, s := range *sent {
		if strings.HasPrefix(s, "configure exclusive") {
			t.Errorf("committed after the config changed: %q", *sent)
		}
	}
}

func TestApplyWhenLocked(t *testing.T) {
	d, _ := newFake()
	d.locked = true
	_, err := Apply(context.Background(), d, reconnectTo(d), *d.config, []string{"set system host-name sw2"}, time.Millisecond)
	if !errors.As(err, new(NotLiveError)) || !strings.Contains(err.Error(), "locked") {
		t.Fatalf("err = %v", err)
	}
}

func TestApplyLeavesARefusalInTheLivePassUnconfirmed(t *testing.T) {
	d, sent := newFake()
	d.refuse, d.refuseIn = "sw2", "exclusive"
	_, err := Apply(context.Background(), d, reconnectTo(d), *d.config, []string{"set system host-name sw2"}, time.Millisecond)
	if err == nil || errors.As(err, new(NotLiveError)) || !strings.Contains(err.Error(), "rolls back on its own") {
		t.Fatalf("err = %v, want a live, unconfirmed commit", err)
	}
	if last := (*sent)[len(*sent)-1]; !strings.Contains(last, "commit confirmed") {
		t.Errorf("confirmed anyway: last sent %q", last)
	}
}

func TestApplyWhenTheConfirmCantLogIn(t *testing.T) {
	d, _ := newFake()
	gone := func(context.Context) (Device, error) { return nil, errors.New("dial tcp: i/o timeout") }
	_, err := Apply(context.Background(), d, gone, *d.config, []string{"set system host-name sw2"}, time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "couldn't confirm") {
		t.Fatalf("err = %v", err)
	}
}

func TestShellLogin(t *testing.T) {
	d, _ := newFake()
	d.shell = true
	if _, err := RunningConfig(context.Background(), d); !errors.Is(err, ErrShellLogin) {
		t.Fatalf("err = %v", err)
	}
}

func TestReadFacts(t *testing.T) {
	d, _ := newFake()
	f, err := ReadFacts(context.Background(), d)
	if err != nil {
		t.Fatal(err)
	}
	if f != (Facts{Hostname: "sw1", Model: "ex9214", Version: "26.2R1.7"}) {
		t.Errorf("facts = %+v", f)
	}
}

func TestShowRefused(t *testing.T) {
	d, _ := newFake()
	if _, err := Show(context.Background(), d, "show bogus"); err == nil || !strings.Contains(err.Error(), "syntax error") {
		t.Fatalf("err = %v", err)
	}
}

func TestMask(t *testing.T) {
	for in, want := range map[string]string{
		`set system root-authentication encrypted-password "$6$abc$def"`:              "set system root-authentication encrypted-password <hidden>",
		`set protocols ospf area 0 interface ge-0/0/0 authentication-key x`:           "set protocols ospf area 0 interface ge-0/0/0 authentication-key <hidden>",
		`set snmp community public authorization read-only`:                           "set snmp community <hidden>",
		`set system login user ops authentication ssh-ed25519 "ssh-ed25519 AAAA ops"`: `set system login user ops authentication ssh-ed25519 "ssh-ed25519 AAAA ops"`,
	} {
		if got := Mask(in); got != want {
			t.Errorf("Mask(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCheckConfirmAfter(t *testing.T) {
	for d, ok := range map[time.Duration]bool{time.Second: false, 5 * time.Second: true, 30 * time.Second: true, 4 * time.Minute: false} {
		if err := CheckConfirmAfter(d); (err == nil) != ok {
			t.Errorf("CheckConfirmAfter(%s) = %v", d, err)
		}
	}
}

// A commit that cuts its own session may have committed, so the lost
// session mustn't read as nothing changed.
func TestApplyWhenTheLiveSessionDrops(t *testing.T) {
	d, _ := newFake()
	d.dropLive = true
	_, err := Apply(context.Background(), d, reconnectTo(d), *d.config, []string{"set system host-name sw2"}, time.Millisecond)
	if err == nil || errors.As(err, new(NotLiveError)) || !strings.Contains(err.Error(), "rolls back on its own") {
		t.Fatalf("err = %v, want an error that isn't NotLiveError", err)
	}
}

func TestApplyRefusesWhileACommitIsPending(t *testing.T) {
	d, sent := newFake()
	d.pending = true
	_, err := Apply(context.Background(), d, reconnectTo(d), *d.config, []string{"set system host-name sw2"}, time.Millisecond)
	if !errors.As(err, new(PendingError)) {
		t.Fatalf("err = %v, want PendingError", err)
	}
	if len(*sent) != 1 {
		t.Errorf("went on past the dry run: %q", *sent)
	}
}

func TestPending(t *testing.T) {
	d, _ := newFake()
	if says, err := Pending(context.Background(), d); err != nil || says != "" {
		t.Fatalf("nothing pending: %q, %v", says, err)
	}
	d.pending = true
	if says, err := Pending(context.Background(), d); err != nil || says != "commit confirmed will be rolled back in 4 minutes" {
		t.Fatalf("pending: %q, %v", says, err)
	}
}

// Junos says some refusals in words no keyword list knows: the caret
// under the refused word is what marks them.
func TestCLIErrorsAfterACaret(t *testing.T) {
	out := `ops# set interfaces ge-0/0/4 mtu 9216
                                         ^
Value 9216 is not within range (256..9192) at '9216'
[edit]
ops# commit check
configuration check succeeds
`
	if errs := cliErrors(out); len(errs) != 1 || !strings.Contains(errs[0], "not within range") {
		t.Fatalf("errs = %q", errs)
	}
	syntax := "ops# set x\n          ^\nsyntax error.\n"
	if errs := cliErrors(syntax); len(errs) != 1 {
		t.Errorf("a syntax error counted %d times: %q", len(errs), errs)
	}
}
