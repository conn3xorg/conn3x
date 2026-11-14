// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ios

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// showRun is show running-config as IOS XE 17.18 (IOL-XE) printed it, cut down.
const showRun = `Building configuration...

Current configuration : 1520 bytes
!
! Last configuration change at 15:59:54 UTC Sat Nov 14 2026 by ops
!
version 17.18
hostname r2
!
interface Loopback1
 description shell-test
 no ip address
!
interface Ethernet0/0
 ip address dhcp
!
archive
 path unix:arch
 maximum 5
!
line vty 0 4
 transport input ssh
!
end
`

func TestRunningConfig(t *testing.T) {
	cfg, err := RunningConfig(context.Background(), &fakeIOS{show: map[string]string{"show running-config": showRun}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(cfg, "Current configuration") || strings.HasSuffix(strings.TrimSpace(cfg), "end") || !strings.Contains(cfg, " description shell-test") {
		t.Errorf("config:\n%s", cfg)
	}
	if lines, ok := section(cfg, []string{"interface Loopback1"}); !ok || !slices.Equal(lines, []string{"description shell-test", "no ip address"}) {
		t.Errorf("section: %q %v", lines, ok)
	}
	if _, err := RunningConfig(context.Background(), &fakeIOS{show: map[string]string{"show running-config": "bash: show: not found"}}); err == nil {
		t.Error("read a shell as IOS")
	}
}

func TestConfigCommandsAndWithLines(t *testing.T) {
	cfg, _ := RunningConfig(context.Background(), &fakeIOS{show: map[string]string{"show running-config": showRun}})
	lo := Config{Parents: []string{"interface Loopback1"}, Lines: []string{"description uplink", "no ip address"}, Match: MatchBlock}
	cmds := lo.Commands(cfg)
	if !slices.Equal(cmds, []string{"interface Loopback1", " no description shell-test", " description uplink"}) {
		t.Fatalf("commands %q", cmds)
	}
	after := WithLines(cfg, cmds)
	if !lo.InSync(after) {
		t.Errorf("not in sync after its own commands:\n%s", after)
	}
	// A second step works out its commands from the first's view.
	ntp := Config{Lines: []string{"ntp server 192.0.2.10"}}
	both := WithLines(after, ntp.Commands(after))
	if !ntp.InSync(both) || !lo.InSync(both) || !strings.Contains(both, "hostname r2") {
		t.Errorf("two steps staged:\n%s", both)
	}
	if !slices.Equal(lo.RemoveCommands(after), []string{"interface Loopback1", " no description uplink", " ip address"}) {
		t.Errorf("remove %q", lo.RemoveCommands(after))
	}
	newIf := Config{Parents: []string{"interface Loopback9"}, Lines: []string{"shutdown"}}
	if got := WithLines(cfg, newIf.Commands(cfg)); !newIf.InSync(got) {
		t.Errorf("a new block:\n%s", got)
	}
	shut := Config{Parents: []string{"interface Ethernet0/0"}, Lines: []string{"shutdown"}}
	if got := WithLines(WithLines(cfg, shut.Commands(cfg)), []string{"interface Ethernet0/0", " no shutdown"}); strings.Contains(got, " shutdown\n") {
		t.Errorf("no shutdown left shutdown:\n%s", got)
	}
}

func TestValidate(t *testing.T) {
	for _, ok := range []Config{
		{Lines: []string{"hostname r1"}},
		{Lines: []string{"enable secret 9 $9$abc"}},
		{Parents: []string{"router ospf 1", "address-family ipv4"}, Lines: []string{"exit-address-family"}},
	} {
		if err := ok.Validate(); err != nil {
			t.Errorf("%+v: %v", ok, err)
		}
	}
	for _, bad := range []Config{
		{},
		{Lines: []string{"end"}},
		{Lines: []string{"wr"}},
		{Lines: []string{"do show run"}},
		{Lines: []string{"conf t"}},
		{Lines: []string{" description x"}},
		{Lines: []string{"hostname a\nhostname b"}},
		{Lines: []string{"! a comment"}},
		{Lines: []string{"x"}, Match: MatchBlock},
	} {
		if bad.Validate() == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}

func TestSession(t *testing.T) {
	got := session([]string{"interface Loopback1", " description x", "hostname r1"})
	want := []string{"configure terminal revert timer 5", "interface Loopback1", " description x", "end", "configure terminal", "hostname r1", "end"}
	if !slices.Equal(got, want) {
		t.Errorf("session %q", got)
	}
}

// fakeIOS answers show commands from a map and shell scripts the way the
// lab's IOS XE did, with the running config changing only when told to.
type fakeIOS struct {
	show     map[string]string
	refuse   string // a line the shell refuses with % Invalid input
	pending  bool
	scripts  []string
	reverted bool
	noSave   bool
}

func (f *fakeIOS) RunRaw(_ context.Context, cmd string, _ []byte) (ssh.Result, error) {
	switch {
	case cmd == "show archive config rollback timer" && f.pending:
		return ssh.Result{Stdout: []byte("Timer type: absolute timer\nTimer value: 5 min\nUser: ops\n")}, nil
	case cmd == "show archive config rollback timer":
		return ssh.Result{Stdout: []byte("%No Rollback Confirmed Change pending\n")}, nil
	case cmd == "show archive" && f.show["show archive"] == "":
		return ssh.Result{Stdout: []byte("The maximum archive configurations allowed is 5.\nThe next archive file will be named unix:arch-<timestamp>-0\n")}, nil
	}
	return ssh.Result{Stdout: []byte(f.show[cmd])}, nil
}

func (f *fakeIOS) RunShell(_ context.Context, stdin []byte) (ssh.Result, error) {
	s := string(stdin)
	f.scripts = append(f.scripts, s)
	var out strings.Builder
	for _, l := range strings.Split(s, "\n") {
		out.WriteString("r2#" + l + "\n")
		switch {
		case strings.HasPrefix(l, "configure terminal revert timer"):
			out.WriteString("Rollback Confirmed Change: Backing up current running config to unix:arch-Nov-14-15-59-51.797-0\n")
			f.pending = true
		case f.refuse != "" && strings.TrimSpace(l) == f.refuse:
			out.WriteString("                ^\n% Invalid input detected at '^' marker.\n")
		case l == "configure revert now":
			out.WriteString("Rollback Confirmed Change: rolling to:unix:arch\nTotal number of passes: 1\nRollback Done\n")
			f.pending, f.reverted = false, true
		case l == "configure confirm":
			f.pending = false
		case l == "show archive config rollback timer" && !f.pending:
			out.WriteString("%No Rollback Confirmed Change pending\n")
		case l == "write memory" && !f.noSave:
			out.WriteString("Building configuration...\n[OK]\n")
		}
	}
	return ssh.Result{Stdout: []byte(out.String())}, nil
}

func reconnectTo(f *fakeIOS) func(context.Context) (Device, error) {
	return func(context.Context) (Device, error) { return f, nil }
}

func TestApply(t *testing.T) {
	ctx := context.Background()
	f := &fakeIOS{show: map[string]string{"show running-config": showRun}}
	base, _ := RunningConfig(ctx, f)
	cmds := []string{"interface Loopback1", " description uplink"}
	if _, err := Apply(ctx, f, reconnectTo(f), base, cmds, time.Millisecond); err != nil {
		t.Fatal(err)
	}
	all := strings.Join(f.scripts, "\n---\n")
	for _, want := range []string{"configure terminal revert timer 5\ninterface Loopback1\n description uplink\nend", "configure confirm", "write memory"} {
		if !strings.Contains(all, want) {
			t.Errorf("never sent %q:\n%s", want, all)
		}
	}
	if f.pending {
		t.Error("left the change unconfirmed")
	}

	// A refused line reverts everything at once.
	f = &fakeIOS{show: map[string]string{"show running-config": showRun}, refuse: "bogus-command"}
	_, err := Apply(ctx, f, reconnectTo(f), base, []string{"interface Loopback1", " bogus-command"}, time.Millisecond)
	if !errors.As(err, new(NotLiveError)) || !strings.Contains(err.Error(), "Invalid input") || !f.reverted {
		t.Errorf("refused line: %v, reverted %v", err, f.reverted)
	}

	// A change waiting for its confirm stops anything new.
	f = &fakeIOS{show: map[string]string{"show running-config": showRun}, pending: true}
	if _, err := Apply(ctx, f, reconnectTo(f), base, cmds, time.Millisecond); !errors.As(err, new(PendingError)) || len(f.scripts) != 0 {
		t.Errorf("pending: %v, %d scripts", err, len(f.scripts))
	}

	// No archive, no way back: nothing is typed.
	f = &fakeIOS{show: map[string]string{"show running-config": showRun, "show archive": "Archive feature not enabled\n"}}
	if _, err := Apply(ctx, f, reconnectTo(f), base, cmds, time.Millisecond); !errors.Is(err, ErrNoArchive) || len(f.scripts) != 0 {
		t.Errorf("no archive: %v, %d scripts", err, len(f.scripts))
	}

	// A change by hand since the plan: nothing is typed.
	f = &fakeIOS{show: map[string]string{"show running-config": strings.Replace(showRun, "hostname r2", "hostname r3", 1)}}
	if _, err := Apply(ctx, f, reconnectTo(f), base, cmds, time.Millisecond); !errors.As(err, new(NotLiveError)) || len(f.scripts) != 0 {
		t.Errorf("changed underneath: %v, %d scripts", err, len(f.scripts))
	}

	// A stamp in a "!" comment isn't a change.
	f = &fakeIOS{show: map[string]string{"show running-config": strings.Replace(showRun, "15:59:54", "16:30:00", 1)}}
	if _, err := Apply(ctx, f, reconnectTo(f), base, cmds, time.Millisecond); err != nil {
		t.Errorf("a new timestamp stopped the apply: %v", err)
	}

	// Not saved is an error, though the change stays.
	f = &fakeIOS{show: map[string]string{"show running-config": showRun}, noSave: true}
	if _, err := Apply(ctx, f, reconnectTo(f), base, cmds, time.Millisecond); err == nil || !strings.Contains(err.Error(), "write memory") {
		t.Errorf("unsaved: %v", err)
	}
}

func TestPending(t *testing.T) {
	says, err := Pending(context.Background(), &fakeIOS{pending: true})
	if err != nil || !strings.Contains(says, "absolute timer") {
		t.Errorf("pending %q %v", says, err)
	}
	if says, err := Pending(context.Background(), &fakeIOS{}); err != nil || says != "" {
		t.Errorf("none %q %v", says, err)
	}
}
