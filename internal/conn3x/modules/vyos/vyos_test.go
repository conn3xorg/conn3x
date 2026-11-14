// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package vyos

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// fakeRouter answers the way VyOS 2026.11.13-0016-rolling did: exit 0 for a
// refused set, "Set failed" in the output, and a commit-confirm that waits
// for a y on the next line of the script.
type fakeRouter struct {
	sent    *[]string
	config  *[]string // show configuration commands, quoted as VyOS prints it
	refuse  string
	pending *bool
	down    bool
}

func (f fakeRouter) RunRaw(ctx context.Context, cmd string, stdin []byte) (ssh.Result, error) {
	if _, ok := ctx.Deadline(); !ok {
		return ssh.Result{}, errors.New("no deadline")
	}
	*f.sent = append(*f.sent, strings.TrimSpace(cmd+"\n"+string(stdin)))
	if f.down {
		return ssh.Result{}, errors.New("connection lost")
	}
	switch {
	case cmd == opWrapper+"show configuration commands":
		return ssh.Result{Stdout: []byte(strings.Join(*f.config, "\n") + "\n")}, nil
	case cmd == opWrapper+"show version":
		return ssh.Result{Stdout: []byte("Version:          VyOS 2026.11.13-0016-rolling\nRelease train:    rolling\n")}, nil
	case cmd == "systemctl is-active commit-confirm.timer":
		if *f.pending {
			return ssh.Result{Stdout: []byte("active\n"), ExitCode: 0}, nil
		}
		return ssh.Result{Stdout: []byte("inactive\n"), ExitCode: 3}, nil
	case cmd != "vbash -s":
		return ssh.Result{Stdout: []byte("  Invalid command: [" + strings.Fields(cmd)[0] + "]\n")}, nil
	}
	lines := strings.Split(strings.TrimSpace(string(stdin)), "\n")
	var b strings.Builder
	candidate := slices.Clone(*f.config)
	for n := 0; n < len(lines); n++ {
		l := lines[n]
		switch {
		case f.refuse != "" && strings.Contains(l, f.refuse):
			b.WriteString("\n  Configuration path: [" + l + "] is not valid\n  Set failed\n\n")
		case strings.HasPrefix(l, "set "):
			candidate = append(candidate, l)
		case strings.HasPrefix(l, "delete "):
			p := "set " + strings.TrimPrefix(l, "delete ")
			candidate = slices.DeleteFunc(candidate, func(c string) bool { return Normalize(c) == p || strings.HasPrefix(Normalize(c), p+" ") })
		case strings.HasPrefix(l, "commit-confirm"):
			b.WriteString("commit-confirm will automatically reload previous config 5 minutes\nafter commit completes, unless changes are confirmed.\nProceed ? [Y/n] ")
			if n+1 >= len(lines) || lines[n+1] != "y" {
				return ssh.Result{}, errors.New("hung: commit-confirm read no y")
			}
			n++
			*f.config, *f.pending = candidate, true
			b.WriteString("[ commit ]\nInitialized commit-confirm; 5 minutes to confirm before reload\n")
		case l == "confirm":
			if *f.pending {
				*f.pending = false
				b.WriteString("Reload timer stopped\n")
			}
		case l == "save":
			b.WriteString("Saving configuration to '/config/config.boot'...\nDone\n")
		}
	}
	return ssh.Result{Stdout: []byte(b.String())}, nil
}

func newRouter() (fakeRouter, *[]string) {
	sent := []string{}
	config := []string{"set system host-name 'r1'", "set interfaces ethernet eth0 address '192.0.2.10/24'", "set system config-management commit-confirm action 'reload'"}
	pending := false
	return fakeRouter{sent: &sent, config: &config, pending: &pending}, &sent
}

func reconnectTo(d Device) func(context.Context) (Device, error) {
	return func(context.Context) (Device, error) { return d, nil }
}

func TestNormalize(t *testing.T) {
	for in, want := range map[string]string{
		"set system host-name 'r1'":                                 "set system host-name r1",
		"set interfaces ethernet eth0 description 'uplink to core'": `set interfaces ethernet eth0 description "uplink to core"`,
		"set system host-name r1":                                   "set system host-name r1",
	} {
		if got := Normalize(in); got != want {
			t.Errorf("Normalize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestApplyChecksConfirmsAndSaves(t *testing.T) {
	d, sent := newRouter()
	base, err := RunningConfig(context.Background(), d)
	if err != nil {
		t.Fatal(err)
	}
	cmds := Hostname("r2").Commands(base)
	if !slices.Equal(cmds, []string{"delete system host-name", "set system host-name r2"}) {
		t.Fatalf("commands = %q", cmds)
	}
	if _, err := Apply(context.Background(), d, reconnectTo(d), base, cmds, time.Millisecond); err != nil {
		t.Fatal(err)
	}
	all := strings.Join(*sent, "\n---\n")
	for _, want := range []string{"exit discard", "commit-confirm 5\ny", "confirm\nsave"} {
		if !strings.Contains(all, want) {
			t.Errorf("never sent %q:\n%s", want, all)
		}
	}
	if *d.pending {
		t.Error("left the commit unconfirmed")
	}
}

func TestApplyStopsAtARefusal(t *testing.T) {
	d, sent := newRouter()
	d.refuse = "bogus-knob"
	base, _ := RunningConfig(context.Background(), d)
	_, err := Apply(context.Background(), d, reconnectTo(d), base, []string{"set interfaces ethernet eth0 bogus-knob 1"}, time.Millisecond)
	if !errors.As(err, new(NotLiveError)) || !strings.Contains(err.Error(), "Set failed") {
		t.Fatalf("err = %v", err)
	}
	for _, s := range *sent {
		if strings.Contains(s, "commit-confirm 5") {
			t.Fatal("committed after a refusal")
		}
	}
}

func TestApplyWhilePending(t *testing.T) {
	d, _ := newRouter()
	*d.pending = true
	base, _ := RunningConfig(context.Background(), d)
	_, err := Apply(context.Background(), d, reconnectTo(d), base, []string{"set system host-name r2"}, time.Millisecond)
	if !errors.Is(err, ErrPending) {
		t.Fatalf("err = %v", err)
	}
}

func TestApplyWhenTheConfirmCantLogIn(t *testing.T) {
	d, _ := newRouter()
	base, _ := RunningConfig(context.Background(), d)
	gone := func(context.Context) (Device, error) { return nil, errors.New("i/o timeout") }
	_, err := Apply(context.Background(), d, gone, base, []string{"set system host-name r2"}, time.Millisecond)
	if err == nil || errors.As(err, new(NotLiveError)) || !strings.Contains(err.Error(), "rolls the change back") {
		t.Fatalf("err = %v", err)
	}
}

func TestInterface(t *testing.T) {
	d, _ := newRouter()
	config, _ := RunningConfig(context.Background(), d)
	desc := "uplink to core"
	i := Interface{Name: "eth0", Description: &desc, Addresses: []string{"192.0.2.10/24", "2001:db8::1/64"}, MTU: 9000}
	want := []string{
		`set interfaces ethernet eth0 description "uplink to core"`,
		"set interfaces ethernet eth0 mtu 9000",
		"set interfaces ethernet eth0 address 2001:db8::1/64",
	}
	if got := i.Commands(config); !slices.Equal(got, want) {
		t.Errorf("Commands:\n%q\nwant\n%q", got, want)
	}
	off := false
	if err := (Interface{Name: "eth0", Enabled: &off}).Guard(config, "192.0.2.10"); err == nil {
		t.Error("disabled the interface Conn3x connects through")
	}
	if err := (Interface{Name: "eth0", Addresses: []string{"198.51.100.1/24"}}).Guard(config, "192.0.2.10"); err == nil {
		t.Error("took Conn3x's own address off")
	}
	for _, bad := range []Interface{{Name: "ge-0/0/1"}, {Name: "eth0", Addresses: []string{"192.0.2.1"}}, {Name: "eth0", MTU: 20000}} {
		if bad.Validate() == nil {
			t.Errorf("%+v passed", bad)
		}
	}
}

func TestFactsAndReboot(t *testing.T) {
	d, _ := newRouter()
	f, err := ReadFacts(context.Background(), d)
	if err != nil || f.Hostname != "r1" || f.Version != "VyOS 2026.11.13-0016-rolling" {
		t.Fatalf("facts %+v, %v", f, err)
	}
	config, _ := RunningConfig(context.Background(), d)
	if RebootsOnRollback(config) {
		t.Error("action reload read as reboot")
	}
	if !RebootsOnRollback("set system host-name r1\n") {
		t.Error("the default, reboot, wasn't noticed")
	}
}

func TestStaticRoute(t *testing.T) {
	r := StaticRoute{Prefix: "10.20.0.0/16", NextHops: []string{"192.0.2.1", "192.0.2.2"}, Distance: 10}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	config := "set protocols static route 10.20.0.0/16 next-hop 192.0.2.1 distance '10'\nset protocols static route 10.20.0.0/16 next-hop 192.0.2.9\nset protocols static route 10.200.0.0/16 next-hop 192.0.2.1\n"
	norm := ""
	for _, l := range strings.Split(strings.TrimSpace(config), "\n") {
		norm += Normalize(l) + "\n"
	}
	want := []string{
		"delete protocols static route 10.20.0.0/16 next-hop 192.0.2.9",
		"set protocols static route 10.20.0.0/16 next-hop 192.0.2.2 distance 10",
	}
	if got := r.Commands(norm); !slices.Equal(got, want) {
		t.Errorf("commands %q, want %q", got, want)
	}
	// What the lab router showed: deleting a hop's distance leaves the hop,
	// so a hop that's not wanted goes whole.
	one := StaticRoute{Prefix: "10.20.0.0/16", NextHops: []string{"192.0.2.1"}}
	both := "set protocols static route 10.20.0.0/16 next-hop 192.0.2.1 distance 10\nset protocols static route 10.20.0.0/16 next-hop 192.0.2.2 distance 10\nset protocols static route 10.20.0.0/16 blackhole\n"
	if got := one.Commands(both); !slices.Equal(got, []string{
		"delete protocols static route 10.20.0.0/16 blackhole",
		"delete protocols static route 10.20.0.0/16 next-hop 192.0.2.2",
		"delete protocols static route 10.20.0.0/16 next-hop 192.0.2.1 distance",
	}) {
		t.Errorf("one hop, no distance: %q", got)
	}
	if got := one.Commands("set protocols static route 10.20.0.0/16 next-hop 192.0.2.1\n"); got != nil {
		t.Errorf("in sync, but %q", got)
	}
	if got := r.RemoveCommands(norm); !slices.Equal(got, []string{"delete protocols static route 10.20.0.0/16"}) {
		t.Errorf("remove %q", got)
	}
	if v6 := (StaticRoute{Prefix: "2001:db8:20::/48", NextHops: []string{"2001:db8::1"}}); v6.Validate() != nil || !strings.HasPrefix(v6.Commands("")[0], "set protocols static route6 2001:db8:20::/48 next-hop 2001:db8::1") {
		t.Errorf("v6: %v %q", v6.Validate(), v6.Commands(""))
	}
	for _, bad := range []StaticRoute{
		{Prefix: "10.20.0.1/16", NextHops: []string{"192.0.2.1"}},
		{Prefix: "10.20.0.0/16"},
		{Prefix: "10.20.0.0/16", NextHops: []string{"2001:db8::1"}},
		{Prefix: "10.20.0.0/16", NextHops: []string{"gw"}},
		{Prefix: "10.20.0.0/16", NextHops: []string{"192.0.2.1"}, Distance: 256},
		{Prefix: "10.20.0.0", NextHops: []string{"192.0.2.1"}},
	} {
		if bad.Validate() == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}
