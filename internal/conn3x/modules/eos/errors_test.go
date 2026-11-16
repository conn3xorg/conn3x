// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package eos

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// failAt passes commands to d until the nth (from 0), which fails with
// errLost as a dropped connection does.
type failAt struct {
	d Device
	n int
}

var errLost = errors.New("connection lost")

func (f *failAt) RunRaw(ctx context.Context, cmd string, stdin []byte) (ssh.Result, error) {
	f.n--
	if f.n == -1 {
		return ssh.Result{}, errLost
	}
	return f.d.RunRaw(ctx, cmd, stdin)
}

// Whichever command the connection drops on, Apply says so: nothing it
// sends is taken as done once one is lost.
func TestApplyPassesOnEveryLostCommand(t *testing.T) {
	for n := range 8 {
		var sent []string
		f := &failAt{fakeSwitch{name: "pool", sent: &sent}, n}
		reconnect := func(context.Context) (Device, error) { return f, nil } // the same count goes on
		if _, err := Apply(context.Background(), f, reconnect, "", []string{"hostname leaf1"}, 0); !errors.Is(err, errLost) {
			t.Errorf("losing command %d: %v", n, err)
		}
		// Up to the commit, nothing is live and the session is aborted.
		if n >= 1 && n <= 5 && !strings.Contains(strings.Join(sent, "\n"), " abort") {
			t.Errorf("losing command %d left the session: %q", n, sent)
		}
	}
	// The confirm and the save fail with what that means for the switch.
	for n, want := range map[int]string{6: "will roll the change back on its own", 7: "the change is live but wasn't saved"} {
		var sent []string
		f := &failAt{fakeSwitch{name: "pool", sent: &sent}, n}
		_, err := Apply(context.Background(), f, func(context.Context) (Device, error) { return f, nil }, "", []string{"hostname leaf1"}, 0)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("losing command %d: %v, want %q", n, err, want)
		}
	}
}

// A lost connection while reading facts fails the read; only a refusal
// leaves a list empty.
func TestReadFactsLost(t *testing.T) {
	j := jsonSwitch{
		"show version | json":           `{"modelName":"cEOSLab"}`,
		"show hostname | json":          `{"hostname":"leaf1"}`,
		"show interfaces status | json": `{}`,
		"show lldp neighbors | json":    `{}`,
	}
	for n := range 4 {
		if _, err := ReadFacts(context.Background(), &failAt{j, n}); !errors.Is(err, errLost) {
			t.Errorf("losing read %d: %v", n, err)
		}
	}
}

// A failed abort says how to clear the session by hand.
func TestAbortFails(t *testing.T) {
	s := &Session{Name: "conn3x-1", started: true}
	err := s.Abort(context.Background(), &failAt{jsonSwitch{}, 0})
	if !errors.Is(err, errLost) || !strings.Contains(err.Error(), `remove it by hand with "configure session conn3x-1 abort"`) {
		t.Errorf("got %v", err)
	}
	if err := (&Session{}).Abort(context.Background(), nil); err != nil {
		t.Errorf("a session never started: %v", err)
	}
}

// With no enable password, only enable and the command go in.
func TestEnableWithoutPassword(t *testing.T) {
	var got string
	d := recordStdin{&got}
	if _, err := (Enable{Device: d}).RunRaw(context.Background(), "show version", nil); err != nil {
		t.Fatal(err)
	}
	if got != "enable\nshow version\n" {
		t.Errorf("sent %q", got)
	}
}

type recordStdin struct{ got *string }

func (r recordStdin) RunRaw(_ context.Context, _ string, stdin []byte) (ssh.Result, error) {
	*r.got = string(stdin)
	return ssh.Result{}, nil
}

func TestUserGuardRole(t *testing.T) {
	if err := (User{Name: "ops", Privilege: 15, Role: "network-admin"}).Guard("ops"); err != nil {
		t.Error(err)
	}
	if err := (User{Name: "ops", Privilege: 15, Role: "network-operator"}).Guard("ops"); err == nil || !strings.Contains(err.Error(), "a role other than network-admin") {
		t.Errorf("got %v", err)
	}
	if p, role, _, _ := fields("username ops privilege"); p != 1 || role != "" {
		t.Errorf("a line cut short: %d %q", p, role)
	}
	if _, role, _, _ := fields("username ops role"); role != "" {
		t.Errorf("role with no value: %q", role)
	}
}

// closer is a switch that records its Close.
type closer struct {
	Device
	closed *bool
}

func (c closer) Close() error { *c.closed = true; return nil }

// The confirm's connection is closed once it has confirmed.
func TestConfirmClosesItsConnection(t *testing.T) {
	var sent []string
	d := fakeSwitch{name: "pool", sent: &sent}
	var closed bool
	reconnect := func(context.Context) (Device, error) { return closer{d, &closed}, nil }
	if _, err := Apply(context.Background(), d, reconnect, "", []string{"hostname leaf1"}, 0); err != nil || !closed {
		t.Errorf("%v, closed %v", err, closed)
	}
}
