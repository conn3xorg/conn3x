// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package junos

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// failAt passes calls to d until the nth (from 0), which fails with
// errLost as a dropped connection does.
type failAt struct {
	d Device
	n int
}

var errLost = errors.New("connection lost")

func (f *failAt) RunRaw(ctx context.Context, cmd string, stdin []byte) (ssh.Result, error) {
	if f.n--; f.n == -1 {
		return ssh.Result{}, errLost
	}
	return f.d.RunRaw(ctx, cmd, stdin)
}

func (f *failAt) RunShell(ctx context.Context, stdin []byte) (ssh.Result, error) {
	return f.RunRaw(ctx, "", stdin)
}

// says answers every call with out.
type says string

func (s says) RunRaw(context.Context, string, []byte) (ssh.Result, error) {
	return ssh.Result{Stdout: []byte(s)}, nil
}
func (s says) RunShell(ctx context.Context, stdin []byte) (ssh.Result, error) {
	return s.RunRaw(ctx, "", stdin)
}

func TestApplyPassesOnEveryLostCall(t *testing.T) {
	for n, want := range []string{
		"connection lost",                      // the dry run: nothing live
		"connection lost. Nothing was changed", // the config read
		"the session ended before Junos said",  // the live pass
		"couldn't confirm it over a new connection",
	} {
		d, _ := newFake()
		f := &failAt{d, n}
		_, err := Apply(context.Background(), f, func(context.Context) (Device, error) { return f, nil }, *d.config, []string{"set system host-name sw2"}, 0)
		if !errors.Is(err, errLost) || !strings.Contains(err.Error(), want) {
			t.Errorf("losing call %d: %v, want %q", n, err, want)
		}
	}
	if diff, err := Apply(context.Background(), nil, nil, "", nil, 0); diff != "" || err != nil {
		t.Errorf("nothing to do: %q, %v", diff, err)
	}
}

// What the device prints, when it isn't what Conn3x looks for, fails the
// step with its last lines.
func TestCheckAndConfirmNeedTheirWords(t *testing.T) {
	ctx := context.Background()
	long := "Entering configuration mode\n1\n2\n3\n4\n5\n6\n"
	if err := Check(ctx, says(long), nil); err == nil || !strings.Contains(err.Error(), "didn't say the configuration checks out: 2 | 3 | 4 | 5 | 6") {
		t.Errorf("check: %v", err)
	}
	// The live pass printed neither an error nor commit complete.
	d, _ := newFake()
	var calls int
	odd := &scripted{d: d, at: 2, out: "Entering configuration mode\nexclusive\n", calls: &calls}
	if _, err := Apply(ctx, odd, reconnectTo(d), *d.config, []string{"set system host-name sw2"}, 0); err == nil || !strings.Contains(err.Error(), "the commit didn't complete: Entering configuration mode | exclusive. Nothing was changed") {
		t.Errorf("no commit complete: %v", err)
	}
	// The confirm's commit check doesn't say it succeeds.
	if _, err := Apply(ctx, d, reconnectTo(says("Entering configuration mode\n")), *d.config, []string{"set system host-name sw2"}, 0); err == nil || !strings.Contains(err.Error(), "the confirm wasn't taken") {
		t.Errorf("confirm: %v", err)
	}
	if _, err := Pending(ctx, &failAt{d, 0}); !errors.Is(err, errLost) {
		t.Errorf("pending: %v", err)
	}
}

// scripted is d, except call number at (from 0) gets out.
type scripted struct {
	d     Device
	at    int
	out   string
	calls *int
}

func (s *scripted) RunRaw(ctx context.Context, cmd string, stdin []byte) (ssh.Result, error) {
	n := *s.calls
	*s.calls++
	if n == s.at {
		return ssh.Result{Stdout: []byte(s.out)}, nil
	}
	return s.d.RunRaw(ctx, cmd, stdin)
}
func (s *scripted) RunShell(ctx context.Context, stdin []byte) (ssh.Result, error) {
	return s.RunRaw(ctx, "", stdin)
}

func TestReadFactsOddAnswers(t *testing.T) {
	ctx := context.Background()
	if _, err := ReadFacts(ctx, &failAt{says(""), 0}); !errors.Is(err, errLost) {
		t.Errorf("lost: %v", err)
	}
	for _, out := range []string{"not json", `{"software-information": []}`} {
		if _, err := ReadFacts(ctx, says(out)); err == nil || !strings.Contains(err.Error(), "is this Junos?") {
			t.Errorf("%q: %v", out, err)
		}
	}
	// The CLI may echo the command first, and a field may be missing.
	f, err := ReadFacts(ctx, says("show version | display json\n"+`{"software-information": [{"host-name": [{"data": "sw1"}], "product-model": []}]}`))
	if err != nil || f != (Facts{Hostname: "sw1"}) {
		t.Errorf("got %+v, %v", f, err)
	}
}

// closer is a device that records its Close.
type closer struct {
	Device
	closed *bool
}

func (c closer) Close() error { *c.closed = true; return nil }

// The confirm's connection is closed once it has confirmed.
func TestConfirmClosesItsConnection(t *testing.T) {
	d, _ := newFake()
	var closed bool
	if _, err := Apply(context.Background(), d, reconnectTo(closer{d, &closed}), *d.config, []string{"set system host-name sw2"}, 0); err != nil || !closed {
		t.Errorf("%v, closed %v", err, closed)
	}
}
