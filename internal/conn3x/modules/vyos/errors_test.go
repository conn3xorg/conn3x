// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package vyos

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

func TestApplyPassesOnEveryLostCall(t *testing.T) {
	for n, want := range []string{
		"connection lost. Nothing was changed", // pending
		"connection lost. Nothing was changed", // check
		"connection lost. Nothing was changed", // config read
		"the session ended before VyOS said",
		"couldn't confirm it over a new connection",
	} {
		d, _ := newRouter()
		base, _ := RunningConfig(context.Background(), d)
		f := &failAt{d, n}
		_, err := Apply(context.Background(), f, func(context.Context) (Device, error) { return f, nil }, base, []string{"set system host-name 'r2'"}, 0)
		if !errors.Is(err, errLost) || !strings.Contains(err.Error(), want) {
			t.Errorf("losing call %d: %v, want %q", n, err, want)
		}
	}
}

// closer is a router that records its Close.
type closer struct {
	Device
	closed *bool
}

func (c closer) Close() error { *c.closed = true; return nil }

func TestConfirmClosesItsConnection(t *testing.T) {
	d, _ := newRouter()
	base, _ := RunningConfig(context.Background(), d)
	var closed bool
	if _, err := Apply(context.Background(), d, reconnectTo(closer{d, &closed}), base, []string{"set system host-name 'r2'"}, 0); err != nil || !closed {
		t.Errorf("%v, closed %v", err, closed)
	}
}

// says answers every call with out.
type says string

func (s says) RunRaw(context.Context, string, []byte) (ssh.Result, error) {
	return ssh.Result{Stdout: []byte(s)}, nil
}

func TestReadFactsOddAnswers(t *testing.T) {
	ctx := context.Background()
	if _, err := ReadFacts(ctx, says("Release train: rolling\n")); err == nil || err.Error() != "show version didn't say a version; is this VyOS?" {
		t.Errorf("no version: %v", err)
	}
	d, _ := newRouter()
	if _, err := ReadFacts(ctx, &failAt{d, 1}); !errors.Is(err, errLost) {
		t.Errorf("config read lost: %v", err)
	}
	if _, err := RunningConfig(ctx, &failAt{d, 0}); !errors.Is(err, errLost) {
		t.Errorf("RunningConfig lost: %v", err)
	}
}
