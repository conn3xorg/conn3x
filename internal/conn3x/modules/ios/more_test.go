// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package ios

import (
	"context"
	"slices"
	"strings"
	"testing"
)

// A device with no Close is used as it is, and a script dials too.
func TestPerCommandShellWithoutClose(t *testing.T) {
	f := &fakeIOS{}
	d := PerCommand(func(context.Context) (Device, error) { return f, nil })
	if out, err := run(context.Background(), d, "", script("show clock")); err != nil || !strings.Contains(out, "r2#show clock") {
		t.Errorf("%q, %v", out, err)
	}
	if len(f.scripts) != 1 {
		t.Errorf("scripts %q", f.scripts)
	}
}

// The confirm's connection is closed once it has confirmed.
func TestConfirmClosesItsConnection(t *testing.T) {
	f := &fakeIOS{show: map[string]string{"show running-config": showRun}}
	base, _ := RunningConfig(context.Background(), f)
	closed := 0
	reconnect := func(context.Context) (Device, error) { return closingIOS{f, &closed}, nil }
	if _, err := Apply(context.Background(), f, reconnect, base, []string{"hostname r3"}, 0); err != nil || closed != 1 {
		t.Errorf("%v, closed %d", err, closed)
	}
}

func TestConfigEdges(t *testing.T) {
	// An indent deeper than the block it's in goes under the last line.
	got := WithLines("hostname r2\n", []string{"interface Loopback2", "   description deep"})
	if !(Config{Parents: []string{"interface Loopback2"}, Lines: []string{"description deep"}}).InSync(got) {
		t.Errorf("got:\n%s", got)
	}
	for want, c := range map[string]Config{
		"match must be":             {Lines: []string{"hostname r2"}, Match: "all"},
		"must not be empty strings": {Lines: []string{" "}},
	} {
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%+v: %v, want %q", c, err, want)
		}
	}
	// Only the lines still there are removed; none left is nil.
	c := Config{Lines: []string{"hostname r2", "ntp server 192.0.2.1"}}
	if got := c.RemoveCommands("hostname r2\n"); !slices.Equal(got, []string{"no hostname r2"}) {
		t.Errorf("remove: %q", got)
	}
	if got := c.RemoveCommands("version 17\n"); got != nil {
		t.Errorf("nothing left: %q", got)
	}
}

// The hostname line is matched at the top level only, and without case,
// since Cisco doesn't promise to keep it.
func TestHostname(t *testing.T) {
	running := "version 17.18\nhostname Edge01\n!\ninterface GigabitEthernet1\n hostname not-this\n"
	for name, want := range map[string]bool{"edge01": true, "EDGE01": true, "edge02": false, "not-this": false} {
		if got := (Hostname{Name: name}).InSync(running); got != want {
			t.Errorf("%s: InSync = %v", name, got)
		}
	}
	if got := (Hostname{Name: "edge02"}).Commands(running); !slices.Equal(got, []string{"hostname edge02"}) {
		t.Errorf("Commands = %q", got)
	}
	if got := (Hostname{Name: "edge01"}).Commands(running); got != nil {
		t.Errorf("in sync, Commands = %q", got)
	}
	if got := (Hostname{Name: "r1"}).Commands("version 17.18\n"); !slices.Equal(got, []string{"hostname r1"}) {
		t.Errorf("no hostname line, Commands = %q", got)
	}
}

func TestValidateHostname(t *testing.T) {
	for _, ok := range []string{"r", "edge01", "core-sw-1", strings.Repeat("a", 63)} {
		if err := ValidateHostname(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "123", "1edge", "edge-", "edge.lab", "edge_01", "edge 01", `\99`, strings.Repeat("a", 64)} {
		if err := ValidateHostname(bad); err == nil {
			t.Errorf("%q: no error", bad)
		}
	}
}
