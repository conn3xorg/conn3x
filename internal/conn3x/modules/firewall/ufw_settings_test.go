// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package firewall

import (
	"net"
	"slices"
	"testing"
)

func on(b bool) *bool { return &b }

func TestParseUFWState(t *testing.T) {
	st, err := parseUFWState("incoming=DROP\noutgoing=ACCEPT\nrouted=REJECT\nboot=yes\nstatus=Status: active\n")
	if err != nil || st != (UFWState{Active: true, Incoming: "deny", Outgoing: "allow", Routed: "reject"}) {
		t.Errorf("active: %+v, %v", st, err)
	}
	// Running but not enabled at boot, or the reverse, isn't on.
	for _, out := range []string{
		"incoming=DROP\noutgoing=ACCEPT\nrouted=DROP\nboot=no\nstatus=Status: active\n",
		"incoming=DROP\noutgoing=ACCEPT\nrouted=DROP\nboot=yes\nstatus=Status: inactive\n",
	} {
		if st, err := parseUFWState(out); err != nil || st.Active {
			t.Errorf("%q: %+v, %v", out, st, err)
		}
	}
	for _, bad := range []string{"incoming=\noutgoing=ACCEPT\nrouted=DROP\n", "incoming=QUEUE\noutgoing=ACCEPT\nrouted=DROP\n"} {
		if _, err := parseUFWState(bad); err == nil {
			t.Errorf("%q was read", bad)
		}
	}
}

func TestUFWSettingsCommands(t *testing.T) {
	off := UFWState{Incoming: "allow", Outgoing: "allow", Routed: "deny"}
	do, undo := UFWSettings{Enabled: on(true), Incoming: "deny"}.Commands(off)
	wantDo := []string{"flock /run/conn3x-ufw.lock ufw default deny incoming", "flock /run/conn3x-ufw.lock ufw --force enable"}
	wantUndo := []string{"flock /run/conn3x-ufw.lock ufw disable", "flock /run/conn3x-ufw.lock ufw default allow incoming"}
	if !slices.Equal(do, wantDo) || !slices.Equal(undo, wantUndo) {
		t.Errorf("enable with deny:\n%q\n%q", do, undo)
	}
	if do, _ := (UFWSettings{Enabled: on(false), Routed: "deny"}).Commands(off); len(do) != 0 {
		t.Errorf("already off and deny routed: %q", do)
	}
	if !(UFWSettings{Outgoing: "allow"}).Matches(off) || (UFWSettings{Enabled: on(true)}).Matches(off) {
		t.Error("Matches")
	}
	for _, bad := range []UFWSettings{{}, {Incoming: "drop"}, {Routed: "DENY"}} {
		if bad.Validate() == nil {
			t.Errorf("%+v passed", bad)
		}
	}
}

func TestUFWLocksOut(t *testing.T) {
	off := UFWState{Incoming: "deny", Outgoing: "allow", Routed: "deny"}
	enable := UFWSettings{Enabled: on(true)}
	for _, c := range []struct {
		name  string
		s     UFWSettings
		st    UFWState
		added string
		ports []int
		want  bool
		peer  *SSHPeer // nil: a remote client, 198.51.100.7
	}{
		{"no rules", enable, off, "", []int{22}, true, nil},
		{"22/tcp", enable, off, "ufw allow 22/tcp\n", []int{22}, false, nil},
		{"22", enable, off, "ufw allow 22\n", []int{22}, false, nil},
		{"limit", enable, off, "ufw limit 22/tcp\n", []int{22}, false, nil},
		{"from a network that has the client", enable, off, "ufw allow from 198.51.100.0/24 to any port 22 proto tcp\n", []int{22}, false, nil},
		{"from one address, the client's", enable, off, "ufw allow from 198.51.100.7 to any port 22\n", []int{22}, false, nil},
		{"from a network without the client", enable, off, "ufw allow from 10.0.0.0/8 to any port 22 proto tcp\n", []int{22}, true, nil},
		{"from another network, over loopback", enable, off, "ufw allow from 203.0.113.0/24 to any port 22 proto tcp\n", []int{22}, false, &SSHPeer{Client: net.ParseIP("10.0.2.100"), Local: true}},
		{"from a network, client unknown", enable, off, "ufw allow from 198.51.100.0/24 to any port 22 proto tcp\n", []int{22}, true, &SSHPeer{}},
		{"no from, client unknown", enable, off, "ufw allow 22/tcp\n", []int{22}, false, &SSHPeer{}},
		{"from any", enable, off, "ufw allow from any to any port 22 proto tcp\n", []int{22}, false, nil},
		{"OpenSSH", enable, off, "ufw allow OpenSSH\n", []int{22}, false, nil},
		{"OpenSSH, another port", enable, off, "ufw allow OpenSSH\n", []int{2222}, true, nil},
		{"a range", enable, off, "ufw allow 2000:3000/tcp\n", []int{2222}, false, nil},
		{"udp only", enable, off, "ufw allow 22/udp\n", []int{22}, true, nil},
		{"deny", enable, off, "ufw deny 22/tcp\n", []int{22}, true, nil},
		{"out", enable, off, "ufw allow out 22/tcp\n", []int{22}, true, nil},
		{"udp from", enable, off, "ufw allow from 10.0.0.1 to any port 22 proto udp\n", []int{22}, true, nil},
		{"either port", enable, off, "ufw allow 2222/tcp\n", []int{22, 2222}, false, nil},
		{"incoming allowed", UFWSettings{Enabled: on(true), Incoming: "allow"}, off, "", []int{22}, false, nil},
		{"turning off", UFWSettings{Enabled: on(false)}, UFWState{Active: true, Incoming: "deny"}, "", []int{22}, false, nil},
		{"deny while on", UFWSettings{Incoming: "deny"}, UFWState{Active: true, Incoming: "allow"}, "", []int{22}, true, nil},
		{"already on and denying", UFWSettings{Outgoing: "deny"}, UFWState{Active: true, Incoming: "deny"}, "", []int{22}, false, nil},
		{"deny while off", UFWSettings{Incoming: "deny"}, UFWState{Incoming: "allow"}, "", []int{22}, false, nil},
	} {
		peer := SSHPeer{Client: net.ParseIP("198.51.100.7")}
		if c.peer != nil {
			peer = *c.peer
		}
		if got := c.s.LocksOut(c.st, c.added, c.ports, peer); got != c.want {
			t.Errorf("%s: %t, want %t", c.name, got, c.want)
		}
	}
}

func TestParseSSHConnection(t *testing.T) {
	for v, want := range map[string]SSHPeer{
		"198.51.100.7 51000 203.0.113.5 22": {Client: net.ParseIP("198.51.100.7")},
		"10.0.2.100 54778 10.0.2.100 22":    {Client: net.ParseIP("10.0.2.100"), Local: true},
		"::1 40000 ::1 22":                  {Client: net.ParseIP("::1"), Local: true},
		"":                                  {},
		"nonsense":                          {},
		"x 1 y 22":                          {},
	} {
		got := ParseSSHConnection(v)
		if !got.Client.Equal(want.Client) || got.Local != want.Local {
			t.Errorf("%q: %+v, want %+v", v, got, want)
		}
	}
}
