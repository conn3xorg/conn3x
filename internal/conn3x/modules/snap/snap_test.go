// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package snap

import (
	"context"
	"strings"
	"testing"

	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

func TestValidate(t *testing.T) {
	for _, ok := range []Snap{
		{Name: "lxd"},
		{Name: "hello-world", Channel: "edge"},
		{Name: "microk8s", Channel: "1.28/stable", Classic: true},
		{Name: "0ad", Channel: "latest/edge/fix-123"},
	} {
		if err := ok.Validate(); err != nil {
			t.Errorf("%+v: %v", ok, err)
		}
	}
	for _, bad := range []Snap{
		{Name: ""},
		{Name: "LXD"},
		{Name: "-lxd"},
		{Name: "lxd--core"},
		{Name: "lxd; reboot"},
		{Name: "lxd", Channel: "-stable"},
		{Name: "lxd", Channel: "a/b/c/d"},
		{Name: "lxd", Channel: "latest/stable "},
	} {
		if bad.Validate() == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}

func TestFullChannel(t *testing.T) {
	for in, want := range map[string]string{
		"stable":          "latest/stable",
		"edge":            "latest/edge",
		"5.21":            "5.21/stable",
		"latest":          "latest/stable",
		"1.28/stable":     "1.28/stable",
		"edge/fix":        "latest/edge/fix",
		"latest/edge/fix": "latest/edge/fix",
	} {
		if got := fullChannel(in); got != want {
			t.Errorf("fullChannel(%q) = %q, want %q", in, got, want)
		}
	}
}

// Real snap list output, as --unicode=never prints it.
const helloList = `Name         Version  Rev  Tracking       Publisher    Notes
hello-world  6.4      29   latest/stable  canonical**  -
`

const codeList = `Name  Version   Rev  Tracking       Publisher  Notes
code  5ec3b3a9  187  latest/stable  vscode**   classic,disabled
`

func TestParseList(t *testing.T) {
	a, err := parseList(helloList, "hello-world")
	if err != nil || !a.Installed || a.Tracking != "latest/stable" || a.Classic {
		t.Errorf("hello-world: %+v, %v", a, err)
	}
	a, err = parseList(codeList, "code")
	if err != nil || !a.Installed || !a.Classic {
		t.Errorf("code: %+v, %v", a, err)
	}
	if a, err := parseList(helloList, "hello"); err != nil || a.Installed {
		t.Errorf("another name matched: %+v, %v", a, err)
	}
	if _, err := parseList("hello-world 6.4\n", "hello-world"); err == nil {
		t.Error("accepted a row without the six columns")
	}

	s := Snap{Name: "hello-world"}
	if !s.InSync(Actual{Installed: true, Tracking: "latest/stable"}) {
		t.Error("out of sync with no channel asked for")
	}
	s.Channel = "stable"
	if !s.InSync(Actual{Installed: true, Tracking: "latest/stable"}) {
		t.Error("stable doesn't match latest/stable")
	}
	s.Channel = "edge"
	if s.InSync(Actual{Installed: true, Tracking: "latest/stable"}) {
		t.Error("in sync on the wrong channel")
	}
	s = Snap{Name: "code", Classic: true}
	if s.InSync(Actual{Installed: true, Tracking: "latest/stable"}) {
		t.Error("in sync while strict and classic is wanted")
	}
	s.Classic = false
	if !s.InSync(Actual{Installed: true, Tracking: "latest/stable", Classic: true}) {
		t.Error("a classic snap must satisfy classic = false")
	}
}

// fakeHost answers snap list from rows and records everything else, after
// which the snap reads as installed on the channel asked for.
type fakeHost struct {
	rows     string
	noSnap   bool
	stderr   string
	ran      []string
	afterRun string
}

func (h *fakeHost) Run(_ context.Context, cmd string, _ []byte) (ssh.Result, error) {
	if h.noSnap && strings.Contains(cmd, "command -v snap") {
		return ssh.Result{Stderr: []byte("snapd isn't installed on this host; install the snapd package"), ExitCode: 3}, nil
	}
	if strings.Contains(cmd, "snap list") {
		if h.stderr != "" {
			return ssh.Result{Stderr: []byte(h.stderr), ExitCode: 1}, nil
		}
		if h.rows == "" {
			return ssh.Result{Stderr: []byte("error: no matching snaps installed"), ExitCode: 1}, nil
		}
		return ssh.Result{Stdout: []byte(h.rows)}, nil
	}
	h.ran = append(h.ran, cmd)
	if h.afterRun != "" {
		h.rows = h.afterRun
	}
	return ssh.Result{}, nil
}

func TestApplyInstallsRefreshesOrLeavesAlone(t *testing.T) {
	ctx := context.Background()
	// Not installed: install, with the channel and confinement asked for.
	h := &fakeHost{afterRun: codeList}
	if err := Apply(ctx, h, Snap{Name: "code", Channel: "stable", Classic: true}); err != nil {
		t.Fatal(err)
	}
	if len(h.ran) != 1 || !strings.Contains(h.ran[0], "snap install --classic --channel='stable' 'code'") {
		t.Errorf("ran %q", h.ran)
	}
	// Installed on another channel: refresh onto the one asked for.
	edge := strings.Replace(helloList, "latest/stable", "latest/edge", 1)
	h = &fakeHost{rows: helloList, afterRun: edge}
	if err := Apply(ctx, h, Snap{Name: "hello-world", Channel: "edge"}); err != nil {
		t.Fatal(err)
	}
	if len(h.ran) != 1 || !strings.Contains(h.ran[0], "snap refresh --channel='edge' 'hello-world'") {
		t.Errorf("ran %q", h.ran)
	}
	// Already as asked: nothing runs.
	h = &fakeHost{rows: helloList}
	if err := Apply(ctx, h, Snap{Name: "hello-world", Channel: "latest/stable"}); err != nil || len(h.ran) != 0 {
		t.Errorf("err %v, ran %q", err, h.ran)
	}
	// snap exits 0 without changing anything: the read-back says so.
	h = &fakeHost{rows: helloList}
	if err := Apply(ctx, h, Snap{Name: "hello-world", Channel: "edge"}); err == nil || !strings.Contains(err.Error(), "exited 0") {
		t.Errorf("err = %v", err)
	}
	// Remove skips a snap that isn't there.
	h = &fakeHost{}
	if err := Remove(ctx, h, "hello-world"); err != nil || len(h.ran) != 0 {
		t.Errorf("remove: %v, ran %q", err, h.ran)
	}
	h = &fakeHost{rows: helloList}
	if err := Remove(ctx, h, "hello-world"); err != nil || len(h.ran) != 1 || !strings.Contains(h.ran[0], "snap remove 'hello-world'") {
		t.Errorf("remove: %v, ran %q", err, h.ran)
	}
}

func TestReadErrors(t *testing.T) {
	ctx := context.Background()
	// No snap command: the error names the package.
	if _, err := Read(ctx, &fakeHost{noSnap: true}, "lxd"); err == nil || !strings.Contains(err.Error(), "snapd package") {
		t.Errorf("err = %v", err)
	}
	// snapd not running is an error, not an absent snap.
	h := &fakeHost{stderr: `error: cannot communicate with server: Get "http://localhost/v2/snaps?...": dial unix /run/snapd.socket: connect: no such file or directory`}
	if _, err := Read(ctx, h, "lxd"); err == nil || !strings.Contains(err.Error(), "cannot communicate") {
		t.Errorf("err = %v", err)
	}
	// A name the regexp refuses never reaches the host.
	h = &fakeHost{}
	if _, err := Read(ctx, h, "lxd; reboot"); err == nil {
		t.Error("read accepted a bad name")
	}
	if err := Apply(ctx, h, Snap{Name: "lxd", Channel: "$(reboot)"}); err == nil {
		t.Error("apply accepted a bad channel")
	}
	if len(h.ran) != 0 {
		t.Errorf("ran %q", h.ran)
	}
}
