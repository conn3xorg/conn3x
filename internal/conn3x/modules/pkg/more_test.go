// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package pkg

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// down is a host whose connection is gone.
type down struct{}

var errLost = errors.New("connection lost")

func (down) Run(context.Context, string, []byte) (ssh.Result, error) { return ssh.Result{}, errLost }

func TestConnectionLostPassesOn(t *testing.T) {
	for name, err := range map[string]error{
		"detect":     func() error { _, err := DetectFamily(ctx, down{}); return err }(),
		"read rpm":   func() error { _, err := Read(ctx, down{}, RPM, "bash", true); return err }(),
		"read deb":   func() error { _, err := Read(ctx, down{}, Deb, "bash", true); return err }(),
		"hold":       func() error { _, err := ReadHold(ctx, down{}, Deb, "bash"); return err }(),
		"apply":      Apply(ctx, down{}, RPM, Desired{Name: "bash", State: Present}),
		"inventory":  func() error { _, err := Inventory(ctx, down{}, Deb); return err }(),
		"apply hold": ApplyHold(ctx, down{}, Deb, Hold{Name: "bash"}),
		"apply held": ApplyHold(ctx, down{}, RPM, Hold{Name: "bash", Held: true}),
	} {
		if !errors.Is(err, errLost) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	// The candidate lookup fails after the installed one answered.
	h := &scriptedHost{answers: []answer{{"rpm -q", ok("0:1-1.x86_64\n")}}}
	if _, err := Read(ctx, &afterFirst{h}, RPM, "bash", true); !errors.Is(err, errLost) {
		t.Errorf("rpm candidate: %v", err)
	}
	h = &scriptedHost{answers: []answer{{"dpkg-query", ok("ii 1.0\n")}}}
	if _, err := Read(ctx, &afterFirst{h}, Deb, "bash", true); !errors.Is(err, errLost) {
		t.Errorf("deb candidate: %v", err)
	}
}

// afterFirst answers the first run with r, then loses the connection.
type afterFirst struct{ r *scriptedHost }

func (a *afterFirst) Run(ctx context.Context, cmd string, in []byte) (ssh.Result, error) {
	if len(a.r.ran) > 0 {
		return ssh.Result{}, errLost
	}
	return a.r.Run(ctx, cmd, in)
}

func TestReadEdges(t *testing.T) {
	// Installed, and the newest dnf knows of.
	h := &scriptedHost{answers: []answer{
		{"rpm -q", ok("0:1.0-1.el10.x86_64\n0:1.1-1.el10.x86_64\n")},
		{"repoquery", ok("0:1.2-1.el10\n")},
	}}
	a, err := Read(ctx, h, RPM, "kernel", true)
	if err != nil || !a.Installed || a.Version != "0:1.1-1.el10" || a.Candidate != "0:1.2-1.el10" {
		t.Errorf("rpm: %+v, %v", a, err)
	}
	h = &scriptedHost{answers: []answer{{"rpm -q", ok("\n")}, {"repoquery", ssh.Result{ExitCode: 1, Stderr: []byte("no repos\n")}}}}
	if _, err := Read(ctx, h, RPM, "bash", true); err == nil || err.Error() != "finding the newest bash: no repos" {
		t.Errorf("repoquery fails: %v", err)
	}
	// A package apt knows of but has nothing for.
	h = &scriptedHost{answers: []answer{
		{"dpkg-query", ok("un <none>\n")},
		{"apt-cache policy", ok("bash:\n  Installed: (none)\n  Candidate: (none)\n")},
	}}
	if a, err := Read(ctx, h, Deb, "bash", true); err != nil || a.Installed || a.Candidate != "" {
		t.Errorf("deb with no candidate: %+v, %v", a, err)
	}
	if _, err := Read(ctx, h, "apk", "bash", false); err == nil || !strings.Contains(err.Error(), `unknown package family "apk"`) {
		t.Errorf("unknown family: %v", err)
	}
	if _, err := Read(ctx, h, Deb, "-x", false); err == nil {
		t.Error("a bad name was read")
	}
	h = &scriptedHost{answers: []answer{{"/etc/os-release", ssh.Result{ExitCode: 1, Stderr: []byte("No such file\n")}}}}
	if _, err := DetectFamily(ctx, h); err == nil || err.Error() != "reading /etc/os-release: No such file" {
		t.Errorf("no os-release: %v", err)
	}
	for _, id := range []string{"ID=rhel\n", "ID=centos\n"} {
		if f, err := DetectFamily(ctx, &scriptedHost{answers: []answer{{"/etc/os-release", ok(id)}}}); err != nil || f != RPM {
			t.Errorf("%q: %v, %v", id, f, err)
		}
	}
}

func TestVersionMatches(t *testing.T) {
	for _, c := range []struct {
		actual, want string
		ok           bool
	}{
		{"1:1.26.3-2.el10", "1.26.3", true},
		{"1:1.26.3-2.el10", "1:1.26.3", true},
		{"1:1.26.3-2.el10", "2:1.26.3", false},
		{"1.26.3-2", "1.26.3-2", true},
		{"1.26.30-1", "1.26.3", false},
	} {
		if got := versionMatches(c.actual, c.want); got != c.ok {
			t.Errorf("versionMatches(%q, %q) = %v", c.actual, c.want, got)
		}
	}
	for _, bad := range []Desired{{Name: "x", State: Latest, Version: "1.0"}, {Name: "x", State: Present, Version: "1 0"}} {
		if bad.Validate() == nil {
			t.Errorf("%+v passed", bad)
		}
	}
}

func TestHoldFailures(t *testing.T) {
	h := &scriptedHost{answers: []answer{{"versionlock list", ssh.Result{ExitCode: 1, Stderr: []byte("No such command: versionlock.")}}}}
	if _, err := ReadHold(ctx, h, RPM, "bash"); err == nil || err.Error() != versionlockHint {
		t.Errorf("no plugin: %v", err)
	}
	h = &scriptedHost{answers: []answer{{"apt-mark", ssh.Result{ExitCode: 100, Stderr: []byte("E: locked\n")}}}}
	if _, err := ReadHold(ctx, h, Deb, "bash"); err == nil || err.Error() != "E: locked (exit status 100)" {
		t.Errorf("apt-mark fails: %v", err)
	}
	// Releasing with no plugin says what to install.
	h = &scriptedHost{answers: []answer{{"versionlock delete", ssh.Result{ExitCode: 1, Stderr: []byte("No such command: versionlock.")}}}}
	if err := ApplyHold(ctx, h, RPM, Hold{Name: "bash"}); err == nil || err.Error() != versionlockHint {
		t.Errorf("release with no plugin: %v", err)
	}
	h = &scriptedHost{answers: []answer{{"apt-mark unhold", ssh.Result{ExitCode: 1, Stderr: []byte("denied")}}}}
	if err := ApplyHold(ctx, h, Deb, Hold{Name: "bash"}); err == nil || err.Error() != "denied (exit status 1)" {
		t.Errorf("unhold fails: %v", err)
	}
	h = &scriptedHost{answers: []answer{{"apt-mark unhold", ok("")}, {"apt-mark showhold", ssh.Result{ExitCode: 1, Stderr: []byte("broken")}}}}
	if err := ApplyHold(ctx, h, Deb, Hold{Name: "bash"}); err == nil || err.Error() != "broken (exit status 1)" {
		t.Errorf("read back fails: %v", err)
	}
	h = &scriptedHost{answers: []answer{{"dpkg-query", ok("ii 5.2\n")}, {"apt-mark hold", ok("")}, {"apt-mark showhold", ok("bash\n")}}}
	if err := ApplyHold(ctx, h, Deb, Hold{Name: "bash", Held: true}); err != nil {
		t.Errorf("deb hold: %v", err)
	}
	if err := ApplyHold(ctx, h, Deb, Hold{Name: "-bad"}); err == nil {
		t.Error("a bad name was held")
	}
}

func TestInventoryEdges(t *testing.T) {
	if _, err := Inventory(ctx, down{}, "apk"); err == nil || err.Error() != `unknown package family "apk"` {
		t.Errorf("unknown family: %v", err)
	}
	h := &scriptedHost{answers: []answer{{"dpkg", ssh.Result{ExitCode: 2, Stderr: []byte("dpkg: error\n")}}}}
	if _, err := Inventory(ctx, h, Deb); err == nil || err.Error() != "listing installed packages: dpkg: error" {
		t.Errorf("dpkg fails: %v", err)
	}
	if _, err := parseInventory(Deb, "amd64\nbash\tamd64\n"); err == nil || !strings.Contains(err.Error(), "unexpected line") {
		t.Errorf("short line: %v", err)
	}
	got, err := parseInventory(RPM, "x86_64\nkernel\tx86_64\t0:6.1-2\nkernel\tx86_64\t0:6.1-10\nglibc\ti686\t0:2.39-1\n")
	if err != nil || strings.Join(got["kernel"], ",") != "0:6.1-2,0:6.1-10" || len(got["glibc.i686"]) != 1 {
		t.Errorf("rpm inventory: %v, %v", got, err)
	}
}
