// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package pkg

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// scriptedHost answers commands by substring and records what ran.
type scriptedHost struct {
	answers []answer
	ran     []string
}

type answer struct {
	contains string
	res      ssh.Result
}

func (h *scriptedHost) Run(_ context.Context, cmd string, _ []byte) (ssh.Result, error) {
	h.ran = append(h.ran, cmd)
	for _, a := range h.answers {
		if strings.Contains(cmd, a.contains) {
			return a.res, nil
		}
	}
	return ssh.Result{ExitCode: 127, Stderr: []byte("unexpected command: " + cmd)}, nil
}

func ok(out string) ssh.Result { return ssh.Result{Stdout: []byte(out)} }

const rockyRelease = "ID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"\nVERSION_ID=\"10.2\"\n"
const ubuntuRelease = "ID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"24.04\"\n"

var ctx = context.Background()

func TestDetectFamily(t *testing.T) {
	for release, want := range map[string]Family{
		rockyRelease:  RPM,
		ubuntuRelease: Deb,
		"ID=debian\n": Deb,
		"ID=fedora\n": RPM,
		"ID=almalinux\nID_LIKE=\"rhel centos fedora\"\n": RPM,
	} {
		h := &scriptedHost{answers: []answer{{"/etc/os-release", ok(release)}}}
		got, err := DetectFamily(ctx, h)
		if err != nil || got != want {
			t.Errorf("DetectFamily(%q) = %v, %v; want %v", release, got, err, want)
		}
	}
	h := &scriptedHost{answers: []answer{{"/etc/os-release", ok("ID=alpine\n")}}}
	if _, err := DetectFamily(ctx, h); err == nil || !strings.Contains(err.Error(), "alpine") {
		t.Errorf("unsupported distro error = %v", err)
	}
}

func TestReadRPM(t *testing.T) {
	h := &scriptedHost{answers: []answer{
		{"rpm -q", ok("1:1.26.3-2.el10.x86_64\n")},
	}}
	a, err := Read(ctx, h, RPM, "nginx", false)
	if err != nil {
		t.Fatal(err)
	}
	if !a.Installed || a.Version != "1:1.26.3-2.el10" {
		t.Fatalf("got %+v", a)
	}
	missing := &scriptedHost{answers: []answer{{"rpm -q", ssh.Result{ExitCode: 1, Stdout: []byte("package nginx is not installed\n")}}}}
	a, err = Read(ctx, missing, RPM, "nginx", false)
	if err != nil || a.Installed {
		t.Fatalf("missing package: %+v, %v", a, err)
	}
}

func TestReadDeb(t *testing.T) {
	h := &scriptedHost{answers: []answer{{"dpkg-query", ok("ii  1.24.0-2ubuntu7\n")}}}
	a, err := Read(ctx, h, Deb, "nginx", false)
	if err != nil || !a.Installed || a.Version != "1.24.0-2ubuntu7" {
		t.Fatalf("got %+v, %v", a, err)
	}
	// Held with apt-mark hold ("hi") is still installed.
	hi := &scriptedHost{answers: []answer{{"dpkg-query", ok("hi  1.24.0-2ubuntu7\n")}}}
	if a, _ := Read(ctx, hi, Deb, "nginx", false); !a.Installed || a.Version != "1.24.0-2ubuntu7" {
		t.Fatalf("held package: %+v", a)
	}
	// Removed but config left behind ("rc") is not installed.
	rc := &scriptedHost{answers: []answer{{"dpkg-query", ok("rc  1.24.0-2ubuntu7\n")}}}
	if a, _ := Read(ctx, rc, Deb, "nginx", false); a.Installed {
		t.Fatal("rc package reported as installed")
	}
	none := &scriptedHost{answers: []answer{{"dpkg-query", ssh.Result{ExitCode: 1, Stderr: []byte("dpkg-query: no packages found matching nginx\n")}}}}
	if a, err := Read(ctx, none, Deb, "nginx", false); err != nil || a.Installed {
		t.Fatalf("unknown package: %+v, %v", a, err)
	}
}

func TestReadLatestCandidate(t *testing.T) {
	rpm := &scriptedHost{answers: []answer{
		{"rpm -q", ok("0:1.26.3-2.el10.x86_64\n")},
		{"repoquery", ok("0:1.26.4-1.el10\n")},
	}}
	a, err := Read(ctx, rpm, RPM, "nginx", true)
	if err != nil || a.Candidate != "0:1.26.4-1.el10" {
		t.Fatalf("rpm candidate: %+v, %v", a, err)
	}
	deb := &scriptedHost{answers: []answer{
		{"dpkg-query", ok("ii  1.24.0-2ubuntu7\n")},
		{"apt-cache policy", ok("nginx:\n  Installed: 1.24.0-2ubuntu7\n  Candidate: 1.24.0-2ubuntu7.1\n  Version table:\n")},
	}}
	a, err = Read(ctx, deb, Deb, "nginx", true)
	if err != nil || a.Candidate != "1.24.0-2ubuntu7.1" {
		t.Fatalf("deb candidate: %+v, %v", a, err)
	}
}

func TestNeedsChange(t *testing.T) {
	for _, tc := range []struct {
		d    Desired
		a    Actual
		want bool
	}{
		{Desired{Name: "x", State: Present}, Actual{Installed: true, Version: "1"}, false},
		{Desired{Name: "x", State: Present}, Actual{}, true},
		{Desired{Name: "x", State: Absent}, Actual{}, false},
		{Desired{Name: "x", State: Absent}, Actual{Installed: true}, true},
		{Desired{Name: "x", State: Latest}, Actual{Installed: true, Version: "1", Candidate: "1"}, false},
		{Desired{Name: "x", State: Latest}, Actual{Installed: true, Version: "1", Candidate: "2"}, true},
		{Desired{Name: "x", State: Present, Version: "2"}, Actual{Installed: true, Version: "1"}, true},
		{Desired{Name: "x", State: Present, Version: "1"}, Actual{Installed: true, Version: "1"}, false},
	} {
		if got := NeedsChange(tc.d, tc.a); got != tc.want {
			t.Errorf("NeedsChange(%+v, %+v) = %v", tc.d, tc.a, got)
		}
	}
}

func TestApplyCommands(t *testing.T) {
	for _, tc := range []struct {
		family Family
		d      Desired
		want   []string
	}{
		{RPM, Desired{Name: "nginx", State: Present}, []string{"dnf -y install 'nginx'"}},
		{RPM, Desired{Name: "nginx", State: Present, Version: "1.26.3"}, []string{"dnf -y install 'nginx-1.26.3'"}},
		{RPM, Desired{Name: "nginx", State: Absent}, []string{"dnf -y remove 'nginx'"}},
		{RPM, Desired{Name: "nginx", State: Latest}, []string{"dnf -y install 'nginx'", "dnf -y upgrade 'nginx'"}},
		{Deb, Desired{Name: "nginx", State: Present}, []string{"apt-get", "install", "'nginx'", "DEBIAN_FRONTEND=noninteractive", "Lock::Timeout"}},
		{Deb, Desired{Name: "nginx", State: Present, Version: "1.24.0"}, []string{"'nginx=1.24.0'"}},
		{Deb, Desired{Name: "nginx", State: Absent}, []string{"apt-get", "remove", "'nginx'"}},
	} {
		h := &scriptedHost{answers: []answer{{"", ok("")}}}
		if err := Apply(ctx, h, tc.family, tc.d); err != nil {
			t.Fatalf("Apply(%v, %+v): %v", tc.family, tc.d, err)
		}
		all := strings.Join(h.ran, "\n")
		for _, w := range tc.want {
			if !strings.Contains(all, w) {
				t.Errorf("Apply(%v, %+v) ran %q, missing %q", tc.family, tc.d, all, w)
			}
		}
	}
}

func TestApplyDebRefreshesListsWhenPackageUnknown(t *testing.T) {
	calls := 0
	h := &fnHost{fn: func(cmd string) ssh.Result {
		if strings.Contains(cmd, "apt-get") && strings.Contains(cmd, "install") {
			calls++
			if calls == 1 {
				return ssh.Result{ExitCode: 100, Stderr: []byte("E: Unable to locate package nginx\n")}
			}
		}
		return ok("")
	}}
	if err := Apply(ctx, h, Deb, Desired{Name: "nginx", State: Present}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(h.ran, "\n"), "apt-get") || calls != 2 {
		t.Fatalf("expected an update and a retry, ran %v", h.ran)
	}
	found := false
	for _, c := range h.ran {
		if strings.Contains(c, "apt-get") && strings.Contains(c, " update") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no apt-get update before retry: %v", h.ran)
	}
}

func TestApplyFailureIsAnError(t *testing.T) {
	h := &scriptedHost{answers: []answer{{"dnf", ssh.Result{ExitCode: 1, Stderr: []byte("Error: Unable to find a match: nope\n")}}}}
	err := Apply(ctx, h, RPM, Desired{Name: "nope", State: Present})
	if err == nil || !strings.Contains(err.Error(), "Unable to find a match") {
		t.Fatalf("err = %v", err)
	}
}

func TestValidate(t *testing.T) {
	for _, bad := range []Desired{
		{Name: "", State: Present},
		{Name: "nginx; rm -rf /", State: Present},
		{Name: "-x", State: Present},
		{Name: "nginx", State: "installed"},
		{Name: "nginx", State: Absent, Version: "1"},
	} {
		if err := bad.Validate(); err == nil {
			t.Errorf("Validate(%+v) accepted", bad)
		}
	}
	if err := (Desired{Name: "python3.12-libs", State: Present, Version: "3.12.1"}).Validate(); err != nil {
		t.Errorf("valid desired rejected: %v", err)
	}
}

type fnHost struct {
	fn  func(string) ssh.Result
	ran []string
}

func (h *fnHost) Run(_ context.Context, cmd string, _ []byte) (ssh.Result, error) {
	h.ran = append(h.ran, cmd)
	return h.fn(cmd), nil
}

func TestApplyDebRefreshesListsWhenNoCandidate(t *testing.T) {
	calls := 0
	h := &fnHost{fn: func(cmd string) ssh.Result {
		if strings.Contains(cmd, " install ") {
			calls++
			if calls == 1 {
				return ssh.Result{ExitCode: 100, Stderr: []byte("E: Package 'cron' has no installation candidate\n")}
			}
		}
		return ok("")
	}}
	if err := Apply(ctx, h, Deb, Desired{Name: "cron", State: Present}); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("install ran %d times, want a retry after apt-get update", calls)
	}
}

// On Fedora, wget is a name that wget2-wget provides: dnf installs it, and
// rpm -q wget finds nothing.
func TestReadRPMVirtualProvide(t *testing.T) {
	h := &scriptedHost{answers: []answer{
		{"--whatprovides", ok("0:2.2.1-1.fc45.x86_64\n")},
		{"rpm -q", ssh.Result{ExitCode: 1, Stdout: []byte("package wget is not installed\n")}},
	}}
	a, err := Read(ctx, h, RPM, "wget", false)
	if err != nil || !a.Installed || a.Version != "0:2.2.1-1.fc45" {
		t.Fatalf("got %+v, %v", a, err)
	}
}

// lockedHost fails the first busy commands with a lock error, as apt and
// dnf do while another package manager runs, then succeeds.
type lockedHost struct {
	busy   int
	stderr string
	ran    int
}

func (h *lockedHost) Run(_ context.Context, _ string, _ []byte) (ssh.Result, error) {
	h.ran++
	if h.ran <= h.busy {
		return ssh.Result{ExitCode: 100, Stderr: []byte(h.stderr)}, nil
	}
	return ok(""), nil
}

func TestRunWaitsForAnotherPackageManagersLock(t *testing.T) {
	defer func(w, p time.Duration) { lockWait, lockPoll = w, p }(lockWait, lockPoll)
	lockWait, lockPoll = time.Second, time.Millisecond

	for _, stderr := range []string{
		"E: Could not get lock /var/lib/apt/lists/lock. It is held by process 170 (apt-get)",
		"error: can't create transaction lock on /var/lib/rpm/.rpm.lock (Resource temporarily unavailable)",
	} {
		h := &lockedHost{busy: 2, stderr: stderr}
		if err := Run(ctx, h, "apt-get update"); err != nil || h.ran != 3 {
			t.Errorf("with %q: Run = %v after %d tries, want success on the third", stderr, err, h.ran)
		}
	}

	h := &lockedHost{busy: 1, stderr: "E: Unable to locate package nope"}
	if err := Run(ctx, h, "apt-get install nope"); err == nil || h.ran != 1 {
		t.Errorf("Run = %v after %d tries, want other errors to fail at once", err, h.ran)
	}

	lockWait = 10 * time.Millisecond
	h = &lockedHost{busy: 1 << 30, stderr: "E: Could not get lock /var/lib/dpkg/lock-frontend"}
	if err := Run(ctx, h, "apt-get install curl"); err == nil || !strings.Contains(err.Error(), "Could not get lock") {
		t.Errorf("Run = %v, want the lock error once lockWait has passed", err)
	}
}
