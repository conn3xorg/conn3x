// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package npm

import (
	"context"
	"strings"
	"testing"

	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

func TestValidate(t *testing.T) {
	good := Desired{Name: "@angular/cli", Path: "/opt/app", State: Present, Version: "18.2.0"}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := (Desired{Name: "pm2", Global: true, State: Latest}).Validate(); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*Desired){
		"version in name":  func(d *Desired) { d.Name = "pm2@5" },
		"tag in name":      func(d *Desired) { d.Name = "pm2@latest" },
		"upper case":       func(d *Desired) { d.Name = "PM2" },
		"url":              func(d *Desired) { d.Name = "https://example.com/x.tgz" },
		"flag":             func(d *Desired) { d.Name = "--registry=http://evil" },
		"no path":          func(d *Desired) { d.Path = "" },
		"global with path": func(d *Desired) { d.Global = true },
		"relative path":    func(d *Desired) { d.Path = "app" },
		"unclean path":     func(d *Desired) { d.Path = "/opt/../etc" },
		"root as path":     func(d *Desired) { d.Path = "/" },
		"unknown state":    func(d *Desired) { d.State = "installed" },
		"range":            func(d *Desired) { d.Version = "^18" },
		"tag":              func(d *Desired) { d.Version = "latest" },
		"two parts":        func(d *Desired) { d.Version = "18.2" },
		"latest with pin":  func(d *Desired) { d.State = Latest },
		"absent with pin":  func(d *Desired) { d.State = Absent },
	} {
		d := good
		change(&d)
		if d.Validate() == nil {
			t.Errorf("%s: accepted %+v", name, d)
		}
	}
}

func TestNeedsChange(t *testing.T) {
	for _, c := range []struct {
		d    Desired
		a    Actual
		want bool
	}{
		{Desired{State: Present}, Actual{}, true},
		{Desired{State: Present}, Actual{Installed: true, Version: "9.0.0"}, false}, // unpinned accepts what's there
		{Desired{State: Present, Version: "1.2.0"}, Actual{Installed: true, Version: "1.2.0"}, false},
		{Desired{State: Present, Version: "1.2.0"}, Actual{Installed: true, Version: "1.3.0"}, true},
		{Desired{State: Absent}, Actual{Installed: true}, true},
		{Desired{State: Absent}, Actual{}, false},
		{Desired{State: Latest}, Actual{}, true},
		{Desired{State: Latest}, Actual{Installed: true, Version: "1.0.0", Candidate: "1.0.0"}, false},
		{Desired{State: Latest}, Actual{Installed: true, Version: "1.0.0", Candidate: "2.0.0"}, true},
	} {
		if got := NeedsChange(c.d, c.a); got != c.want {
			t.Errorf("NeedsChange(%+v, %+v) = %v", c.d, c.a, got)
		}
	}
}

type fakeRunner struct {
	out  map[string]string // by a piece of the command
	cmds []string
}

func (f *fakeRunner) Run(_ context.Context, cmd string, _ []byte) (ssh.Result, error) {
	f.cmds = append(f.cmds, cmd)
	for k, v := range f.out {
		if strings.Contains(cmd, k) {
			return ssh.Result{Stdout: []byte(v)}, nil
		}
	}
	return ssh.Result{}, nil
}

func TestReadSeesOnlyWhatIsThere(t *testing.T) {
	// npm ls lists a dependency package.json names but node_modules lacks,
	// without a version: that one isn't installed.
	r := &fakeRunner{out: map[string]string{"npm ls": `{"name":"app","dependencies":{"left-pad":{"version":"1.3.0"},"gone":{"missing":true,"problems":["missing: gone@^1"]}}}`}}
	a, err := Read(context.Background(), r, Desired{Name: "left-pad", Path: "/opt/app", State: Present})
	if err != nil || !a.Installed || a.Version != "1.3.0" {
		t.Fatalf("read = %+v, %v", a, err)
	}
	a, err = Read(context.Background(), r, Desired{Name: "gone", Path: "/opt/app", State: Present})
	if err != nil || a.Installed {
		t.Fatalf("read = %+v, %v", a, err)
	}
	// An error npm reports as JSON is an error, not an empty tree.
	r = &fakeRunner{out: map[string]string{"npm ls": `{"error":{"code":"EJSONPARSE","summary":"Failed to parse json"}}`}}
	if _, err := Read(context.Background(), r, Desired{Name: "left-pad", Path: "/opt/app", State: Present}); err == nil || !strings.Contains(err.Error(), "Failed to parse json") {
		t.Fatalf("err = %v", err)
	}
}

func TestLatestAsksTheRegistry(t *testing.T) {
	r := &fakeRunner{out: map[string]string{"npm ls": `{"dependencies":{"pm2":{"version":"5.3.0"}}}`, "npm view": "5.4.2\n"}}
	a, err := Read(context.Background(), r, Desired{Name: "pm2", Global: true, State: Latest})
	if err != nil || a.Candidate != "5.4.2" || !NeedsChange(Desired{State: Latest}, a) {
		t.Fatalf("read = %+v, %v", a, err)
	}
	if !strings.Contains(r.cmds[0], "--global") {
		t.Errorf("not global:\n%s", r.cmds[0])
	}
}

func TestApplyRunsInThePath(t *testing.T) {
	r := &fakeRunner{}
	d := Desired{Name: "left-pad", Path: "/opt/app", State: Present, Version: "1.3.0"}
	if err := Apply(context.Background(), r, d); err != nil {
		t.Fatal(err)
	}
	// Guard quotes the script again, so look past the quoting.
	for _, want := range []string{"/opt/app", "left-pad@1.3.0", "route_walk whole"} {
		if !strings.Contains(r.cmds[0], want) {
			t.Errorf("no %q in:\n%s", want, r.cmds[0])
		}
	}
	if strings.Contains(r.cmds[0], "--global") {
		t.Errorf("a project install went global:\n%s", r.cmds[0])
	}
}

// Read and Apply check their own arguments; nothing runs for a bad one.
func TestReadAndApplyValidate(t *testing.T) {
	bad := Desired{Name: "pm2; reboot", Global: true, State: Present}
	f := &fakeRunner{}
	if _, err := Read(context.Background(), f, bad); err == nil {
		t.Error("Read accepted an invalid name")
	}
	if err := Apply(context.Background(), f, bad); err == nil {
		t.Error("Apply accepted an invalid name")
	}
	if len(f.cmds) != 0 {
		t.Errorf("ran %q", f.cmds)
	}
}
