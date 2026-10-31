// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package pip

import (
	"context"
	"strings"
	"testing"

	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

func TestValidate(t *testing.T) {
	good := Desired{Name: "Django", Venv: "/opt/app/venv", State: Present, Version: "5.2.1"}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*Desired){
		"specifier in name": func(d *Desired) { d.Name = "django==5.2" },
		"extras":            func(d *Desired) { d.Name = "requests[socks]" },
		"url":               func(d *Desired) { d.Name = "git+https://example.com/x" },
		"flag":              func(d *Desired) { d.Name = "--index-url=http://evil" },
		"relative venv":     func(d *Desired) { d.Venv = "venv" },
		"unclean venv":      func(d *Desired) { d.Venv = "/opt/../etc" },
		"root as venv":      func(d *Desired) { d.Venv = "/" },
		"home shorthand":    func(d *Desired) { d.Venv = "~/venv" },
		"unknown state":     func(d *Desired) { d.State = "forcereinstall" },
		"range":             func(d *Desired) { d.Version = ">=1" },
		"wildcard":          func(d *Desired) { d.Version = "1.*" },
		"epoch":             func(d *Desired) { d.Version = "1!2.0" },
		"latest with pin":   func(d *Desired) { d.State = Latest },
		"absent with pin":   func(d *Desired) { d.State = Absent },
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
		{Desired{State: Present}, Actual{Installed: true, Version: "9"}, false}, // unpinned accepts what's there
		{Desired{State: Present, Version: "1.2"}, Actual{Installed: true, Version: "1.2"}, false},
		{Desired{State: Present, Version: "1.2"}, Actual{Installed: true, Version: "1.3"}, true},
		{Desired{State: Present, Version: "1.2"}, Actual{Installed: true, Version: "1.2.0"}, false}, // == says these are equal, so it settles
		{Desired{State: Present, Version: "1.2.0"}, Actual{Installed: true, Version: "1.2"}, false},
		{Desired{State: Present, Version: "1.2"}, Actual{Installed: true, Version: "1.2+cpu"}, false},
		{Desired{State: Present, Version: "1.2+cpu"}, Actual{Installed: true, Version: "1.2"}, true},
		{Desired{State: Present, Version: "1.2rc1"}, Actual{Installed: true, Version: "1.2"}, true},
		{Desired{State: Absent}, Actual{Installed: true}, true},
		{Desired{State: Absent}, Actual{}, false},
		{Desired{State: Latest}, Actual{}, true},
		{Desired{State: Latest}, Actual{Installed: true, Version: "1", Candidate: "1"}, false},
		{Desired{State: Latest}, Actual{Installed: true, Version: "1", Candidate: "2"}, true},
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

func TestReadMatchesNormalizedNames(t *testing.T) {
	r := &fakeRunner{out: map[string]string{"pip list": `[{"name":"Zope.Interface","version":"7.0"},{"name":"six","version":"1.16.0"}]`}}
	a, err := Read(context.Background(), r, Desired{Name: "zope_interface", Venv: "/v", State: Present})
	if err != nil || !a.Installed || a.Version != "7.0" {
		t.Fatalf("read = %+v, %v", a, err)
	}
	a, err = Read(context.Background(), r, Desired{Name: "absent", Venv: "/v", State: Present})
	if err != nil || a.Installed {
		t.Fatalf("read = %+v, %v", a, err)
	}
	// No output: there's no usable venv yet.
	a, err = Read(context.Background(), &fakeRunner{}, Desired{Name: "six", Venv: "/v", State: Present})
	if err != nil || a.Installed {
		t.Fatalf("read = %+v, %v", a, err)
	}
}

func TestLatestReadsWhatPipWouldInstall(t *testing.T) {
	list := `[{"name":"six","version":"1.15.0"}]`
	r := &fakeRunner{out: map[string]string{"--dry-run": `{"install":[{"metadata":{"version":"1.16.0"}}]}`, "pip list": list}}
	a, err := Read(context.Background(), r, Desired{Name: "six", Venv: "/v", State: Latest})
	if err != nil || a.Candidate != "1.16.0" {
		t.Fatalf("read = %+v, %v", a, err)
	}
	// Nothing to install means it has settled, even above what the index offers.
	r.out["--dry-run"] = `{"install":[]}`
	a, err = Read(context.Background(), r, Desired{Name: "six", Venv: "/v", State: Latest})
	if err != nil || a.Candidate != "1.15.0" || NeedsChange(Desired{State: Latest}, a) {
		t.Fatalf("read = %+v, %v", a, err)
	}
}

func TestUserRunsEverything(t *testing.T) {
	d := Desired{Name: "six", Venv: "/home/app/venv", User: "app", State: Present, Version: "1.16.0"}
	r := &fakeRunner{}
	if _, err := Read(context.Background(), r, d); err != nil {
		t.Fatal(err)
	}
	if err := Apply(context.Background(), r, d); err != nil {
		t.Fatal(err)
	}
	for _, cmd := range r.cmds {
		if !strings.Contains(cmd, "runuser -u 'app'") && !strings.Contains(cmd, "runuser -u app") {
			t.Errorf("not run as the user:\n%s", cmd)
		}
	}
	if !strings.Contains(r.cmds[1], "six==1.16.0") {
		t.Errorf("no pin in:\n%s", r.cmds[1])
	}
}
