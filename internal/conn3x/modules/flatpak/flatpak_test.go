// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package flatpak

import (
	"context"
	"strings"
	"testing"

	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

func TestValidate(t *testing.T) {
	good := Desired{Name: "org.gnome.Calculator", Remote: "flathub", Method: System, State: Present}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*Desired){
		"two parts":     func(d *Desired) { d.Name = "gnome.Calculator" },
		"ref":           func(d *Desired) { d.Name = "app/org.gnome.Calculator/x86_64/stable" },
		"url":           func(d *Desired) { d.Name = "https://flathub.org/repo/appstream/org.gnome.Calculator.flatpakref" },
		"flag":          func(d *Desired) { d.Name = "--assumeyes.x.y" },
		"digit first":   func(d *Desired) { d.Name = "org.1gnome.Calculator" },
		"space":         func(d *Desired) { d.Name = "org.gnome.Calc ulator" },
		"remote flag":   func(d *Desired) { d.Remote = "--user" },
		"remote space":  func(d *Desired) { d.Remote = "flat hub" },
		"empty remote":  func(d *Desired) { d.Remote = "" },
		"method":        func(d *Desired) { d.Method = "global" },
		"unknown state": func(d *Desired) { d.State = "installed" },
	} {
		d := good
		change(&d)
		if d.Validate() == nil {
			t.Errorf("%s: accepted %+v", name, d)
		}
	}
}

func TestInSync(t *testing.T) {
	for _, c := range []struct {
		d    Desired
		a    Actual
		want bool
	}{
		{Desired{State: Present}, Actual{}, false},
		{Desired{State: Present, Remote: "flathub"}, Actual{Installed: true, Origin: "other"}, true}, // any remote will do
		{Desired{State: Absent}, Actual{Installed: true}, false},
		{Desired{State: Absent}, Actual{}, true},
		{Desired{State: Latest}, Actual{}, false},
		{Desired{State: Latest}, Actual{Installed: true}, true},
		{Desired{State: Latest}, Actual{Installed: true, Outdated: true}, false},
	} {
		if got := c.d.InSync(c.a); got != c.want {
			t.Errorf("InSync(%+v, %+v) = %v", c.d, c.a, got)
		}
	}
}

// fakeHost answers each command by a piece of it and records them all.
type fakeHost struct {
	out  map[string]string
	exit map[string]int
	ran  []string
}

func (h *fakeHost) Run(_ context.Context, cmd string, _ []byte) (ssh.Result, error) {
	h.ran = append(h.ran, cmd)
	for k, v := range h.out {
		if strings.Contains(cmd, k) {
			return ssh.Result{Stdout: []byte(v), ExitCode: h.exit[k]}, nil
		}
	}
	for k, code := range h.exit {
		if strings.Contains(cmd, k) {
			return ssh.Result{Stderr: []byte("error: " + k), ExitCode: code}, nil
		}
	}
	return ssh.Result{}, nil
}

const list = "org.test.Hello\tlocal\norg.test.Platform\tlocal\n"

func TestReadParsesTheList(t *testing.T) {
	ctx := context.Background()
	h := &fakeHost{out: map[string]string{"flatpak list": list, "--updates": "org.test.Hello\n"}}
	a, err := Read(ctx, h, Desired{Name: "org.test.Hello", Remote: "local", Method: System, State: Present})
	if err != nil || !a.Installed || a.Origin != "local" || a.Outdated {
		t.Fatalf("read = %+v, %v", a, err)
	}
	if !strings.Contains(h.ran[0], "--system") || len(h.ran) != 1 {
		t.Errorf("present asked the remote: %q", h.ran)
	}
	a, err = Read(ctx, h, Desired{Name: "org.test.Hello", Remote: "local", Method: User, State: Latest})
	if err != nil || !a.Outdated || !strings.Contains(h.ran[2], "remote-ls --updates --user") {
		t.Fatalf("latest: %+v, %v, ran %q", a, err, h.ran)
	}
	a, err = Read(ctx, h, Desired{Name: "org.test.Nope", Remote: "local", Method: System, State: Latest})
	if err != nil || a.Installed || len(h.ran) != 4 {
		t.Fatalf("missing app: %+v, %v, ran %d", a, err, len(h.ran))
	}
	// A list that fails is an error, not an empty host.
	h = &fakeHost{exit: map[string]int{"flatpak list": 127}}
	if _, err := Read(ctx, h, Desired{Name: "org.test.Hello", Remote: "local", Method: System, State: Present}); err == nil {
		t.Error("read swallowed the error")
	}
}

func TestApplyDoesOnlyWhatIsMissing(t *testing.T) {
	ctx := context.Background()
	last := func(h *fakeHost) string { return h.ran[len(h.ran)-1] }
	// Installed and wanted: nothing runs after the list.
	h := &fakeHost{out: map[string]string{"flatpak list": list}}
	if err := Apply(ctx, h, Desired{Name: "org.test.Hello", Remote: "local", Method: System, State: Present}); err != nil || len(h.ran) != 1 {
		t.Fatalf("err %v, ran %q", err, h.ran)
	}
	// Missing: install from the remote, into the right installation.
	if err := Apply(ctx, h, Desired{Name: "org.test.New", Remote: "flathub", Method: User, State: Present}); err != nil || !strings.HasSuffix(last(h), "flatpak install -y --noninteractive --user 'flathub' 'org.test.New'") {
		t.Fatalf("err %v, ran %q", err, last(h))
	}
	// Installed and outdated: update, not install.
	h.out["--updates"] = "org.test.Hello\n"
	if err := Apply(ctx, h, Desired{Name: "org.test.Hello", Remote: "local", Method: System, State: Latest}); err != nil || !strings.HasSuffix(last(h), "flatpak update -y --noninteractive --system 'org.test.Hello'") {
		t.Fatalf("err %v, ran %q", err, last(h))
	}
	// Installed and unwanted: uninstall.
	if err := Apply(ctx, h, Desired{Name: "org.test.Hello", Remote: "local", Method: System, State: Absent}); err != nil || !strings.HasSuffix(last(h), "flatpak uninstall -y --noninteractive --system 'org.test.Hello'") {
		t.Fatalf("err %v, ran %q", err, last(h))
	}
	// Missing and unwanted: nothing.
	n := len(h.ran)
	if err := Apply(ctx, h, Desired{Name: "org.test.Nope", Remote: "local", Method: System, State: Absent}); err != nil || len(h.ran) != n+1 {
		t.Fatalf("err %v, ran %q", err, h.ran[n:])
	}
	// What flatpak says when it fails reaches the reader.
	h = &fakeHost{exit: map[string]int{"flatpak install": 1}}
	if err := Apply(ctx, h, Desired{Name: "org.test.Nope", Remote: "local", Method: System, State: Present}); err == nil || !strings.Contains(err.Error(), "error: flatpak install") {
		t.Errorf("err = %v", err)
	}
	// Nothing runs for a bad name.
	h = &fakeHost{}
	if err := Apply(ctx, h, Desired{Name: "org.test.Hello; reboot", Remote: "local", Method: System, State: Present}); err == nil || len(h.ran) != 0 {
		t.Errorf("err %v, ran %q", err, h.ran)
	}
}
