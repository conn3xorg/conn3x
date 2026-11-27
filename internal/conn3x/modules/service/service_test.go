// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

type host struct {
	show string
	ran  []string
	fail map[string]ssh.Result
}

func (h *host) Run(_ context.Context, cmd string, _ []byte) (ssh.Result, error) {
	h.ran = append(h.ran, cmd)
	for k, r := range h.fail {
		if strings.Contains(cmd, k) {
			return r, nil
		}
	}
	if strings.Contains(cmd, "systemctl show") {
		return ssh.Result{Stdout: []byte(h.show)}, nil
	}
	return ssh.Result{}, nil
}

var ctx = context.Background()

func show(load, active, file, reload string) string {
	return "LoadState=" + load + "\nActiveState=" + active + "\nUnitFileState=" + file + "\nNeedDaemonReload=" + reload + "\n"
}

func TestRead(t *testing.T) {
	h := &host{show: show("loaded", "active", "enabled", "no")}
	a, err := Read(ctx, h, "nginx")
	if err != nil {
		t.Fatal(err)
	}
	if !a.Exists || !a.Running || !a.Enabled || a.NeedsReload {
		t.Fatalf("got %+v", a)
	}
	if !strings.Contains(h.ran[0], "'nginx.service'") {
		t.Fatalf("unit name not normalised and quoted: %q", h.ran[0])
	}
}

func TestReadMissingUnit(t *testing.T) {
	a, err := Read(ctx, &host{show: show("not-found", "inactive", "", "no")}, "nope")
	if err != nil || a.Exists {
		t.Fatalf("got %+v, %v", a, err)
	}
}

func TestReadTreatsActivatingAsRunning(t *testing.T) {
	a, _ := Read(ctx, &host{show: show("loaded", "activating", "disabled", "no")}, "x")
	if !a.Running {
		t.Fatal("activating unit not treated as running")
	}
	a, _ = Read(ctx, &host{show: show("loaded", "failed", "disabled", "no")}, "x")
	if a.Running {
		t.Fatal("failed unit treated as running")
	}
}

func TestNeedsChange(t *testing.T) {
	yes, no := true, false
	running := Actual{Exists: true, Running: true, Enabled: true}
	for _, tc := range []struct {
		d    Desired
		a    Actual
		want bool
	}{
		{Desired{Name: "x", State: Started, Enabled: &yes}, running, false},
		{Desired{Name: "x", State: Stopped}, running, true},
		{Desired{Name: "x", Enabled: &no}, running, true},
		{Desired{Name: "x"}, running, false},
		{Desired{Name: "x", State: Started}, Actual{Exists: true, Running: true, NeedsReload: true}, true},
	} {
		if got := NeedsChange(tc.d, tc.a); got != tc.want {
			t.Errorf("NeedsChange(%+v, %+v) = %v", tc.d, tc.a, got)
		}
	}
}

func TestApply(t *testing.T) {
	yes := true
	h := &host{show: show("loaded", "inactive", "disabled", "yes")}
	if err := Apply(ctx, h, Desired{Name: "web", State: Started, Enabled: &yes}); err != nil {
		t.Fatal(err)
	}
	all := strings.Join(h.ran, "\n")
	for _, want := range []string{"systemctl daemon-reload", "systemctl enable -- 'web.service'", "systemctl start -- 'web.service'"} {
		if !strings.Contains(all, want) {
			t.Errorf("missing %q in:\n%s", want, all)
		}
	}
	if strings.Index(all, "daemon-reload") > strings.Index(all, "start") {
		t.Error("daemon-reload must run before start")
	}
}

func TestApplyStoppedDisabled(t *testing.T) {
	no := false
	h := &host{show: show("loaded", "active", "enabled", "no")}
	if err := Apply(ctx, h, Desired{Name: "web", State: Stopped, Enabled: &no}); err != nil {
		t.Fatal(err)
	}
	all := strings.Join(h.ran, "\n")
	if !strings.Contains(all, "systemctl stop -- 'web.service'") || !strings.Contains(all, "systemctl disable -- 'web.service'") {
		t.Fatalf("ran:\n%s", all)
	}
}

func TestApplyMissingUnitIsAnError(t *testing.T) {
	err := Apply(ctx, &host{show: show("not-found", "inactive", "", "no")}, Desired{Name: "nope", State: Started})
	if err == nil || !strings.Contains(err.Error(), "nope.service") || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("err = %v", err)
	}
}

func TestApplyStartFailureIncludesStatus(t *testing.T) {
	h := &host{show: show("loaded", "inactive", "disabled", "no"), fail: map[string]ssh.Result{
		"systemctl start": {ExitCode: 1, Stderr: []byte("Job for web.service failed because the control process exited with error code.")},
	}}
	err := Apply(ctx, h, Desired{Name: "web", State: Started})
	if err == nil || !strings.Contains(err.Error(), "control process exited") {
		t.Fatalf("err = %v", err)
	}
}

func TestValidate(t *testing.T) {
	for _, bad := range []Desired{{Name: ""}, {Name: "a b"}, {Name: "x;reboot"}, {Name: "x", State: "running"}} {
		if bad.Validate() == nil {
			t.Errorf("Validate(%+v) accepted", bad)
		}
	}
	for _, good := range []string{"nginx", "nginx.service", "getty@tty1.service", "systemd-resolved"} {
		if err := (Desired{Name: good}).Validate(); err != nil {
			t.Errorf("Validate(%q): %v", good, err)
		}
	}
}

func TestValidateErrorNamesAttribute(t *testing.T) {
	yes := true
	for _, c := range []struct {
		attr string
		d    Desired
	}{
		{"name", Desired{Name: "x y"}},
		{"state", Desired{Name: "web", State: "restarted"}},
		{"masked", Desired{Name: "web", State: Started, Masked: &yes}},
	} {
		var ve *ValidationError
		if err := c.d.Validate(); !errors.As(err, &ve) || ve.Attribute != c.attr {
			t.Errorf("Validate(%+v): want ValidationError on %q, got %v", c.d, c.attr, err)
		}
	}
}

func TestValidateRestartHintOnlyForRestartStates(t *testing.T) {
	const hint = "notify a handler from the step that changes the config"
	yes := true
	// restarted/reloaded point people at the real way to restart; an arbitrary
	// bad state or a masked unit does not get that hint.
	for _, c := range []struct {
		name string
		d    Desired
		want bool
	}{
		{"restarted", Desired{Name: "web", State: "restarted"}, true},
		{"reloaded", Desired{Name: "web", State: "reloaded"}, true},
		{"other bad state", Desired{Name: "web", State: "up"}, false},
		{"masked", Desired{Name: "web", State: Started, Masked: &yes}, false},
	} {
		err := c.d.Validate()
		if err == nil {
			t.Errorf("%s: Validate accepted, want error", c.name)
			continue
		}
		got := strings.Contains(err.Error(), hint)
		if got != c.want {
			t.Errorf("%s: hint present = %v, want %v (err: %s)", c.name, got, c.want, err)
		}
	}
}

// fastHost answers ReadUnit with props or err.
type fastHost struct {
	host
	props map[string]string
	err   error
	asked []string
}

func (h *fastHost) ReadUnit(_ context.Context, unit string) (map[string]string, error) {
	h.asked = append(h.asked, unit)
	return h.props, h.err
}

func TestReadUsesUnitReader(t *testing.T) {
	h := &fastHost{props: map[string]string{"LoadState": "loaded", "ActiveState": "reloading", "UnitFileState": "enabled-runtime", "NeedDaemonReload": "yes"}}
	a, err := Read(ctx, h, "nginx")
	if err != nil {
		t.Fatal(err)
	}
	if want := (Actual{Exists: true, Running: true, Enabled: true, NeedsReload: true}); a != want {
		t.Fatalf("got %+v, want %+v", a, want)
	}
	if len(h.ran) != 0 || len(h.asked) != 1 || h.asked[0] != "nginx.service" {
		t.Fatalf("asked %q, ran %q", h.asked, h.ran)
	}
	h.props = map[string]string{"LoadState": "not-found"}
	if a, err := Read(ctx, h, "nope"); err != nil || a.Exists {
		t.Fatalf("not found: %+v, %v", a, err)
	}
	if _, err := Read(ctx, h, "bad name"); err == nil || len(h.asked) != 2 {
		t.Fatalf("an invalid name reached the agent: %v, %q", err, h.asked)
	}
}

func TestReadUnitFallsBackOnlyWhenUnsupported(t *testing.T) {
	h := &fastHost{host: host{show: show("masked", "inactive", "masked", "no")}, err: fmt.Errorf("no D-Bus: %w", errors.ErrUnsupported)}
	a, err := Read(ctx, h, "nginx")
	if err != nil || !a.Exists || a.Enabled || a.Running || len(h.ran) != 1 {
		t.Fatalf("got %+v, %v after running %q; want the shell's answer", a, err, h.ran)
	}
	gone := errors.New("the conn3x agent stopped")
	h = &fastHost{err: gone}
	if _, err := Read(ctx, h, "nginx"); !errors.Is(err, gone) || len(h.ran) != 0 {
		t.Fatalf("got %v after running %q; want the agent's error and no shell", err, h.ran)
	}
}

// A handler that restarts or reloads a unit whose file changed reloads
// systemd first, or the unit would come back with its old settings.
func TestHandlerReloadsSystemdWhenUnitChanged(t *testing.T) {
	for _, tc := range []struct {
		fn   func(context.Context, *host, string) error
		verb string
	}{
		{func(c context.Context, h *host, n string) error { return Restart(c, h, n) }, "restart"},
		{func(c context.Context, h *host, n string) error { return Reload(c, h, n) }, "reload"},
		{func(c context.Context, h *host, n string) error { return Start(c, h, n) }, "start"},
		{func(c context.Context, h *host, n string) error { return TryRestart(c, h, n) }, "try-restart"},
		{func(c context.Context, h *host, n string) error { return TryReload(c, h, n) }, "try-reload-or-restart"},
	} {
		for _, changed := range []string{"yes", "no"} {
			h := &host{show: show("loaded", "active", "enabled", changed)}
			if err := tc.fn(ctx, h, "web"); err != nil {
				t.Fatal(err)
			}
			all := strings.Join(h.ran, "\n")
			want := "systemctl " + tc.verb + " -- 'web.service'"
			if !strings.HasSuffix(all, want) {
				t.Errorf("%s, NeedDaemonReload=%s: last command isn't %q in:\n%s", tc.verb, changed, want, all)
			}
			if got := strings.Contains(all, "daemon-reload"); got != (changed == "yes") {
				t.Errorf("%s, NeedDaemonReload=%s: daemon-reload ran = %v in:\n%s", tc.verb, changed, got, all)
			}
		}
	}
}

// masking reads as systemd reports it, after "systemctl mask".
type maskHost struct{ host }

func (h *maskHost) Run(ctx context.Context, cmd string, in []byte) (ssh.Result, error) {
	if strings.Contains(cmd, "systemctl mask") {
		h.show = show("masked", "inactive", "masked", "no")
	}
	return h.host.Run(ctx, cmd, in)
}

func TestMasked(t *testing.T) {
	yes, no := true, false
	// A masked unit reads as masked; masking one that's running stops it
	// once the mask is on, and one that isn't installed can be masked.
	for name, sh := range map[string]string{
		"running":       show("loaded", "active", "enabled", "no"),
		"not installed": show("not-found", "inactive", "", "no"),
	} {
		h := &maskHost{host{show: sh}}
		if err := Apply(ctx, h, Desired{Name: "rpcbind", State: Stopped, Masked: &yes}); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		all := strings.Join(h.ran, "\n")
		if !strings.Contains(all, "systemctl mask -- 'rpcbind.service'") {
			t.Errorf("%s: no mask in:\n%s", name, all)
		}
		a, _ := Read(ctx, h, "rpcbind")
		if !a.Masked || NeedsChange(Desired{Name: "rpcbind", State: Stopped, Masked: &yes}, a) {
			t.Errorf("%s: after the mask %+v", name, a)
		}
	}

	h := &host{show: show("masked", "inactive", "masked", "no")}
	if err := Apply(ctx, h, Desired{Name: "rpcbind", Masked: &no}); err != nil || !strings.Contains(strings.Join(h.ran, "\n"), "systemctl unmask -- 'rpcbind.service'") {
		t.Errorf("unmask: %v, ran %v", err, h.ran)
	}
	if !NeedsChange(Desired{Name: "rpcbind", Masked: &yes}, Actual{Exists: true}) {
		t.Error("an unmasked unit with masked = true needs no change")
	}
	for _, d := range []Desired{{Name: "a", State: Started, Masked: &yes}, {Name: "a", Enabled: &yes, Masked: &yes}} {
		if d.Validate() == nil {
			t.Errorf("%+v validated", d)
		}
	}
	if (Desired{Name: "a", State: Started, Masked: &no}).Validate() != nil {
		t.Error("masked = false with started was refused")
	}
}

// masked = true with enabled = false disables an enabled unit before the
// mask, while systemd still reports it enabled.
func TestMaskDisablesFirst(t *testing.T) {
	yes, no := true, false
	h := &maskHost{host{show: show("loaded", "active", "enabled", "no")}}
	if err := Apply(ctx, h, Desired{Name: "rpcbind", State: Stopped, Enabled: &no, Masked: &yes}); err != nil {
		t.Fatal(err)
	}
	all := strings.Join(h.ran, "\n")
	d, m := strings.Index(all, "systemctl disable -- 'rpcbind.service'"), strings.Index(all, "systemctl mask -- 'rpcbind.service'")
	if d < 0 || m < 0 || d > m {
		t.Errorf("want disable before mask in:\n%s", all)
	}
	// Without enabled = false the links stay, as systemctl mask leaves them.
	h = &maskHost{host{show: show("loaded", "active", "enabled", "no")}}
	if err := Apply(ctx, h, Desired{Name: "rpcbind", Masked: &yes}); err != nil || strings.Contains(strings.Join(h.ran, "\n"), "disable") {
		t.Errorf("disabled without enabled = false: %v, %v", err, h.ran)
	}
}

// A reload of a unit that isn't running starts it, as Ansible's systemd
// module does; a restart already starts it.
func TestReloadStartsAStoppedUnit(t *testing.T) {
	for verb, want := range map[string]string{"reload": "start", "restart": "restart"} {
		h := &host{show: show("loaded", "inactive", "enabled", "no")}
		fn := Reload
		if verb == "restart" {
			fn = Restart
		}
		if err := fn(ctx, h, "web"); err != nil {
			t.Fatal(err)
		}
		if got := h.ran[len(h.ran)-1]; got != "systemctl "+want+" -- 'web.service'" {
			t.Errorf("%s on a stopped unit ran %q", verb, got)
		}
	}
}

// The try- verbs go to systemctl as they are, so a stopped unit stays
// stopped: unlike reload, they aren't turned into a start.
func TestTryActionsLeaveStoppedUnitStopped(t *testing.T) {
	for verb, fn := range map[string]func(context.Context, *host, string) error{
		"try-restart":           func(c context.Context, h *host, n string) error { return TryRestart(c, h, n) },
		"try-reload-or-restart": func(c context.Context, h *host, n string) error { return TryReload(c, h, n) },
	} {
		h := &host{show: show("loaded", "inactive", "enabled", "no")}
		if err := fn(ctx, h, "web"); err != nil {
			t.Fatal(err)
		}
		all := strings.Join(h.ran, "\n")
		if !strings.HasSuffix(all, "systemctl "+verb+" -- 'web.service'") || strings.Contains(all, "systemctl start") {
			t.Errorf("%s on a stopped unit ran:\n%s", verb, all)
		}
	}
}

// reset-failed runs on an installed unit and is skipped for a missing one,
// where systemctl would fail with "Unit not loaded".
func TestResetFailed(t *testing.T) {
	h := &host{show: show("loaded", "failed", "enabled", "no")}
	if err := ResetFailed(ctx, h, "jenkins"); err != nil {
		t.Fatal(err)
	}
	if all := strings.Join(h.ran, "\n"); !strings.HasSuffix(all, "systemctl reset-failed -- 'jenkins.service'") {
		t.Errorf("ran:\n%s", all)
	}
	h = &host{show: show("not-found", "inactive", "", "no")}
	if err := ResetFailed(ctx, h, "jenkins"); err != nil {
		t.Fatal(err)
	}
	if all := strings.Join(h.ran, "\n"); strings.Contains(all, "reset-failed") {
		t.Errorf("reset-failed ran on a missing unit:\n%s", all)
	}
}

// A oneshot that RemainAfterExit keeps active is restarted, so it runs
// again; a running service of any other type is only started, a no-op.
func TestStartRerunsActiveOneshot(t *testing.T) {
	for typ, want := range map[string]string{"oneshot": "restart", "simple": "start"} {
		h := &host{show: show("loaded", "active", "static", "no"), fail: map[string]ssh.Result{"-p Type": {Stdout: []byte(typ + "\n")}}}
		if err := Start(ctx, h, "converge"); err != nil {
			t.Fatal(err)
		}
		if all := strings.Join(h.ran, "\n"); !strings.HasSuffix(all, "systemctl "+want+" -- 'converge.service'") {
			t.Errorf("Type=%s, active: ran\n%s", typ, all)
		}
	}
	h := &host{show: show("loaded", "inactive", "static", "no")}
	if err := Start(ctx, h, "converge"); err != nil {
		t.Fatal(err)
	}
	if all := strings.Join(h.ran, "\n"); strings.Contains(all, "-p Type") || !strings.HasSuffix(all, "systemctl start -- 'converge.service'") {
		t.Errorf("inactive unit: ran\n%s", all)
	}
}

func TestDaemonReload(t *testing.T) {
	h := &host{show: show("loaded", "active", "enabled", "no")}
	if err := DaemonReload(ctx, h); err != nil {
		t.Fatal(err)
	}
	if strings.Join(h.ran, "\n") != "systemctl daemon-reload" {
		t.Errorf("ran %q", h.ran)
	}
}

// A try- action on a unit that isn't installed does nothing, where
// systemctl would fail with "Unit not found".
func TestTryActionsSkipMissingUnit(t *testing.T) {
	for _, fn := range []func(context.Context, *host, string) error{
		func(c context.Context, h *host, n string) error { return TryRestart(c, h, n) },
		func(c context.Context, h *host, n string) error { return TryReload(c, h, n) },
	} {
		h := &host{show: show("not-found", "inactive", "", "no")}
		if err := fn(ctx, h, "systemd-resolved"); err != nil {
			t.Fatal(err)
		}
		if all := strings.Join(h.ran, "\n"); strings.Contains(all, "try-") {
			t.Errorf("ran a try- action on a missing unit:\n%s", all)
		}
	}
}
