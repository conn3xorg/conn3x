// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package supervisor

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

func TestParseStatus(t *testing.T) {
	for _, c := range []struct {
		name, out string
		want      []Process
	}{
		{"app", "app                              RUNNING   pid 812, uptime 0:01:02\n", []Process{{"app", "RUNNING"}}},
		{"app", "app                              STOPPED   Nov 22 08:01 PM\n", []Process{{"app", "STOPPED"}}},
		{"app", "app                              FATAL     Exited too quickly (process log may have details)\n", []Process{{"app", "FATAL"}}},
		{"app", "app: ERROR (no such process)\n", nil},
		{"web:", "web: ERROR (no such group)\n", nil},
		{"web:", "web:web_00                       RUNNING   pid 1, uptime 0:00:05\nweb:web_01                       BACKOFF   Exited too quickly\n", []Process{{"web:web_00", "RUNNING"}, {"web:web_01", "BACKOFF"}}},
		{"app", "app2                             RUNNING   pid 9, uptime 0:00:01\n", nil},
	} {
		got, err := parseStatus(c.out, c.name)
		if err != nil || !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s %q: %v, %v; want %v", c.name, c.out, got, err, c.want)
		}
	}
	if _, err := parseStatus("unix:///var/run/supervisor.sock no such file\n", "app"); err == nil {
		t.Error("supervisord down: no error")
	}
}

func TestInSync(t *testing.T) {
	run, stop := []Process{{"app", "RUNNING"}}, []Process{{"app", "STOPPED"}}
	mixed := []Process{{"w:0", "RUNNING"}, {"w:1", "FATAL"}}
	for _, c := range []struct {
		state State
		procs []Process
		want  bool
	}{
		{Started, run, true}, {Started, stop, false}, {Started, mixed, false}, {Started, nil, false},
		{Stopped, stop, true}, {Stopped, run, false}, {Stopped, mixed, false},
		{Present, stop, true}, {Present, nil, false},
		{Absent, nil, true}, {Absent, stop, false},
	} {
		if got := InSync(c.state, c.procs); got != c.want {
			t.Errorf("%s %v: %v", c.state, c.procs, got)
		}
	}
}

func TestValidate(t *testing.T) {
	for _, good := range []Program{{Name: "app", State: Started}, {Name: "web:", State: Stopped}, {Name: "a.b-c_1", State: Present, Conn: Conn{Config: "/etc/supervisor/supervisord.conf", Path: "/usr/bin/supervisorctl", Password: "it's"}}} {
		if err := good.Validate(); err != nil {
			t.Errorf("%+v: %v", good, err)
		}
	}
	for _, bad := range []Program{
		{Name: "all", State: Started}, {Name: "all:", State: Started}, {Name: "-c", State: Started}, {Name: "a b", State: Started},
		{Name: "web:web_00", State: Started}, {Name: "app", State: "restarted"}, {Name: "app", State: Started, Conn: Conn{Config: "supervisord.conf"}},
		{Name: "app", State: Started, Conn: Conn{Password: "a\nb"}},
	} {
		if err := bad.Validate(); err == nil {
			t.Errorf("%+v: no error", bad)
		}
	}
}

// Every value reaches the shell as one quoted word.
func TestCommandQuotes(t *testing.T) {
	c := Conn{Config: "/etc/s.conf", ServerURL: "http://127.0.0.1:9001", Username: "u", Password: "p'w $x", Path: "/opt/bin/supervisorctl"}
	want := `'/opt/bin/supervisorctl' -c '/etc/s.conf' -s 'http://127.0.0.1:9001' -u 'u' -p 'p'\''w $x' 'status' 'app'`
	if got := c.command("status", "app"); got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
	if got := (Conn{}).command("reread"); got != "supervisorctl 'reread'" {
		t.Errorf("default: %s", got)
	}
}

// host answers status with each of statuses in turn and records the
// actions it was asked for.
type host struct {
	statuses []string
	actions  []string
}

func (h *host) Run(_ context.Context, cmd string, _ []byte) (ssh.Result, error) {
	if strings.HasPrefix(cmd, "supervisorctl 'status'") {
		out := h.statuses[0]
		if len(h.statuses) > 1 {
			h.statuses = h.statuses[1:]
		}
		return ssh.Result{Stdout: []byte(out)}, nil
	}
	h.actions = append(h.actions, strings.TrimPrefix(cmd, "supervisorctl "))
	return ssh.Result{}, nil
}

func TestApply(t *testing.T) {
	const (
		none    = "app: ERROR (no such process)\n"
		running = "app RUNNING pid 1, uptime 0:00:01\n"
		stopped = "app STOPPED Nov 22 08:01 PM\n"
	)
	for _, c := range []struct {
		state    State
		update   bool
		statuses []string
		want     []string
	}{
		{Started, false, []string{running}, nil},
		{Started, false, []string{stopped}, []string{"'start' 'app'"}},
		{Started, false, []string{none, stopped}, []string{"'reread'", "'add' 'app'", "'start' 'app'"}},
		{Started, false, []string{none, running}, []string{"'reread'", "'add' 'app'"}},
		{Started, true, []string{running}, []string{"'update' 'app'"}},
		{Stopped, false, []string{running}, []string{"'stop' 'app'"}},
		{Present, false, []string{stopped}, nil},
		{Present, false, []string{none, running}, []string{"'reread'", "'add' 'app'"}},
		{Absent, true, []string{running}, []string{"'stop' 'app'", "'reread'", "'remove' 'app'"}},
		{Absent, false, []string{stopped}, []string{"'reread'", "'remove' 'app'"}},
		{Absent, false, []string{none}, nil},
	} {
		h := &host{statuses: c.statuses}
		if err := Apply(context.Background(), h, Program{Name: "app", State: c.state}, c.update); err != nil {
			t.Errorf("%s %v: %v", c.state, c.statuses, err)
		}
		if !reflect.DeepEqual(h.actions, c.want) {
			t.Errorf("%s update=%v %q: ran %q, want %q", c.state, c.update, c.statuses, h.actions, c.want)
		}
	}
}

// A group's actions name the group with its colon, add and remove without.
func TestApplyGroup(t *testing.T) {
	h := &host{statuses: []string{"web: ERROR (no such group)\n", "web:web_00 STOPPED Nov 22\n"}}
	if err := Apply(context.Background(), h, Program{Name: "web:", State: Started}, false); err != nil {
		t.Fatal(err)
	}
	if want := []string{"'reread'", "'add' 'web'", "'start' 'web:'"}; !reflect.DeepEqual(h.actions, want) {
		t.Errorf("ran %q, want %q", h.actions, want)
	}
}

// supervisorctl reports a failed start with exit status 0.
func TestRunErrorInOutput(t *testing.T) {
	r := runFunc(func(cmd string) ssh.Result { return ssh.Result{Stdout: []byte("app: ERROR (spawn error)\n")} })
	err := Program{Name: "app", Conn: Conn{Password: "hunter2"}}.run(context.Background(), r, "start", "app")
	if err == nil || !strings.Contains(err.Error(), "spawn error") || strings.Contains(err.Error(), "hunter2") {
		t.Errorf("got %v", err)
	}
}

type runFunc func(string) ssh.Result

func (f runFunc) Run(_ context.Context, cmd string, _ []byte) (ssh.Result, error) { return f(cmd), nil }
