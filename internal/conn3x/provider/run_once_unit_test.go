// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"strings"
	"sync"
	"testing"

	"github.com/zclconf/go-cty/cty"
)

// brMarkerHost is a host where the command "make-marker" creates /done,
// which a creates guard looks for. runs counts how often it ran.
type brMarkerHost struct {
	mu   sync.Mutex
	done bool
	runs int
}

func (m *brMarkerHost) answer(script string) (string, int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	switch {
	case strings.Contains(script, "[ -e '/done' ]"):
		if m.done {
			return "", 0
		}
		return "", 1
	case strings.HasSuffix(script, "; make-marker'"):
		m.runs++
		m.done = true
		return "made\n", 0
	case strings.HasSuffix(script, "; fail'"):
		return "it broke", 2
	}
	return "", 0
}

// A guarded command runs once: a second run finds the host in line, and
// check reports a change without making it.
func TestRunOnceGuardedCommand(t *testing.T) {
	m := &brMarkerHost{}
	ssh := unitHost(t, m.answer)
	args := map[string]cty.Value{"command": cty.StringVal("make-marker"), "creates": cty.StringVal("/done")}
	got, err := RunOnce(ctx, "conn3x_command", args, ssh, true)
	if err != nil || !got.Changed || m.runs != 0 {
		t.Fatalf("check: %+v, %v, %d runs", got, err, m.runs)
	}
	got, err = RunOnce(ctx, "conn3x_command", args, ssh, false)
	if err != nil || !got.Changed || got.Stdout != "made\n" || m.runs != 1 {
		t.Fatalf("first: %+v, %v, %d runs", got, err, m.runs)
	}
	got, err = RunOnce(ctx, "conn3x_command", args, ssh, false)
	if err != nil || got.Changed || m.runs != 1 {
		t.Fatalf("second: %+v, %v, %d runs", got, err, m.runs)
	}
}

// A command without a guard always runs, and its failure is the error.
func TestRunOnceUnguardedCommand(t *testing.T) {
	m := &brMarkerHost{done: true}
	ssh := unitHost(t, m.answer)
	for i := 1; i <= 2; i++ {
		if got, err := RunOnce(ctx, "conn3x_command", map[string]cty.Value{"command": cty.StringVal("make-marker")}, ssh, false); err != nil || !got.Changed || m.runs != i {
			t.Fatalf("run %d: %+v, %v, %d runs", i, got, err, m.runs)
		}
	}
	if _, err := RunOnce(ctx, "conn3x_command", map[string]cty.Value{"command": cty.StringVal("fail")}, ssh, false); err == nil || !strings.Contains(err.Error(), "exit status 2") || !strings.Contains(err.Error(), "it broke") {
		t.Errorf("a failing command: %v", err)
	}
}

// What a step would refuse, RunOnce refuses before reaching the host.
func TestRunOnceRefuses(t *testing.T) {
	ssh := unitHost(t, (&unitScripts{}).on("", "!reached the host").answer)
	for want, c := range map[string]struct {
		typeName string
		args     map[string]cty.Value
		ssh      map[string]cty.Value
	}{
		"there's no conn3x_nope":        {"conn3x_nope", nil, ssh},
		`unexpected attribute "colour"`: {"conn3x_command", map[string]cty.Value{"colour": cty.StringVal("red")}, ssh},
		"command must not be empty":     {"conn3x_command", map[string]cty.Value{"command": cty.StringVal("")}, ssh},
	} {
		if _, err := RunOnce(ctx, c.typeName, c.args, c.ssh, false); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v", want, err)
		}
	}
}
