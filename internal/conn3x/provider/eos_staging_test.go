// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh/sshtest"
	"github.com/opentofu/opentofu/internal/providers"
)

// fakeEOS answers the CLI the way cEOS-lab 4.37.0F does, closely enough for
// the provider's staging path: config sessions that hold lines until a
// commit replaces running-config with their copy, a commit timer, and "% "
// refusals. It knows only the top-level and one-level lines eos_vlan and
// eos_hostname use.
type fakeEOS struct {
	mu       sync.Mutex
	running  []block            // running-config
	sessions map[string][]block // pending sessions, each a copy of the config with its lines in
	timer    string             // the session waiting on its commit timer
	refuse   string             // a script line containing this is refused
	commits  int                // commit timers started
	saves    int
}

type block struct {
	head string
	kids []string
}

func newFakeEOS(t *testing.T, running ...block) (*fakeEOS, cty.Value) {
	t.Helper()
	s := sshtest.New(t)
	f := &fakeEOS{running: running, sessions: map[string][]block{}}
	s.SetExec(f.run)
	conn := map[string]cty.Value{
		"host":             cty.StringVal(s.Host),
		"port":             cty.NumberIntVal(int64(s.Port)),
		"user":             cty.StringVal("admin"),
		"private_key_file": cty.StringVal(s.KeyFile(t)),
		"known_hosts_file": cty.StringVal(s.KnownHosts(t)),
		// Validate refuses this; apply only waits it out.
		"confirm_after": cty.StringVal("10ms"),
	}
	t.Cleanup(abortStaged)
	return f, eosStep("conn3x_eos_commit", nil, conn).GetAttr("ssh")
}

func render(cfg []block) string {
	var b strings.Builder
	b.WriteString("! Command: show running-config\n")
	for _, bl := range cfg {
		b.WriteString(bl.head + "\n")
		for _, k := range bl.kids {
			b.WriteString("   " + k + "\n")
		}
		b.WriteString("!\n")
	}
	return b.String()
}

// apply runs config-mode lines against a copy of cfg.
func apply(cfg []block, lines []string) []block {
	cfg = slices.Clone(cfg)
	cur := -1
	for _, l := range lines {
		switch {
		case strings.HasPrefix(l, "no vlan "):
			cfg = slices.DeleteFunc(cfg, func(b block) bool { return b.head == strings.TrimPrefix(l, "no ") })
			cur = -1
		case strings.HasPrefix(l, "vlan "), strings.HasPrefix(l, "hostname "):
			cur = slices.IndexFunc(cfg, func(b block) bool {
				return b.head == l || (strings.HasPrefix(l, "hostname ") && strings.HasPrefix(b.head, "hostname "))
			})
			if cur < 0 {
				cfg = append(cfg, block{head: l})
				cur = len(cfg) - 1
			} else {
				cfg[cur] = block{head: l, kids: slices.Clone(cfg[cur].kids)}
			}
		case strings.HasPrefix(l, "no ") && cur >= 0:
			cfg[cur].kids = slices.DeleteFunc(slices.Clone(cfg[cur].kids), func(k string) bool { return k == strings.TrimPrefix(l, "no ") })
		case cur >= 0:
			cfg[cur].kids = append(slices.Clone(cfg[cur].kids), l)
		}
	}
	return cfg
}

func (f *fakeEOS) run(cmd string, stdin []byte) (string, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	session := func() (string, string) {
		name, verb, _ := strings.Cut(strings.TrimPrefix(cmd, "configure session "), " ")
		return name, verb
	}
	switch {
	case cmd == "" && len(stdin) > 0:
		lines := strings.Split(strings.TrimSpace(string(stdin)), "\n")
		name := strings.TrimPrefix(lines[0], "configure session ")
		body := lines[1 : len(lines)-1] // drop "end"
		base, ok := f.sessions[name]
		if !ok {
			base = f.running
		}
		for _, l := range body {
			if f.refuse != "" && strings.Contains(l, f.refuse) {
				f.sessions[name] = base
				return "> " + l + "\n% Invalid input at line 2\n", 1
			}
		}
		f.sessions[name] = apply(base, body)
		return "", 0
	case cmd == "show running-config":
		return render(f.running), 0
	case cmd == "show configuration sessions | json":
		out := map[string]any{"sessions": map[string]any{}, "maxOpenSessions": 5}
		for name := range f.sessions {
			out["sessions"].(map[string]any)[name] = map[string]string{"state": "pending"}
		}
		if f.timer != "" {
			out["commitTimerSessionName"] = f.timer
			out["commitTimerExpireTime"] = 1
		}
		b, _ := json.Marshal(out)
		return string(b), 0
	case strings.HasPrefix(cmd, "show session-config named "):
		name, diffs := strings.CutSuffix(strings.TrimPrefix(cmd, "show session-config named "), " diffs")
		if diffs {
			return fmt.Sprintf("--- running\n+++ %s\n", name), 0
		}
		return render(f.sessions[name]), 0
	case strings.HasPrefix(cmd, "configure session "):
		name, verb := session()
		switch {
		case verb == "abort":
			delete(f.sessions, name)
		case strings.HasPrefix(verb, "commit timer"):
			f.running, f.timer = f.sessions[name], name
			delete(f.sessions, name)
			f.commits++
		case verb == "commit" && f.timer == name:
			f.timer = ""
		default:
			return "% Invalid input\n", 1
		}
		return "", 0
	case cmd == "copy running-config startup-config":
		f.saves++
		return "Copy completed successfully.\n", 0
	}
	return "% Invalid input (fake EOS doesn't know " + cmd + ")\n", 1
}

func (f *fakeEOS) state() (string, int, int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return render(f.running), f.commits, f.saves, len(f.sessions)
}

func vlanStep(id int, name string, ssh cty.Value) cty.Value {
	attrs := map[string]cty.Value{
		"vlan_id":   cty.NumberIntVal(int64(id)),
		"on_remove": cty.StringVal(onRemoveDelete),
	}
	if name != "" {
		attrs["name"] = cty.StringVal(name)
	}
	return onSwitch(eosStep("conn3x_eos_vlan", attrs, nil), ssh)
}

func onSwitch(v, ssh cty.Value) cty.Value {
	vals := v.AsValueMap()
	vals["ssh"] = ssh
	return cty.ObjectVal(vals)
}

func change(apply func(providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse, prior, planned cty.Value) error {
	return apply(providers.ApplyResourceChangeRequest{PriorState: prior, PlannedState: planned}).Diagnostics.Err()
}

func create(apply func(providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse, v cty.Value) error {
	return change(apply, cty.NullVal(v.Type()), v)
}

func destroy(apply func(providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse, v cty.Value) error {
	return change(apply, v, cty.NullVal(v.Type()))
}

func vlanApply(req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	return eosVLANKind.apply(ctx, req)
}

func commitApply(req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	return applyEOSCommit(ctx, req)
}

func removalsApply(req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	return applyEOSRemovals(ctx, req)
}

func commitFor(ssh cty.Value, removals bool) cty.Value {
	attrs := map[string]cty.Value{"id": cty.StringVal("eos-commit")}
	if removals {
		attrs["removals"] = cty.StringVal("eos-removals")
	}
	return onSwitch(eosStep("conn3x_eos_commit", attrs, nil), ssh)
}

// Three steps on one switch stage into one session, and the circuit's
// commit makes them live with one timer, one confirm and one save.
func TestEOSStepsShareOneCommit(t *testing.T) {
	f, ssh := newFakeEOS(t, block{head: "hostname leaf1"})
	for _, v := range []cty.Value{vlanStep(10, "web", ssh), vlanStep(20, "db", ssh), vlanStep(30, "", ssh)} {
		if err := create(vlanApply, v); err != nil {
			t.Fatal(err)
		}
	}
	if running, commits, _, pending := f.state(); commits != 0 || pending != 1 || strings.Contains(running, "vlan 10") {
		t.Fatalf("before the commit: %d commits, %d pending sessions, running:\n%s", commits, pending, running)
	}
	if err := create(commitApply, commitFor(ssh, true)); err != nil {
		t.Fatal(err)
	}
	running, commits, saves, pending := f.state()
	if commits != 1 || saves != 1 || pending != 0 {
		t.Errorf("%d commits, %d saves, %d pending sessions; want 1, 1, 0", commits, saves, pending)
	}
	for _, want := range []string{"vlan 10\n   name web\n", "vlan 20\n   name db\n", "vlan 30\n"} {
		if !strings.Contains(running, want) {
			t.Errorf("running-config is missing %q:\n%s", want, running)
		}
	}
}

// A refused line aborts the session with every earlier step's lines in it,
// and the commit then commits nothing.
func TestEOSRefusedStepAbortsTheSession(t *testing.T) {
	f, ssh := newFakeEOS(t)
	f.refuse = "vlan 20"
	if err := create(vlanApply, vlanStep(10, "web", ssh)); err != nil {
		t.Fatal(err)
	}
	err := create(vlanApply, vlanStep(20, "db", ssh))
	if err == nil || !strings.Contains(err.Error(), "Nothing was changed") {
		t.Fatalf("refused step: err = %v", err)
	}
	if err := create(vlanApply, vlanStep(30, "", ssh)); err == nil || !strings.Contains(err.Error(), "not applied") {
		t.Errorf("a step after the refusal: err = %v", err)
	}
	if err := create(commitApply, commitFor(ssh, true)); err == nil || !strings.Contains(err.Error(), "nothing was committed") {
		t.Errorf("commit: err = %v", err)
	}
	if running, commits, _, pending := f.state(); commits != 0 || pending != 0 || strings.Contains(running, "vlan") {
		t.Errorf("%d commits, %d pending sessions, running:\n%s", commits, pending, running)
	}
}

// Destroying a circuit whose commit has a conn3x_eos_removals stages every
// removal and commits them once, at the end.
func TestEOSDestroyCommitsRemovalsOnce(t *testing.T) {
	f, ssh := newFakeEOS(t, block{head: "vlan 10", kids: []string{"name web"}}, block{head: "vlan 20"}, block{head: "vlan 99"})
	removals := onSwitch(eosStep("conn3x_eos_removals", map[string]cty.Value{"id": cty.StringVal("eos-removals")}, nil), ssh)
	if err := destroy(commitApply, commitFor(ssh, true)); err != nil {
		t.Fatal(err)
	}
	for _, v := range []cty.Value{vlanStep(10, "web", ssh), vlanStep(20, "", ssh)} {
		if err := destroy(vlanApply, v); err != nil {
			t.Fatal(err)
		}
	}
	if _, commits, _, pending := f.state(); commits != 0 || pending != 1 {
		t.Fatalf("before conn3x_eos_removals: %d commits, %d pending sessions", commits, pending)
	}
	if err := destroy(removalsApply, removals); err != nil {
		t.Fatal(err)
	}
	running, commits, saves, _ := f.state()
	if commits != 1 || saves != 1 {
		t.Errorf("%d commits, %d saves; want 1 each", commits, saves)
	}
	if strings.Contains(running, "vlan 10") || strings.Contains(running, "vlan 20") || !strings.Contains(running, "vlan 99") {
		t.Errorf("running-config after destroy:\n%s", running)
	}

	// A removal after conn3x_eos_removals, out of order, commits on its own.
	if err := destroy(vlanApply, vlanStep(99, "", ssh)); err != nil {
		t.Fatal(err)
	}
	if running, commits, _, pending := f.state(); commits != 2 || pending != 0 || strings.Contains(running, "vlan 99") {
		t.Errorf("late removal: %d commits, %d pending, running:\n%s", commits, pending, running)
	}
}

// A commit in state from before conn3x_eos_removals has no removals id:
// each removal then commits on its own, as it did.
func TestEOSDestroyBeforeRemovalsCommitsEach(t *testing.T) {
	f, ssh := newFakeEOS(t, block{head: "vlan 10"}, block{head: "vlan 20"})
	if err := destroy(commitApply, commitFor(ssh, false)); err != nil {
		t.Fatal(err)
	}
	for _, v := range []cty.Value{vlanStep(10, "", ssh), vlanStep(20, "", ssh)} {
		if err := destroy(vlanApply, v); err != nil {
			t.Fatal(err)
		}
	}
	if running, commits, _, pending := f.state(); commits != 2 || pending != 0 || strings.Contains(running, "vlan") {
		t.Errorf("%d commits, %d pending, running:\n%s", commits, pending, running)
	}
}
