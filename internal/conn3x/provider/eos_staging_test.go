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
	"time"

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
	marks    map[string]string  // their descriptions
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
	f := &fakeEOS{running: running, sessions: map[string][]block{}, marks: map[string]string{}}
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
	t.Cleanup(func() { _ = FinishEOS() })
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
		case strings.HasPrefix(l, "no username "):
			cfg = slices.DeleteFunc(cfg, func(b block) bool { return strings.HasPrefix(b.head, strings.TrimPrefix(l, "no ")+" ") })
			cur = -1
		case strings.HasPrefix(l, "username "):
			// EOS merges a username line into the one that's there: a
			// secret, or nopassword, replaces only that part.
			f := strings.Fields(l)
			at := slices.IndexFunc(cfg, func(b block) bool { return strings.HasPrefix(b.head, "username "+f[1]+" ") })
			if at < 0 {
				cfg = append(cfg, block{head: l})
			} else if f[2] == "secret" || f[2] == "nopassword" {
				head := cfg[at].head
				for _, w := range []string{" secret ", " nopassword"} {
					head, _, _ = strings.Cut(head, w)
				}
				cfg[at] = block{head: head + " " + strings.Join(f[2:], " ")}
			} else {
				cfg[at] = block{head: l}
			}
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
	case cmd == "show configuration sessions | json", cmd == "show configuration sessions detail | json":
		out := map[string]any{"sessions": map[string]any{}, "maxOpenSessions": 5}
		for name := range f.sessions {
			out["sessions"].(map[string]any)[name] = map[string]string{"state": "pending", "description": f.marks[name]}
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
			delete(f.marks, name)
		case strings.HasPrefix(verb, "description "):
			f.marks[name] = strings.TrimPrefix(verb, "description ")
		case strings.HasPrefix(verb, "commit timer"):
			if _, ok := f.sessions[name]; !ok {
				return "% Cannot commit session " + name + " (not present) at line 1\n", 1
			}
			f.running, f.timer = f.sessions[name], name
			delete(f.sessions, name)
			delete(f.marks, name)
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

// A removal staged with other changes is forgotten as soon as it's in the
// session. When a later step's line is refused and the session goes, the
// removal is committed on its own, so the switch matches state.
func TestEOSRefusalStillCommitsStagedRemovals(t *testing.T) {
	f, ssh := newFakeEOS(t, block{head: "vlan 10"}, block{head: "vlan 20"})
	f.refuse = "vlan 40"
	if err := create(vlanApply, vlanStep(30, "", ssh)); err != nil {
		t.Fatal(err)
	}
	if err := destroy(vlanApply, vlanStep(10, "", ssh)); err != nil {
		t.Fatal(err)
	}
	err := create(vlanApply, vlanStep(40, "", ssh))
	if err == nil || !strings.Contains(err.Error(), "committed on their own") || !strings.Contains(err.Error(), "no vlan 10") {
		t.Fatalf("err = %v", err)
	}
	running, commits, _, pending := f.state()
	if commits != 1 || pending != 0 || strings.Contains(running, "vlan 10") || strings.Contains(running, "vlan 30") || !strings.Contains(running, "vlan 20") {
		t.Errorf("%d commits, %d pending, running:\n%s", commits, pending, running)
	}
}

// A destroy's final commit finds running-config changed by hand and aborts
// without making anything live. The removals are committed again on the
// changed config, which keeps the hand edit.
func TestEOSRemovalsCommitAgainAfterAHandEdit(t *testing.T) {
	f, ssh := newFakeEOS(t, block{head: "vlan 10"}, block{head: "vlan 20"})
	removals := onSwitch(eosStep("conn3x_eos_removals", map[string]cty.Value{"id": cty.StringVal("eos-removals")}, nil), ssh)
	if err := destroy(commitApply, commitFor(ssh, true)); err != nil {
		t.Fatal(err)
	}
	for _, v := range []cty.Value{vlanStep(10, "", ssh), vlanStep(20, "", ssh)} {
		if err := destroy(vlanApply, v); err != nil {
			t.Fatal(err)
		}
	}
	f.mu.Lock()
	f.running = append(f.running, block{head: "vlan 99", kids: []string{"name by-hand"}})
	f.mu.Unlock()
	err := destroy(removalsApply, removals)
	if err == nil || !strings.Contains(err.Error(), "undo that change") || !strings.Contains(err.Error(), "committed on their own") {
		t.Fatalf("err = %v", err)
	}
	running, commits, _, _ := f.state()
	if commits != 1 || strings.Contains(running, "vlan 10") || strings.Contains(running, "vlan 20") || !strings.Contains(running, "vlan 99\n   name by-hand") {
		t.Errorf("%d commits, running:\n%s", commits, running)
	}
}

// When another run took the session, committing the removals in a session
// of ours would abort that run's in turn, so they're listed instead.
func TestEOSRemovalsLostToAnotherRunAreListed(t *testing.T) {
	f, ssh := newFakeEOS(t, block{head: "vlan 10"})
	if err := create(vlanApply, vlanStep(30, "", ssh)); err != nil {
		t.Fatal(err)
	}
	if err := destroy(vlanApply, vlanStep(10, "", ssh)); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	clear(f.sessions) // the other run's Open aborts ours
	clear(f.marks)
	f.mu.Unlock()
	err := create(vlanApply, vlanStep(40, "", ssh))
	if err == nil || !strings.Contains(err.Error(), "another Conn3x run") || !strings.Contains(err.Error(), "remove these by hand: no vlan 10") {
		t.Fatalf("err = %v", err)
	}
	if running, commits, _, _ := f.state(); commits != 0 || !strings.Contains(running, "vlan 10") {
		t.Errorf("%d commits, running:\n%s", commits, running)
	}
}

func userStep(name, password string, ssh cty.Value) (planned, config cty.Value) {
	attrs := map[string]cty.Value{"name": cty.StringVal(name), "on_remove": cty.StringVal(onRemoveDelete)}
	config = onSwitch(eosStep("conn3x_eos_user", map[string]cty.Value{"name": cty.StringVal(name), "password_wo": cty.StringVal(password)}, nil), ssh)
	key, _ := hmacKey(false)
	attrs["password_hmac"] = cty.StringVal(eosPasswordHMAC(key, eosUserID(config), password))
	return onSwitch(eosStep("conn3x_eos_user", attrs, nil), ssh), config
}

func userInSync(t *testing.T, state cty.Value) bool {
	t.Helper()
	resp := eosUserKind.read(ctx, providers.ReadResourceRequest{PriorState: state})
	if err := resp.Diagnostics.Err(); err != nil {
		t.Fatal(err)
	}
	return resp.NewState.GetAttr("in_sync").True()
}

// An account that was on the switch with another password gets the step's:
// state must not say a password is set that the switch never took. And a
// new password whose session never commits shows as out of sync at the
// next refresh, so the next apply sends it again.
func TestEOSUserSendsThePasswordTheSwitchLacks(t *testing.T) {
	t.Setenv(hmacKeyEnv, strings.Repeat("k", 32))
	f, ssh := newFakeEOS(t, block{head: "username legacy privilege 15 role network-admin secret sha512 $6$old$Hash"})
	set := func(prior cty.Value, password string, commit bool) cty.Value {
		t.Helper()
		planned, config := userStep("legacy", password, ssh)
		if prior == cty.NilVal {
			prior = cty.NullVal(planned.Type())
		}
		resp := applyEOSUser(ctx, providers.ApplyResourceChangeRequest{PriorState: prior, PlannedState: planned, Config: config})
		if err := resp.Diagnostics.Err(); err != nil {
			t.Fatal(err)
		}
		if commit {
			if err := create(commitApply, commitFor(ssh, true)); err != nil {
				t.Fatal(err)
			}
		} else {
			abortStaged() // the run stopped before the circuit's commit
		}
		return resp.NewState
	}
	key, _ := hmacKey(false)
	hashOf := func(password string) string {
		_, config := userStep("legacy", password, ssh)
		return eosSecret(key, eosUserID(config), password)
	}

	state := set(cty.NilVal, "New2", true)
	if running, _, _, _ := f.state(); !strings.Contains(running, "username legacy privilege 15 role network-admin secret sha512 "+hashOf("New2")+"\n") {
		t.Fatalf("the account that was there kept its old secret:\n%s", running)
	}
	if !userInSync(t, state) {
		t.Error("not in sync after the password was set")
	}

	rotated := set(state, "Rot8", false)
	if running, _, _, _ := f.state(); !strings.Contains(running, hashOf("New2")) {
		t.Fatalf("an uncommitted session changed the secret:\n%s", running)
	}
	if userInSync(t, rotated) {
		t.Fatal("state records a password the switch never took, and the refresh calls it in sync")
	}
	state = set(rotated, "Rot8", true)
	if running, _, _, _ := f.state(); !strings.Contains(running, hashOf("Rot8")) || !userInSync(t, state) {
		t.Errorf("the next apply didn't send the password again:\n%s", running)
	}

	// Changed by hand on the switch: a refresh sees another hash.
	f.mu.Lock()
	f.running = apply(f.running, []string{"username legacy secret sha512 $6$hand$Made"})
	f.mu.Unlock()
	if userInSync(t, state) {
		t.Error("a secret changed on the switch still reads as in sync")
	}
}

// The lowering sets circuit on every eos step, the commit and the removals,
// so each of their schemas has to take it.
func TestEOSSchemasTakeTheCircuit(t *testing.T) {
	for name, schema := range map[string]func() providers.Schema{
		"config": eosConfigSchema, "hostname": eosHostnameSchema, "vlan": eosVLANSchema, "interface": eosInterfaceSchema,
		"user": eosUserSchema, "commit": eosCommitSchema, "removals": eosRemovalsSchema,
	} {
		if a := schema().Block.Attributes["circuit"]; a == nil || !a.Optional {
			t.Errorf("conn3x_eos_%s has no optional circuit attribute", name)
		}
	}
}

// inCircuit marks a step, a commit or the removals as the lowering does.
func inCircuit(v cty.Value, circuit string) cty.Value {
	vals := v.AsValueMap()
	vals["circuit"] = cty.StringVal(circuit)
	return cty.ObjectVal(vals)
}

// Two circuits on one switch take turns at its session: the second one's
// steps wait for the first one's commit, so that commit makes live the
// first circuit's lines and nothing of the second's. When the second then
// fails, none of its lines are on the switch.
func TestEOSCircuitsTakeTurnsOnASwitch(t *testing.T) {
	f, ssh := newFakeEOS(t)
	f.refuse = "vlan 30"
	if err := create(vlanApply, inCircuit(vlanStep(10, "", ssh), "a")); err != nil {
		t.Fatal(err)
	}
	first := make(chan error, 1)
	go func() { first <- create(vlanApply, inCircuit(vlanStep(20, "", ssh), "b")) }()
	select {
	case err := <-first:
		t.Fatalf("b's step didn't wait for a's commit: %v", err)
	case <-time.After(4 * eosTurnPoll):
	}
	// b's commit has nothing of b's to commit, and leaves a's session alone.
	if err := create(commitApply, inCircuit(commitFor(ssh, true), "b")); err != nil {
		t.Fatal(err)
	}
	if running, commits, _, pending := f.state(); commits != 0 || pending != 1 || strings.Contains(running, "vlan 10") {
		t.Fatalf("after b's empty commit: %d commits, %d pending, running:\n%s", commits, pending, running)
	}
	if err := create(commitApply, inCircuit(commitFor(ssh, true), "a")); err != nil {
		t.Fatal(err)
	}
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	if running, _, _, pending := f.state(); pending != 1 || !strings.Contains(running, "vlan 10") || strings.Contains(running, "vlan 20") {
		t.Fatalf("after a's commit: %d pending sessions, running:\n%s", pending, running)
	}
	err := create(vlanApply, inCircuit(vlanStep(30, "", ssh), "b"))
	if err == nil || strings.Contains(err.Error(), "Nothing was changed") || !strings.Contains(err.Error(), "stays") {
		t.Fatalf("err = %v", err)
	}
	if running, _, _, pending := f.state(); pending != 0 || !strings.Contains(running, "vlan 10") || strings.Contains(running, "vlan 20") {
		t.Errorf("%d pending sessions, running:\n%s", pending, running)
	}
	// b is done for on this switch in this run; a third circuit is not.
	if err := create(vlanApply, inCircuit(vlanStep(21, "", ssh), "b")); err == nil || !strings.Contains(err.Error(), "not applied") {
		t.Fatalf("b's next step: err = %v", err)
	}
	if err := create(vlanApply, inCircuit(vlanStep(40, "", ssh), "c")); err != nil {
		t.Fatal(err)
	}
	if err := create(commitApply, inCircuit(commitFor(ssh, true), "c")); err != nil {
		t.Fatal(err)
	}
	if running, _, _, _ := f.state(); !strings.Contains(running, "vlan 40") || strings.Contains(running, "vlan 21") {
		t.Errorf("after c's commit, running:\n%s", running)
	}
}

// A circuit that stopped short of its commit mustn't hold the others up
// for good: after a while their steps fail, and say whose lines are waiting.
func TestEOSTurnGivesUpOnAnIdleCircuit(t *testing.T) {
	defer func(d time.Duration) { eosTurnIdle = d }(eosTurnIdle)
	eosTurnIdle = 3 * eosTurnPoll
	f, ssh := newFakeEOS(t)
	if err := create(vlanApply, inCircuit(vlanStep(10, "", ssh), "a")); err != nil {
		t.Fatal(err)
	}
	err := create(vlanApply, inCircuit(vlanStep(20, "", ssh), "b"))
	if err == nil || !strings.Contains(err.Error(), `circuit "a" has lines waiting`) {
		t.Fatalf("err = %v", err)
	}
	// a is not disturbed, and can still commit.
	if err := create(commitApply, inCircuit(commitFor(ssh, true), "a")); err != nil {
		t.Fatal(err)
	}
	if running, _, _, pending := f.state(); pending != 0 || !strings.Contains(running, "vlan 10") || strings.Contains(running, "vlan 20") {
		t.Errorf("%d pending sessions, running:\n%s", pending, running)
	}
}

// Steps outside a circuit share the switch's session as before, so a
// commit takes every line staged so far: the error mustn't say nothing
// changed when a later step fails.
func TestEOSRefusalAfterAnotherCommit(t *testing.T) {
	f, ssh := newFakeEOS(t)
	f.refuse = "vlan 30"
	for _, id := range []int{10, 20} {
		if err := create(vlanApply, vlanStep(id, "", ssh)); err != nil {
			t.Fatal(err)
		}
	}
	if err := create(commitApply, commitFor(ssh, true)); err != nil {
		t.Fatal(err)
	}
	if err := create(vlanApply, vlanStep(40, "", ssh)); err != nil {
		t.Fatal(err)
	}
	err := create(vlanApply, vlanStep(30, "", ssh))
	if err == nil || strings.Contains(err.Error(), "Nothing was changed") || !strings.Contains(err.Error(), "stays") {
		t.Fatalf("err = %v", err)
	}
	if running, _, _, pending := f.state(); pending != 0 || !strings.Contains(running, "vlan 20") || strings.Contains(running, "vlan 40") {
		t.Errorf("%d pending sessions, running:\n%s", pending, running)
	}
}

// Two circuits destroyed on one switch: each one's removals wait for its
// own conn3x_eos_removals, and the second circuit's still commit once.
func TestEOSTwoCircuitsDestroyedOnASwitch(t *testing.T) {
	f, ssh := newFakeEOS(t, block{head: "vlan 10"}, block{head: "vlan 11"}, block{head: "vlan 20"}, block{head: "vlan 21"})
	removals := func(c string) cty.Value {
		return inCircuit(onSwitch(eosStep("conn3x_eos_removals", map[string]cty.Value{"id": cty.StringVal("eos-removals")}, nil), ssh), c)
	}
	for _, c := range []string{"a", "b"} {
		if err := destroy(commitApply, inCircuit(commitFor(ssh, true), c)); err != nil {
			t.Fatal(err)
		}
	}
	if err := destroy(vlanApply, inCircuit(vlanStep(10, "", ssh), "a")); err != nil {
		t.Fatal(err)
	}
	waiting := make(chan error, 1)
	go func() { waiting <- destroy(vlanApply, inCircuit(vlanStep(20, "", ssh), "b")) }()
	if err := destroy(vlanApply, inCircuit(vlanStep(11, "", ssh), "a")); err != nil {
		t.Fatal(err)
	}
	if err := destroy(removalsApply, removals("a")); err != nil {
		t.Fatal(err)
	}
	if err := <-waiting; err != nil {
		t.Fatal(err)
	}
	if running, commits, _, pending := f.state(); commits != 1 || pending != 1 || strings.Contains(running, "vlan 10") || strings.Contains(running, "vlan 11") || !strings.Contains(running, "vlan 20") {
		t.Fatalf("after a's removals: %d commits, %d pending, running:\n%s", commits, pending, running)
	}
	if err := destroy(vlanApply, inCircuit(vlanStep(21, "", ssh), "b")); err != nil {
		t.Fatal(err)
	}
	if err := destroy(removalsApply, removals("b")); err != nil {
		t.Fatal(err)
	}
	if running, commits, _, pending := f.state(); commits != 2 || pending != 0 || strings.Contains(running, "vlan 2") {
		t.Fatalf("after b's removals: %d commits, %d pending, running:\n%s", commits, pending, running)
	}
}

// A run that stops before the commit, with a removal staged whose step is
// already forgotten: when the removal can't be committed on its own
// either, the end of the run says so, not only the log.
func TestEOSFinishReportsRemovalsLeftBehind(t *testing.T) {
	f, ssh := newFakeEOS(t, block{head: "vlan 10"})
	if err := create(vlanApply, vlanStep(30, "", ssh)); err != nil {
		t.Fatal(err)
	}
	if err := destroy(vlanApply, vlanStep(10, "", ssh)); err != nil { // staged with vlan 30
		t.Fatal(err)
	}
	if err := FinishEOS(); err != nil {
		t.Fatalf("the removal committed on its own, so nothing is left to report: %v", err)
	}
	if running, _, _, _ := f.state(); strings.Contains(running, "vlan 10") || strings.Contains(running, "vlan 30") {
		t.Fatalf("running:\n%s", running)
	}

	f.mu.Lock()
	f.running = []block{{head: "vlan 10"}}
	f.mu.Unlock()
	if err := create(vlanApply, vlanStep(30, "", ssh)); err != nil {
		t.Fatal(err)
	}
	if err := destroy(vlanApply, vlanStep(10, "", ssh)); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.refuse = "no vlan 10" // the switch won't take the removal again
	f.mu.Unlock()
	err := FinishEOS()
	if err == nil || !strings.Contains(err.Error(), "remove these by hand: no vlan 10") {
		t.Fatalf("err = %v", err)
	}
}
