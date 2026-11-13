// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
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

// fakeJunos answers the way vJunos-switch 26.2R1.7 did, closely enough for
// the staging path: set lines in a candidate, commit check, commit confirmed
// with its banner until a commit check from a new login confirms it, and a
// syntax error for any line holding refuse.
type fakeJunos struct {
	mu       sync.Mutex
	running  []string
	refuse   string
	pending  bool
	commits  int // commit confirmed
	confirms int
	scripts  int // shell sessions
}

func newFakeJunos(t *testing.T, running ...string) (*fakeJunos, cty.Value) {
	t.Helper()
	s := sshtest.New(t)
	f := &fakeJunos{running: running}
	s.SetExec(f.run)
	conn := map[string]cty.Value{
		"host":             cty.StringVal(s.Host),
		"port":             cty.NumberIntVal(int64(s.Port)),
		"user":             cty.StringVal("ops"),
		"private_key_file": cty.StringVal(s.KeyFile(t)),
		"known_hosts_file": cty.StringVal(s.KnownHosts(t)),
		"confirm_after":    cty.StringVal("10ms"), // validate refuses this; apply only waits it out
	}
	t.Cleanup(func() { _ = FinishEOS() })
	return f, eosStep("conn3x_junos_commit", nil, conn).GetAttr("ssh")
}

func (f *fakeJunos) run(cmd string, stdin []byte) (string, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if strings.HasPrefix(cmd, "show configuration | display set") {
		return strings.Join(f.running, "\n") + "\n", 0
	}
	if cmd != "" {
		return "error: syntax error, expecting <command>: " + cmd + "\n", 0
	}
	f.scripts++
	lines := strings.Split(strings.TrimSpace(string(stdin)), "\n")
	var b strings.Builder
	candidate := slices.Clone(f.running)
	for _, l := range lines {
		b.WriteString("ops# " + l + "\n")
		switch {
		case strings.HasPrefix(l, "configure"):
			b.WriteString("Entering configuration mode\n")
			if f.pending {
				b.WriteString("# commit confirmed will be rolled back in 4 minutes\n")
			}
		case f.refuse != "" && strings.Contains(l, f.refuse):
			b.WriteString("                    ^\nsyntax error.\n")
		case strings.HasPrefix(l, "set "):
			if !slices.Contains(candidate, l) {
				candidate = append(candidate, l)
			}
		case strings.HasPrefix(l, "delete "):
			rest := "set " + strings.TrimPrefix(l, "delete ")
			candidate = slices.DeleteFunc(candidate, func(c string) bool { return c == rest || strings.HasPrefix(c, rest+" ") })
		case l == "commit check":
			if f.pending && lines[0] == "configure exclusive" && len(lines) == 3 {
				f.pending = false
				f.confirms++
			}
			b.WriteString("configuration check succeeds\n")
		case strings.HasPrefix(l, "commit confirmed"):
			f.running, f.pending = candidate, true
			f.commits++
			b.WriteString("commit confirmed will be automatically rolled back in 5 minutes unless confirmed\ncommit complete\n")
		}
	}
	return b.String(), 0
}

func (f *fakeJunos) state() (running []string, commits, confirms int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.running), f.commits, f.confirms
}

func junosVLAN(name string, id int, circuit string, ssh cty.Value) cty.Value {
	attrs := map[string]cty.Value{
		"name":      cty.StringVal(name),
		"vlan_id":   cty.NumberIntVal(int64(id)),
		"on_remove": cty.StringVal(onRemoveDelete),
	}
	if circuit != "" {
		attrs["circuit"] = cty.StringVal(circuit)
	}
	return onSwitch(eosStep("conn3x_junos_vlan", attrs, nil), ssh)
}

func junosCommitFor(circuit string, ssh cty.Value) cty.Value {
	return onSwitch(eosStep("conn3x_junos_commit", map[string]cty.Value{
		"id": cty.StringVal("junos-commit"), "circuit": cty.StringVal(circuit), "removals": cty.StringVal("junos-removals"),
	}, nil), ssh)
}

func junosRemovalsFor(circuit string, ssh cty.Value) cty.Value {
	return onSwitch(eosStep("conn3x_junos_removals", map[string]cty.Value{
		"id": cty.StringVal("junos-removals"), "circuit": cty.StringVal(circuit),
	}, nil), ssh)
}

func junosVLANApply(req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	return junosVLANKind.apply(ctx, req)
}

func junosCommitApply(req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	return applyCLICommit(junosPlatform)(ctx, req)
}

func junosRemovalsApply(req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	return applyCLIRemovals(junosPlatform)(ctx, req)
}

// Three steps in a circuit stage their lines, and its commit sends them in
// one commit confirmed with one confirm.
func TestJunosStepsShareOneCommit(t *testing.T) {
	f, ssh := newFakeJunos(t, "set system host-name sw1")
	for i, name := range []string{"web", "db", "voice"} {
		if err := create(junosVLANApply, junosVLAN(name, 10*(i+1), "lab", ssh)); err != nil {
			t.Fatal(err)
		}
	}
	if running, commits, _ := f.state(); commits != 0 || len(running) != 1 {
		t.Fatalf("before the commit: %d commits, running %q", commits, running)
	}
	if err := create(junosCommitApply, junosCommitFor("lab", ssh)); err != nil {
		t.Fatal(err)
	}
	running, commits, confirms := f.state()
	if commits != 1 || confirms != 1 {
		t.Errorf("%d commits, %d confirms; want 1 and 1", commits, confirms)
	}
	for _, want := range []string{"set vlans web vlan-id 10", "set vlans db vlan-id 20", "set vlans voice vlan-id 30"} {
		if !slices.Contains(running, want) {
			t.Errorf("running is missing %q: %q", want, running)
		}
	}
}

// A refused line fails its step, drops what the circuit staged before it,
// and the commit sends nothing.
func TestJunosRefusedStepDropsTheCircuit(t *testing.T) {
	f, ssh := newFakeJunos(t)
	f.refuse = "vlans db"
	if err := create(junosVLANApply, junosVLAN("web", 10, "lab", ssh)); err != nil {
		t.Fatal(err)
	}
	err := create(junosVLANApply, junosVLAN("db", 20, "lab", ssh))
	if err == nil || !strings.Contains(err.Error(), "Nothing was changed") {
		t.Fatalf("refused step: err = %v", err)
	}
	if err := create(junosVLANApply, junosVLAN("voice", 30, "lab", ssh)); err == nil || !strings.Contains(err.Error(), "not applied") {
		t.Errorf("a step after the refusal: err = %v", err)
	}
	if err := create(junosCommitApply, junosCommitFor("lab", ssh)); err == nil || !strings.Contains(err.Error(), "nothing was committed") {
		t.Errorf("commit: err = %v", err)
	}
	if running, commits, _ := f.state(); commits != 0 || len(running) != 0 {
		t.Errorf("%d commits, running %q", commits, running)
	}
}

// Destroying a circuit stages every removal behind its commit, and
// conn3x_junos_removals commits them once.
func TestJunosDestroyCommitsRemovalsOnce(t *testing.T) {
	f, ssh := newFakeJunos(t, "set vlans web vlan-id 10", "set vlans db vlan-id 20", "set vlans keep vlan-id 99")
	if err := destroy(junosCommitApply, junosCommitFor("lab", ssh)); err != nil {
		t.Fatal(err)
	}
	for _, v := range []cty.Value{junosVLAN("web", 10, "lab", ssh), junosVLAN("db", 20, "lab", ssh)} {
		if err := destroy(junosVLANApply, v); err != nil {
			t.Fatal(err)
		}
	}
	if _, commits, _ := f.state(); commits != 0 {
		t.Fatalf("%d commits before conn3x_junos_removals", commits)
	}
	if err := destroy(junosRemovalsApply, junosRemovalsFor("lab", ssh)); err != nil {
		t.Fatal(err)
	}
	running, commits, _ := f.state()
	if commits != 1 || !slices.Equal(running, []string{"set vlans keep vlan-id 99"}) {
		t.Errorf("%d commits, running %q", commits, running)
	}
}

// A step outside a circuit has no commit coming, and a step dropped from a
// circuit that stays has none either: both commit on their own.
func TestJunosStepsWithoutACommitCommitAlone(t *testing.T) {
	f, ssh := newFakeJunos(t, "set vlans old vlan-id 5")
	if err := create(junosVLANApply, junosVLAN("web", 10, "", ssh)); err != nil {
		t.Fatal(err)
	}
	if err := destroy(junosVLANApply, junosVLAN("old", 5, "lab", ssh)); err != nil {
		t.Fatal(err)
	}
	running, commits, confirms := f.state()
	if commits != 2 || confirms != 2 || !slices.Equal(running, []string{"set vlans web vlan-id 10"}) {
		t.Errorf("%d commits, %d confirms, running %q", commits, confirms, running)
	}
}

// While a commit confirmed waits, a step refuses before it stages anything.
func TestJunosStepRefusesWhileACommitIsPending(t *testing.T) {
	f, ssh := newFakeJunos(t)
	f.pending = true
	err := create(junosVLANApply, junosVLAN("web", 10, "lab", ssh))
	if err == nil || !strings.Contains(err.Error(), "waiting for its confirm") {
		t.Fatalf("err = %v", err)
	}
}

// A circuit whose lines sit staged and idle doesn't block another forever.
func TestJunosTurnGivesUpOnAnIdleCircuit(t *testing.T) {
	_, ssh := newFakeJunos(t)
	idle := eosTurnIdle
	eosTurnIdle = 100 * time.Millisecond
	t.Cleanup(func() { eosTurnIdle = idle })
	if err := create(junosVLANApply, junosVLAN("web", 10, "first", ssh)); err != nil {
		t.Fatal(err)
	}
	err := create(junosVLANApply, junosVLAN("db", 20, "second", ssh))
	if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("circuit %q has lines staged", "first")) {
		t.Fatalf("err = %v", err)
	}
}

// Disabling the interface that holds the address Conn3x connects to fails
// its step and drops what the circuit staged.
func TestJunosInterfaceGuard(t *testing.T) {
	f, ssh := newFakeJunos(t, "set interfaces ge-0/0/3 unit 0 family inet address "+ssh0(t)+"/24")
	step := onSwitch(eosStep("conn3x_junos_interface", map[string]cty.Value{
		"name": cty.StringVal("ge-0/0/3"), "enabled": cty.False, "circuit": cty.StringVal("lab"),
	}, nil), ssh)
	err := create(func(req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
		return junosInterfaceKind.apply(ctx, req)
	}, step)
	if err == nil || !strings.Contains(err.Error(), "would cut it off") {
		t.Fatalf("err = %v", err)
	}
	if _, commits, _ := f.state(); commits != 0 {
		t.Errorf("%d commits", commits)
	}
}

// ssh0 is the address sshtest servers listen on, the one Conn3x connects to.
func ssh0(t *testing.T) string {
	t.Helper()
	return sshtest.New(t).Host
}

// A password goes to the device as a salted hash, the read finds it in
// sync, and a hash changed by hand reads as out of sync.
func TestJunosUserPassword(t *testing.T) {
	t.Setenv(hmacKeyEnv, strings.Repeat("k", 32))
	f, ssh := newFakeJunos(t, "set system login user ops class super-user")
	attrs := map[string]cty.Value{"name": cty.StringVal("alice"), "class": cty.StringVal("operator"), "on_remove": cty.StringVal(onRemoveDelete), "circuit": cty.StringVal("lab")}
	config := onSwitch(eosStep("conn3x_junos_user", map[string]cty.Value{"name": cty.StringVal("alice"), "class": cty.StringVal("operator"), "password_wo": cty.StringVal("S3cret!")}, nil), ssh)
	key, _ := hmacKey(false)
	attrs["password_hmac"] = cty.StringVal(eosPasswordHMAC(key, junosUserID(config), "S3cret!"))
	planned := onSwitch(eosStep("conn3x_junos_user", attrs, nil), ssh)
	resp := applyJunosUser(ctx, providers.ApplyResourceChangeRequest{PriorState: cty.NullVal(planned.Type()), PlannedState: planned, Config: config})
	if err := resp.Diagnostics.Err(); err != nil {
		t.Fatal(err)
	}
	if err := create(junosCommitApply, junosCommitFor("lab", ssh)); err != nil {
		t.Fatal(err)
	}
	hash := eosSecret(key, junosUserID(config), "S3cret!")
	running, _, _ := f.state()
	if !slices.Contains(running, `set system login user alice authentication encrypted-password "`+hash+`"`) {
		t.Fatalf("no hash on the device: %q", running)
	}
	for _, l := range running {
		if strings.Contains(l, "S3cret!") {
			t.Fatalf("the password itself reached the device: %q", l)
		}
	}
	inSync := func() bool {
		r := junosUserKind.read(ctx, providers.ReadResourceRequest{PriorState: resp.NewState})
		if err := r.Diagnostics.Err(); err != nil {
			t.Fatal(err)
		}
		return r.NewState.GetAttr("in_sync").True()
	}
	if !inSync() {
		t.Error("not in sync after the password was set")
	}
	f.mu.Lock()
	for n, l := range f.running {
		if strings.Contains(l, "encrypted-password") {
			f.running[n] = `set system login user alice authentication encrypted-password "$6$hand$Made"`
		}
	}
	f.mu.Unlock()
	if inSync() {
		t.Error("a hash changed on the device still reads as in sync")
	}
}
