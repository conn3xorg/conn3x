// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"encoding/base64"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/zclconf/go-cty/cty"
	gossh "golang.org/x/crypto/ssh"

	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh/sshtest"
	"github.com/opentofu/opentofu/internal/providers"
)

const (
	brKeyA = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBcQ+GayZvfZ2fgg5wCe6V/EDF/qXNCZEaOYzR8+dFOw alice@laptop"
	brKeyB = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFvWy9BUnlAEkZ0c0G0YG4ioa5EmMeoVdfZtASP/AtQl bob@desk"
)

// brHomes is a host whose users have home directories under /home (root's
// is /root) and whose files are a map: the per-user reads and writes
// sshkey makes land there, as do /etc files file.Read reads.
type brHomes struct {
	mu     sync.Mutex
	users  map[string]bool
	files  map[string]string
	writes int
}

var (
	brQuotedFile = regexp.MustCompile(`f='(?:\\'')?(/[^'\\]+)`) // quoted once more by AsUser
	brPasswd     = regexp.MustCompile(`getent passwd -- '([^']+)'`)
	brEtcFile    = regexp.MustCompile(`p='(?:\\'')?(/etc/[^'\\]+)`)
)

func (b *brHomes) answer(cmd string, stdin []byte) (string, int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if m := brPasswd.FindStringSubmatch(cmd); m != nil {
		name := m[1]
		if !b.users[name] {
			return "", 2
		}
		home := "/home/" + name
		if name == "root" {
			home = "/root"
		}
		return name + ":x:1000:1000::" + home + ":/bin/sh\n", 0
	}
	if strings.Contains(cmd, "getent group -- ") || strings.Contains(cmd, "id -Gn -- ") {
		return "", 0
	}
	if m := brQuotedFile.FindStringSubmatch(cmd); m != nil {
		switch {
		case strings.Contains(cmd, "head -c"):
			return b.files[m[1]], 0
		case strings.Contains(cmd, `mv -f -- "$tmp" "$f"`):
			b.files[m[1]] = string(stdin)
			b.writes++
			return "", 0
		}
	}
	if m := brEtcFile.FindStringSubmatch(cmd); m != nil && strings.Contains(cmd, "echo present") {
		c, ok := b.files[m[1]]
		if !ok {
			return "missing\n", 0
		}
		return "present\n0644 root root\n" + base64.StdEncoding.EncodeToString([]byte(c)), 0
	}
	return "", 0
}

func (b *brHomes) file(path string) string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.files[path]
}

func (b *brHomes) set(path, content string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.files[path] = content
}

// brHomesHost is unitHost for b, which also sees each command's stdin, and
// the authorized_keys line of the key the provider logs in with.
func brHomesHost(t *testing.T, b *brHomes) (map[string]cty.Value, string) {
	t.Helper()
	s := sshtest.New(t)
	s.SetExec(func(cmd string, stdin []byte) (string, int) {
		return b.answer(strings.ReplaceAll(cmd, `'\''`, "'"), stdin)
	})
	keyFile := s.KeyFile(t)
	raw, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := gossh.ParsePrivateKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]cty.Value{
		"host":             cty.StringVal(s.Host),
		"port":             cty.NumberIntVal(int64(s.Port)),
		"user":             cty.StringVal("root"),
		"private_key_file": cty.StringVal(keyFile),
		"known_hosts_file": cty.StringVal(s.KnownHosts(t)),
		"agent":            cty.False,
	}, strings.TrimSpace(string(gossh.MarshalAuthorizedKey(signer.PublicKey())))
}

func brDestroy(t *testing.T, typeName string, state cty.Value) error {
	t.Helper()
	p, _ := New()
	return p.ApplyResourceChange(ctx, providers.ApplyResourceChangeRequest{TypeName: typeName, PriorState: state, PlannedState: cty.NullVal(state.Type())}).Diagnostics.Err()
}

// A key is added to the user's file, a refresh sees it go, and removing
// the step takes it out again, leaving the other keys.
func TestAuthorizedKeyOnAFakeHost(t *testing.T) {
	b := &brHomes{users: map[string]bool{"deploy": true, "root": true}, files: map[string]string{"/home/deploy/.ssh/authorized_keys": brKeyB + "\n"}}
	ssh, _ := brHomesHost(t, b)
	const file = "/home/deploy/.ssh/authorized_keys"
	cfg := eosStep("conn3x_authorized_key", map[string]cty.Value{"user": cty.StringVal("deploy"), "key": cty.StringVal(brKeyA)}, ssh)
	state, err := unitCreate(t, "conn3x_authorized_key", cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got := b.file(file); !strings.Contains(got, brKeyA) || !strings.Contains(got, brKeyB) {
		t.Fatalf("file %q", got)
	}
	if read, err := unitRead("conn3x_authorized_key", state); err != nil || !read.GetAttr("in_sync").True() {
		t.Fatalf("in sync: %v, %v", read, err)
	}
	b.set(file, brKeyB+"\n")
	if read, err := unitRead("conn3x_authorized_key", state); err != nil || read.GetAttr("in_sync").True() {
		t.Fatalf("after the key went: %v, %v", read, err)
	}
	b.set(file, brKeyA+"\n"+brKeyB+"\n")
	if err := brDestroy(t, "conn3x_authorized_key", state); err != nil {
		t.Fatal(err)
	}
	if got := b.file(file); strings.Contains(got, "alice") || !strings.Contains(got, "bob") {
		t.Errorf("after removal %q", got)
	}

	// A user who isn't there reads out of sync, and can't be given a key.
	gone := eosStep("conn3x_authorized_key", map[string]cty.Value{"user": cty.StringVal("ghost"), "key": cty.StringVal(brKeyA), "on_remove": cty.StringVal("delete"), "in_sync": cty.True}, ssh)
	if read, err := unitRead("conn3x_authorized_key", gone); err != nil || read.GetAttr("in_sync").True() {
		t.Errorf("a missing user: %v, %v", read, err)
	}
	if _, err := unitCreate(t, "conn3x_authorized_key", eosStep("conn3x_authorized_key", map[string]cty.Value{"user": cty.StringVal("ghost"), "key": cty.StringVal(brKeyA)}, ssh)); err == nil || !strings.Contains(err.Error(), "user ghost does not exist") {
		t.Errorf("a missing user: %v", err)
	}
}

// exclusive makes the file exactly the keys listed: a refresh names the
// others and apply removes them. For the account Conn3x logs in as, a list
// without its own key is refused.
func TestAuthorizedKeyExclusive(t *testing.T) {
	b := &brHomes{users: map[string]bool{"deploy": true, "root": true}, files: map[string]string{}}
	ssh, login := brHomesHost(t, b)
	const file = "/home/deploy/.ssh/authorized_keys"
	b.set(file, brKeyA+"\n"+brKeyB+"\n")
	cfg := eosStep("conn3x_authorized_key", map[string]cty.Value{"user": cty.StringVal("deploy"), "key": cty.StringVal(brKeyA), "exclusive": cty.True}, ssh)
	state, err := unitCreate(t, "conn3x_authorized_key", cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got := b.file(file); got != brKeyA+"\n" {
		t.Errorf("file %q", got)
	}
	if state.GetAttr("on_remove").AsString() != "forget" || state.GetAttr("unlisted").LengthInt() != 0 {
		t.Errorf("state on_remove %v unlisted %v", state.GetAttr("on_remove"), state.GetAttr("unlisted"))
	}
	// Applying again with nothing to remove writes nothing.
	writes := b.writes
	if _, err := unitCreate(t, "conn3x_authorized_key", cfg); err != nil || b.writes != writes {
		t.Errorf("a second apply: %v, %d writes", err, b.writes-writes)
	}

	b.set(file, brKeyA+"\n"+brKeyB+"\n")
	p, _ := New()
	read := p.ReadResource(ctx, providers.ReadResourceRequest{TypeName: "conn3x_authorized_key", PriorState: state})
	if read.Diagnostics.HasErrors() || read.NewState.GetAttr("in_sync").True() || read.NewState.GetAttr("unlisted").LengthInt() != 1 {
		t.Fatalf("with bob's key back: %#v, %v", read.NewState, read.Diagnostics.Err())
	}
	if len(read.Diagnostics) != 1 || !strings.Contains(read.Diagnostics[0].Description().Summary, "bob@desk") {
		t.Errorf("warnings %v", read.Diagnostics)
	}
	// Removing an exclusive step leaves the file.
	state = cty.ObjectVal(func() map[string]cty.Value {
		v := state.AsValueMap()
		v["on_remove"] = cty.StringVal("delete")
		return v
	}())
	if err := brDestroy(t, "conn3x_authorized_key", state); err != nil || b.file(file) != brKeyA+"\n"+brKeyB+"\n" {
		t.Errorf("removal: %v, file %q", err, b.file(file))
	}

	rootCfg := func(keys string) cty.Value {
		return eosStep("conn3x_authorized_key", map[string]cty.Value{"user": cty.StringVal("root"), "key": cty.StringVal(keys), "exclusive": cty.True}, ssh)
	}
	if _, err := unitCreate(t, "conn3x_authorized_key", rootCfg(brKeyA)); err == nil || !strings.Contains(err.Error(), "which key doesn't list") {
		t.Errorf("a list without the login key: %v", err)
	}
	if _, err := unitCreate(t, "conn3x_authorized_key", rootCfg(brKeyA+"\n"+login)); err != nil {
		t.Errorf("a list with the login key: %v", err)
	}
	if got := b.file("/root/.ssh/authorized_keys"); !strings.Contains(got, login) {
		t.Errorf("root's file %q", got)
	}
}

func TestAuthorizedKeyValidatesAndPlans(t *testing.T) {
	ssh := map[string]cty.Value{}
	for want, attrs := range map[string]map[string]cty.Value{
		`state must be "present" or "absent"`: {"user": cty.StringVal("deploy"), "key": cty.StringVal(brKeyA), "state": cty.StringVal("gone")},
		"user name":                           {"user": cty.StringVal("-x"), "key": cty.StringVal(brKeyA)},
		"exclusive keeps the keys in key":     {"user": cty.StringVal("deploy"), "key": cty.StringVal(brKeyA), "exclusive": cty.True, "state": cty.StringVal("absent")},
		"would lock out everyone":             {"user": cty.StringVal("deploy"), "key": cty.StringVal(brKeyA), "exclusive": cty.True, "on_remove": cty.StringVal("delete")},
	} {
		d := validateAuthorizedKey(eosStep("conn3x_authorized_key", attrs, ssh))
		if !d.HasErrors() || !strings.Contains(d.Err().Error(), want) {
			t.Errorf("%v: %v, want %q", attrs, d.Err(), want)
		}
	}
	if d := validateAuthorizedKey(eosStep("conn3x_authorized_key", map[string]cty.Value{"user": cty.UnknownVal(cty.String)}, ssh)); d.HasErrors() {
		t.Errorf("unknown: %v", d.Err())
	}

	base := map[string]cty.Value{"user": cty.StringVal("deploy"), "key": cty.StringVal(brKeyA), "on_remove": cty.StringVal("delete"), "in_sync": cty.True, "state": cty.NullVal(cty.String)}
	prior := eosStep("conn3x_authorized_key", base, ssh)
	plan := func(changes map[string]cty.Value, sshChanges map[string]cty.Value) providers.PlanResourceChangeResponse {
		attrs := map[string]cty.Value{}
		for k, v := range base {
			attrs[k] = v
		}
		for k, v := range changes {
			attrs[k] = v
		}
		next := eosStep("conn3x_authorized_key", attrs, sshChanges)
		return planAuthorizedKey(providers.PlanResourceChangeRequest{PriorState: prior, ProposedNewState: next, Config: next})
	}
	if r := plan(nil, nil); len(r.RequiresReplace) != 0 || !r.PlannedState.GetAttr("in_sync").True() {
		t.Errorf("unchanged: %v, %v", r.RequiresReplace, r.PlannedState.GetAttr("in_sync"))
	}
	if r := plan(nil, map[string]cty.Value{"host": cty.StringVal("leaf2")}); len(r.RequiresReplace) != 1 {
		t.Errorf("another host: %v", r.RequiresReplace)
	}
	if r := plan(map[string]cty.Value{"state": cty.StringVal("absent")}, nil); r.PlannedState.GetAttr("in_sync").IsKnown() {
		t.Error("a new state planned in sync")
	}
	if r := plan(map[string]cty.Value{"user": cty.UnknownVal(cty.String)}, nil); r.PlannedState.GetAttr("id").IsKnown() {
		t.Error("an unknown user planned a known id")
	}
	// An exclusive list that changes updates in place, and one that read
	// unlisted keys plans to remove them.
	exclusive := map[string]cty.Value{"exclusive": cty.True, "unlisted": cty.ListValEmpty(cty.String)}
	for k, v := range exclusive {
		base[k] = v
	}
	prior = eosStep("conn3x_authorized_key", base, ssh)
	if r := plan(nil, nil); !r.PlannedState.GetAttr("in_sync").True() {
		t.Error("an unchanged exclusive list planned stale")
	}
	if r := plan(map[string]cty.Value{"key": cty.StringVal(brKeyA + "\n" + brKeyB)}, nil); len(r.RequiresReplace) != 0 || r.PlannedState.GetAttr("in_sync").IsKnown() {
		t.Errorf("a longer list: replace %v, in_sync %v", r.RequiresReplace, r.PlannedState.GetAttr("in_sync"))
	}
	if r := planAuthorizedKey(providers.PlanResourceChangeRequest{PriorState: prior, ProposedNewState: cty.NullVal(prior.Type())}); !r.PlannedState.IsNull() {
		t.Error("planned a removal as something")
	}
}

// A known host goes into the user's known_hosts, and state = "absent"
// takes every key of the host out.
func TestKnownHostsOnAFakeHost(t *testing.T) {
	b := &brHomes{users: map[string]bool{"deploy": true}, files: map[string]string{}}
	ssh, _ := brHomesHost(t, b)
	const file = "/home/deploy/.ssh/known_hosts"
	cfg := eosStep("conn3x_known_hosts", map[string]cty.Value{"host": cty.StringVal("git.example"), "key": cty.StringVal(brKeyA), "user": cty.StringVal("deploy")}, ssh)
	state, err := unitCreate(t, "conn3x_known_hosts", cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got := b.file(file); !strings.HasPrefix(got, "git.example ssh-ed25519 ") {
		t.Fatalf("file %q", got)
	}
	if read, err := unitRead("conn3x_known_hosts", state); err != nil || !read.GetAttr("in_sync").True() {
		t.Errorf("in sync: %v, %v", read, err)
	}
	if err := brDestroy(t, "conn3x_known_hosts", state); err != nil {
		t.Fatal(err)
	}
	if got := b.file(file); strings.Contains(got, "git.example") {
		t.Errorf("after removal %q", got)
	}
	// Keeping a host out had nothing to take back.
	writes := b.writes
	absent := eosStep("conn3x_known_hosts", map[string]cty.Value{"host": cty.StringVal("git.example"), "user": cty.StringVal("deploy"), "state": cty.StringVal("absent"), "on_remove": cty.StringVal("delete")}, ssh)
	if err := brDestroy(t, "conn3x_known_hosts", absent); err != nil || b.writes != writes {
		t.Errorf("removing an absent step: %v, %d writes", err, b.writes-writes)
	}

	// The system file is read whole; a missing one has nothing to remove.
	b.set("/etc/ssh/ssh_known_hosts", "git.example "+strings.Join(strings.Fields(brKeyA)[:2], " ")+"\n")
	system := eosStep("conn3x_known_hosts", map[string]cty.Value{"host": cty.StringVal("git.example"), "key": cty.StringVal(brKeyA), "on_remove": cty.StringVal("delete"), "in_sync": cty.False}, ssh)
	if read, err := unitRead("conn3x_known_hosts", system); err != nil || !read.GetAttr("in_sync").True() {
		t.Errorf("the system file: %v, %v", read, err)
	}
	b.mu.Lock()
	delete(b.files, "/etc/ssh/ssh_known_hosts")
	b.mu.Unlock()
	if err := brDestroy(t, "conn3x_known_hosts", system); err != nil {
		t.Errorf("removing from a missing system file: %v", err)
	}
	// A user who isn't there reads out of sync, and can't be changed.
	ghost := eosStep("conn3x_known_hosts", map[string]cty.Value{"host": cty.StringVal("git.example"), "key": cty.StringVal(brKeyA), "user": cty.StringVal("ghost"), "on_remove": cty.StringVal("delete"), "in_sync": cty.True}, ssh)
	if read, err := unitRead("conn3x_known_hosts", ghost); err != nil || read.GetAttr("in_sync").True() {
		t.Errorf("a missing user: %v, %v", read, err)
	}
	if err := brDestroy(t, "conn3x_known_hosts", ghost); err == nil {
		t.Error("removed a key from a user who isn't there")
	}
}

func TestKnownHostsValidatesAndPlans(t *testing.T) {
	ssh := map[string]cty.Value{}
	for want, attrs := range map[string]map[string]cty.Value{
		"":                           {"host": cty.StringVal("[git.example]:2222"), "key": cty.StringVal(brKeyA), "user": cty.StringVal("deploy")},
		`state must be "present" or`: {"host": cty.StringVal("git.example"), "key": cty.StringVal(brKeyA), "state": cty.StringVal("gone")},
		"key is required unless":     {"host": cty.StringVal("git.example")},
		"leave key out with state":   {"host": cty.StringVal("git.example"), "key": cty.StringVal(brKeyA), "state": cty.StringVal("absent")},
		"user name":                  {"host": cty.StringVal("git.example"), "key": cty.StringVal(brKeyA), "user": cty.StringVal("-x")},
		"must be lowercase":          {"host": cty.StringVal("Git.example"), "key": cty.StringVal(brKeyA)},
		`on_remove must be`:          {"host": cty.StringVal("git.example"), "key": cty.StringVal(brKeyA), "on_remove": cty.StringVal("keep")},
	} {
		d := validateKnownHosts(eosStep("conn3x_known_hosts", attrs, ssh))
		if want == "" {
			if d.HasErrors() {
				t.Errorf("%v: %v", attrs, d.Err())
			}
			continue
		}
		if !d.HasErrors() || !strings.Contains(d.Err().Error(), want) {
			t.Errorf("%v: %v, want %q", attrs, d.Err(), want)
		}
	}
	if d := validateKnownHosts(eosStep("conn3x_known_hosts", map[string]cty.Value{"host": cty.UnknownVal(cty.String)}, ssh)); d.HasErrors() {
		t.Errorf("unknown: %v", d.Err())
	}

	base := map[string]cty.Value{"host": cty.StringVal("git.example"), "key": cty.StringVal(brKeyA), "on_remove": cty.StringVal("delete"), "in_sync": cty.True}
	prior := eosStep("conn3x_known_hosts", base, ssh)
	plan := func(changes, sshChanges map[string]cty.Value) providers.PlanResourceChangeResponse {
		attrs := map[string]cty.Value{}
		for k, v := range base {
			attrs[k] = v
		}
		for k, v := range changes {
			attrs[k] = v
		}
		next := eosStep("conn3x_known_hosts", attrs, sshChanges)
		return planKnownHosts(providers.PlanResourceChangeRequest{PriorState: prior, ProposedNewState: next, Config: next})
	}
	if r := plan(nil, nil); len(r.RequiresReplace) != 0 || !r.PlannedState.GetAttr("in_sync").True() || r.PlannedState.GetAttr("id").AsString() == "" {
		t.Errorf("unchanged: %v, %#v", r.RequiresReplace, r.PlannedState)
	}
	if r := plan(map[string]cty.Value{"key": cty.StringVal(brKeyB)}, nil); len(r.RequiresReplace) != 1 || r.PlannedState.GetAttr("in_sync").IsKnown() {
		t.Errorf("another key: %v", r.RequiresReplace)
	}
	if r := plan(nil, map[string]cty.Value{"host": cty.StringVal("leaf2")}); len(r.RequiresReplace) != 1 {
		t.Errorf("another machine: %v", r.RequiresReplace)
	}
	if r := plan(map[string]cty.Value{"state": cty.StringVal("present")}, nil); r.PlannedState.GetAttr("in_sync").IsKnown() {
		t.Error("a new state planned in sync")
	}
	if r := plan(map[string]cty.Value{"host": cty.UnknownVal(cty.String)}, nil); r.PlannedState.GetAttr("id").IsKnown() {
		t.Error("an unknown host planned a known id")
	}
	if r := planKnownHosts(providers.PlanResourceChangeRequest{PriorState: prior, ProposedNewState: cty.NullVal(prior.Type())}); !r.PlannedState.IsNull() {
		t.Error("planned a removal as something")
	}
}
