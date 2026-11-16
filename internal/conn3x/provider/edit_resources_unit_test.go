// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh/sshtest"
	"github.com/opentofu/opentofu/internal/providers"
)

// brShellHost is a host over SSH whose shell is this machine's sh, and the
// ssh block's attributes that reach it, and a directory to work in.
func brShellHost(t *testing.T) (map[string]cty.Value, string) {
	t.Helper()
	s := sshtest.New(t)
	return map[string]cty.Value{
		"host":             cty.StringVal(s.Host),
		"port":             cty.NumberIntVal(int64(s.Port)),
		"user":             cty.StringVal("test"),
		"private_key_file": cty.StringVal(s.KeyFile(t)),
		"known_hosts_file": cty.StringVal(s.KnownHosts(t)),
		"agent":            cty.False,
	}, s.Dir
}

// brWith is v with attrs replaced.
func brWith(v cty.Value, attrs map[string]cty.Value) cty.Value {
	vals := v.AsValueMap()
	for k, a := range attrs {
		vals[k] = a
	}
	return cty.ObjectVal(vals)
}

// An option a step keeps out of a file is in sync while the file is
// missing, and neither applying nor removing the step creates it. Once the
// file has the option, a refresh says so, and with on_remove = "delete"
// removing the step takes it out.
func TestINIStepOnAFile(t *testing.T) {
	ssh, dir := brShellHost(t)
	path := filepath.Join(dir, "app.ini")
	cfg := func(attrs map[string]cty.Value) cty.Value {
		a := map[string]cty.Value{"path": cty.StringVal(path), "section": cty.StringVal("db"), "option": cty.StringVal("host")}
		for k, v := range attrs {
			a[k] = v
		}
		return eosStep("conn3x_ini", a, ssh)
	}
	absent := cfg(map[string]cty.Value{"state": cty.StringVal("absent")})
	state, err := unitCreate(t, "conn3x_ini", absent)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("keeping an option out created the file: %v", err)
	}
	if read, err := unitRead("conn3x_ini", state); err != nil || !read.GetAttr("in_sync").True() {
		t.Errorf("a missing file: %v, %v", read, err)
	}
	if err := brDestroy(t, "conn3x_ini", brWith(state, map[string]cty.Value{"on_remove": cty.StringVal(onRemoveDelete)})); err != nil {
		t.Errorf("removing from a missing file: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("removing the step created the file: %v", err)
	}

	present := cfg(map[string]cty.Value{"value": cty.StringVal("db1")})
	if _, err := unitCreate(t, "conn3x_ini", present); err == nil || !strings.Contains(err.Error(), "set create = true") {
		t.Errorf("a missing file without create: %v", err)
	}
	present = cfg(map[string]cty.Value{"value": cty.StringVal("db1"), "create": cty.True})
	state, err = unitCreate(t, "conn3x_ini", present)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(path); !strings.Contains(string(b), "host = db1") {
		t.Fatalf("file %q", b)
	}
	if read, err := unitRead("conn3x_ini", state); err != nil || !read.GetAttr("in_sync").True() {
		t.Errorf("in sync: %v, %v", read, err)
	}
	if read, err := unitRead("conn3x_ini", brWith(state, map[string]cty.Value{"state": cty.StringVal("absent"), "value": cty.NullVal(cty.String)})); err == nil && read.GetAttr("in_sync").True() {
		t.Error("an option that's there read in sync with state = absent")
	}
	if err := os.WriteFile(path, []byte("[db]\nhost = db2\nport = 5432\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	read, err := unitRead("conn3x_ini", state)
	if err != nil || read.GetAttr("in_sync").True() {
		t.Fatalf("after an edit: %v, %v", read, err)
	}

	// The plan reruns a step that drifted or changed, and nothing else.
	p, _ := New()
	again := p.PlanResourceChange(ctx, providers.PlanResourceChangeRequest{TypeName: "conn3x_ini", PriorState: read, ProposedNewState: read, Config: present})
	if again.PlannedState.GetAttr("in_sync").IsKnown() {
		t.Error("a drifted step planned in sync")
	}
	still := p.PlanResourceChange(ctx, providers.PlanResourceChangeRequest{TypeName: "conn3x_ini", PriorState: state, ProposedNewState: state, Config: present})
	if !still.PlannedState.GetAttr("in_sync").True() {
		t.Error("an unchanged step planned out of sync")
	}
	moved := brWith(state, map[string]cty.Value{"value": cty.StringVal("db3")})
	if r := p.PlanResourceChange(ctx, providers.PlanResourceChangeRequest{TypeName: "conn3x_ini", PriorState: state, ProposedNewState: moved, Config: moved}); r.PlannedState.GetAttr("in_sync").IsKnown() {
		t.Error("a new value planned in sync")
	}

	// Removing it leaves the file unless on_remove = "delete".
	if err := brDestroy(t, "conn3x_ini", state); err != nil || state.GetAttr("on_remove").AsString() != onRemoveForget {
		t.Fatalf("on_remove %v: %v", state.GetAttr("on_remove"), err)
	}
	if b, _ := os.ReadFile(path); !strings.Contains(string(b), "host = db2") {
		t.Errorf("forgetting it changed the file: %q", b)
	}
	if err := brDestroy(t, "conn3x_ini", brWith(state, map[string]cty.Value{"on_remove": cty.StringVal(onRemoveDelete)})); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(path); strings.Contains(string(b), "host") || !strings.Contains(string(b), "port = 5432") {
		t.Errorf("after removal %q", b)
	}
}

// A file that can't be read is the error, for a refresh and an apply.
func TestEditStepsOnAnUnreadableFile(t *testing.T) {
	ssh, dir := brShellHost(t)
	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	// A directory where the file should be isn't a file to edit.
	for typeName, attrs := range map[string]map[string]cty.Value{
		"conn3x_line": {"path": cty.StringVal(sub), "line": cty.StringVal("x=1")},
		"conn3x_ini":  {"path": cty.StringVal(sub), "option": cty.StringVal("x"), "state": cty.StringVal("absent")},
	} {
		cfg := eosStep(typeName, attrs, ssh)
		if _, err := unitCreate(t, typeName, cfg); err == nil {
			t.Errorf("%s: edited a directory", typeName)
		}
		vals := cfg.AsValueMap()
		vals["on_remove"], vals["in_sync"], vals["id"] = cty.StringVal(onRemoveDelete), cty.True, cty.StringVal("x")
		if _, err := unitRead(typeName, cty.ObjectVal(vals)); err == nil {
			t.Errorf("%s: read a directory", typeName)
		}
		if err := brDestroy(t, typeName, cty.ObjectVal(vals)); err == nil {
			t.Errorf("%s: removed from a directory", typeName)
		}
	}
}
