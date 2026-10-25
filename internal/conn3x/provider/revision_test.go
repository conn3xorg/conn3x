// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"os"
	"testing"

	"github.com/zclconf/go-cty/cty"
)

// revision changes exactly when Conn3x changes something on the host, so a
// handler fires after a hand edit is put back, not only after a config change.

func TestRevisionSetOnCreate(t *testing.T) {
	f := newFileTest(t)
	if rev := f.create("x", nil).GetAttr("revision"); rev.IsNull() || !rev.IsKnown() || rev.AsString() == "" {
		t.Fatalf("revision after create = %#v", rev)
	}
}

func TestRevisionKeptWhenNothingChanges(t *testing.T) {
	f := newFileTest(t)
	state := f.create("x", nil)
	read := f.read(state)
	if !read.GetAttr("revision").RawEquals(state.GetAttr("revision")) {
		t.Fatal("read changed revision")
	}
	cfg := f.config(map[string]cty.Value{"content": cty.StringVal("x")})
	if got := f.plan(read, cfg).PlannedState.GetAttr("revision"); !got.RawEquals(state.GetAttr("revision")) {
		t.Fatalf("no-op plan revision = %#v", got)
	}
}

func TestRevisionChangesWhenAHandEditIsPutBack(t *testing.T) {
	f := newFileTest(t)
	state := f.create("x", nil)
	if err := os.WriteFile(f.path, []byte("edited"), 0o644); err != nil {
		t.Fatal(err)
	}
	read := f.read(state)
	cfg := f.config(map[string]cty.Value{"content": cty.StringVal("x")})
	planned := f.plan(read, cfg).PlannedState
	if planned.GetAttr("revision").IsKnown() {
		t.Fatalf("restoring a hand edit should plan a new revision, got %#v", planned.GetAttr("revision"))
	}
	after := f.apply(read, planned, cfg)
	if rev := after.GetAttr("revision"); !rev.IsKnown() || rev.IsNull() || rev.RawEquals(state.GetAttr("revision")) {
		t.Fatalf("revision after apply = %#v, before %#v", rev, state.GetAttr("revision"))
	}
}

// State from before revision existed has none; a no-op plan must not invent
// a change, or every handler would fire after an upgrade.
func TestRevisionAbsentStaysAbsent(t *testing.T) {
	f := newFileTest(t)
	state := f.create("x", nil)
	vals := state.AsValueMap()
	vals["revision"] = cty.NullVal(cty.String)
	old := cty.ObjectVal(vals)
	cfg := f.config(map[string]cty.Value{"content": cty.StringVal("x")})
	if got := f.plan(old, cfg).PlannedState.GetAttr("revision"); !got.IsNull() {
		t.Fatalf("no-op plan on old state revision = %#v, want null", got)
	}
}
