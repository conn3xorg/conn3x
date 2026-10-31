// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/providers"
)

// dirTest drives conn3x_directory against the test SSH server, as fileTest
// does conn3x_file.
type dirTest struct{ *fileTest }

func newDirTest(t *testing.T) *dirTest {
	f := newFileTest(t)
	f.path = filepath.Join(f.server.Dir, "app")
	return &dirTest{f}
}

func (d *dirTest) config(attrs map[string]cty.Value) cty.Value {
	vals := objFor(directorySchema(), attrs).AsValueMap()
	vals["path"], vals["ssh"] = cty.StringVal(d.path), d.conn
	return cty.ObjectVal(vals)
}

func (d *dirTest) plan(prior, config cty.Value) providers.PlanResourceChangeResponse {
	d.t.Helper()
	proposed := config
	if !prior.IsNull() {
		vals := config.AsValueMap()
		for _, name := range []string{"id", "revision", "mode", "on_remove", "in_sync"} {
			if vals[name].IsNull() {
				vals[name] = prior.GetAttr(name)
			}
		}
		proposed = cty.ObjectVal(vals)
	}
	resp := d.p.PlanResourceChange(ctx, providers.PlanResourceChangeRequest{
		TypeName: "conn3x_directory", PriorState: prior, ProposedNewState: proposed, Config: config,
	})
	if resp.Diagnostics.HasErrors() {
		d.t.Fatalf("plan: %s", resp.Diagnostics.Err())
	}
	return resp
}

func (d *dirTest) tryApply(prior, planned, config cty.Value) providers.ApplyResourceChangeResponse {
	return d.p.ApplyResourceChange(ctx, providers.ApplyResourceChangeRequest{
		TypeName: "conn3x_directory", PriorState: prior, PlannedState: planned, Config: config,
	})
}

func (d *dirTest) apply(prior, planned, config cty.Value) cty.Value {
	d.t.Helper()
	resp := d.tryApply(prior, planned, config)
	if resp.Diagnostics.HasErrors() {
		d.t.Fatalf("apply: %s", resp.Diagnostics.Err())
	}
	return resp.NewState
}

func (d *dirTest) read(prior cty.Value) cty.Value {
	d.t.Helper()
	resp := d.p.ReadResource(ctx, providers.ReadResourceRequest{TypeName: "conn3x_directory", PriorState: prior})
	if resp.Diagnostics.HasErrors() {
		d.t.Fatalf("read: %s", resp.Diagnostics.Err())
	}
	return resp.NewState
}

// applyAbsent plans and applies state = "absent" over prior.
func (d *dirTest) applyAbsent(prior cty.Value) cty.Value {
	d.t.Helper()
	cfg := d.config(absent)
	if prior == cty.NilVal {
		prior = cty.NullVal(cfg.Type())
	}
	return d.apply(prior, d.plan(prior, cfg).PlannedState, cfg)
}

// tryAbsent applies state = "absent" to a path that wasn't managed before.
func (d *dirTest) tryAbsent() providers.ApplyResourceChangeResponse {
	cfg := d.config(absent)
	null := cty.NullVal(cfg.Type())
	return d.tryApply(null, d.plan(null, cfg).PlannedState, cfg)
}

func TestDirectoryAbsentRemovesEmptyDirectory(t *testing.T) {
	d := newDirTest(t)
	if err := os.Mkdir(d.path, 0o755); err != nil {
		t.Fatal(err)
	}
	state := d.applyAbsent(cty.NilVal)
	if _, err := os.Lstat(d.path); !os.IsNotExist(err) {
		t.Fatal("directory still exists with state = absent")
	}
	if got := state.GetAttr("in_sync"); !got.RawEquals(cty.True) {
		t.Fatalf("in_sync = %#v, want true", got)
	}
	if !state.GetAttr("mode").IsNull() {
		t.Errorf("mode = %#v, want null", state.GetAttr("mode"))
	}

	// Once gone, the next plan changes nothing.
	read := d.read(state)
	if planned := d.plan(read, d.config(absent)).PlannedState; !planned.RawEquals(read) {
		t.Fatalf("second plan changes something:\nplanned %#v\nprior   %#v", planned, read)
	}
}

func TestDirectoryAbsentMissingPathPlansClean(t *testing.T) {
	d := newDirTest(t)
	state := d.applyAbsent(cty.NilVal)
	if planned := d.plan(d.read(state), d.config(absent)).PlannedState; !planned.GetAttr("in_sync").RawEquals(cty.True) {
		t.Fatalf("in_sync = %#v, want true", planned.GetAttr("in_sync"))
	}
}

func TestDirectoryAbsentKeepsItGone(t *testing.T) {
	d := newDirTest(t)
	state := d.applyAbsent(cty.NilVal)
	if err := os.Mkdir(d.path, 0o755); err != nil {
		t.Fatal(err)
	}
	read := d.read(state)
	if got := read.GetAttr("in_sync"); !got.RawEquals(cty.False) {
		t.Fatalf("in_sync after the directory came back = %#v, want false", got)
	}
	planned := d.plan(read, d.config(absent)).PlannedState
	if planned.GetAttr("in_sync").IsKnown() {
		t.Fatal("plan shows no change for a directory that came back")
	}
	d.apply(read, planned, d.config(absent))
	if _, err := os.Lstat(d.path); !os.IsNotExist(err) {
		t.Fatal("directory not removed again")
	}
}

func TestDirectoryAbsentRefusesNonEmpty(t *testing.T) {
	d := newDirTest(t)
	inside := filepath.Join(d.path, "data")
	if err := os.Mkdir(d.path, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(inside, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	resp := d.tryAbsent()
	if !resp.Diagnostics.HasErrors() || !strings.Contains(resp.Diagnostics.Err().Error(), "not empty") {
		t.Fatalf("apply over a directory with files in it: %v", resp.Diagnostics.Err())
	}
	if _, err := os.Stat(inside); err != nil {
		t.Fatalf("contents removed: %v", err)
	}
}

// A file, or a symlink even to a directory, is the wrong kind of thing and
// is left in place.
func TestDirectoryAbsentRefusesOtherKinds(t *testing.T) {
	for name, create := range map[string]func(string) error{
		"file":    func(p string) error { return os.WriteFile(p, []byte("x"), 0o644) },
		"symlink": func(p string) error { return os.Symlink(filepath.Dir(p), p) },
	} {
		t.Run(name, func(t *testing.T) {
			d := newDirTest(t)
			if err := create(d.path); err != nil {
				t.Fatal(err)
			}
			resp := d.tryAbsent()
			if !resp.Diagnostics.HasErrors() || !strings.Contains(resp.Diagnostics.Err().Error(), "not a directory") {
				t.Fatalf("apply over a %s: %v", name, resp.Diagnostics.Err())
			}
			if _, err := os.Lstat(d.path); err != nil {
				t.Fatalf("%s removed: %v", name, err)
			}
		})
	}
}

func TestDirectoryPresentToAbsent(t *testing.T) {
	d := newDirTest(t)
	cfg := d.config(nil)
	null := cty.NullVal(cfg.Type())
	state := d.apply(null, d.plan(null, cfg).PlannedState, cfg)

	cfg = d.config(absent)
	resp := d.plan(state, cfg)
	if len(resp.RequiresReplace) != 0 {
		t.Fatalf("RequiresReplace = %#v, want an update", resp.RequiresReplace)
	}
	state = d.apply(state, resp.PlannedState, cfg)
	if _, err := os.Lstat(d.path); !os.IsNotExist(err) {
		t.Fatal("directory still exists")
	}

	// And back: present creates it again, with in_sync no longer tracked.
	cfg = d.config(nil)
	state = d.apply(state, d.plan(state, cfg).PlannedState, cfg)
	if fi, err := os.Stat(d.path); err != nil || !fi.IsDir() {
		t.Fatalf("directory not created again: %v", err)
	}
	if !state.GetAttr("in_sync").IsNull() || state.GetAttr("mode").AsString() != "0755" {
		t.Fatalf("in_sync = %#v, mode = %#v", state.GetAttr("in_sync"), state.GetAttr("mode"))
	}
}

func TestDirectoryAbsentValidate(t *testing.T) {
	d := newDirTest(t)
	validate := func(attrs map[string]cty.Value) error {
		return d.p.ValidateResourceConfig(ctx, providers.ValidateResourceConfigRequest{TypeName: "conn3x_directory", Config: d.config(attrs)}).Diagnostics.Err()
	}
	if err := validate(absent); err != nil {
		t.Fatalf("state = absent alone: %v", err)
	}
	for _, attr := range []string{"mode", "owner", "group"} {
		attrs := map[string]cty.Value{"state": cty.StringVal("absent"), attr: cty.StringVal("0750")}
		if err := validate(attrs); err == nil || !strings.Contains(err.Error(), attr) {
			t.Errorf("%s with state = absent: err = %v", attr, err)
		}
	}
	if err := validate(map[string]cty.Value{"state": cty.StringVal("gone")}); err == nil {
		t.Error("state = \"gone\" accepted")
	}
	if err := validate(map[string]cty.Value{"state": cty.StringVal("present")}); err != nil {
		t.Errorf("state = present: %v", err)
	}
}

func TestDirectoryUnknownStatePlans(t *testing.T) {
	d := newDirTest(t)
	cfg := d.config(map[string]cty.Value{"state": cty.UnknownVal(cty.String)})
	planned := d.plan(cty.NullVal(cfg.Type()), cfg).PlannedState
	for _, attr := range []string{"mode", "in_sync"} {
		if planned.GetAttr(attr).IsKnown() {
			t.Errorf("%s = %#v, want unknown", attr, planned.GetAttr(attr))
		}
	}
}

func TestDirectoryUpgradesStateFromBeforeAbsent(t *testing.T) {
	old := `{"id":"h:/srv/app","path":"/srv/app","mode":"0755","owner":null,"group":null,"on_remove":"forget","ssh":null}`
	resp := upgradeWith(directorySchema)(providers.UpgradeResourceStateRequest{TypeName: "conn3x_directory", RawStateJSON: []byte(old)})
	if resp.Diagnostics.HasErrors() {
		t.Fatal(resp.Diagnostics.Err())
	}
	if !resp.UpgradedState.GetAttr("state").IsNull() || !resp.UpgradedState.GetAttr("in_sync").IsNull() {
		t.Fatalf("upgraded state = %#v", resp.UpgradedState)
	}
}
