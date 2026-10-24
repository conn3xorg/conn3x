// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh/sshtest"
	"github.com/opentofu/opentofu/internal/providers"
)

var ctx = context.Background()

type fileTest struct {
	t      *testing.T
	p      providers.Interface
	server *sshtest.Server
	conn   cty.Value
	path   string
}

func newFileTest(t *testing.T) *fileTest {
	t.Helper()
	s := sshtest.New(t)
	p, _ := New()
	return &fileTest{
		t:      t,
		p:      p,
		server: s,
		path:   filepath.Join(s.Dir, "motd"),
		conn: cty.ObjectVal(map[string]cty.Value{
			"host":             cty.StringVal(s.Host),
			"port":             cty.NumberIntVal(int64(s.Port)),
			"user":             cty.StringVal("test"),
			"private_key_file": cty.StringVal(s.KeyFile(t)),
			"host_key":         cty.NullVal(cty.String),
			"known_hosts_file": cty.StringVal(s.KnownHosts(t)),
		}),
	}
}

// config builds a conn3x_file object with the given attributes set and
// everything else null.
func (f *fileTest) config(attrs map[string]cty.Value) cty.Value {
	ty := fileSchema().Block.ImpliedType()
	vals := map[string]cty.Value{}
	for name, at := range ty.AttributeTypes() {
		vals[name] = cty.NullVal(at)
	}
	vals["path"] = cty.StringVal(f.path)
	vals["connection"] = f.conn
	for k, v := range attrs {
		vals[k] = v
	}
	return cty.ObjectVal(vals)
}

func (f *fileTest) plan(prior, config cty.Value) providers.PlanResourceChangeResponse {
	f.t.Helper()
	// Core proposes the config with computed attributes carried over from prior.
	proposed := config
	if !prior.IsNull() && !config.IsNull() {
		vals := config.AsValueMap()
		for _, name := range []string{"id", "sha256", "mode", "on_remove"} {
			if vals[name].IsNull() {
				vals[name] = prior.GetAttr(name)
			}
		}
		proposed = cty.ObjectVal(vals)
	}
	resp := f.p.PlanResourceChange(ctx, providers.PlanResourceChangeRequest{
		TypeName: "conn3x_file", PriorState: prior, ProposedNewState: proposed, Config: config,
	})
	if resp.Diagnostics.HasErrors() {
		f.t.Fatalf("plan: %s", resp.Diagnostics.Err())
	}
	return resp
}

func (f *fileTest) apply(prior, planned, config cty.Value) cty.Value {
	f.t.Helper()
	resp := f.p.ApplyResourceChange(ctx, providers.ApplyResourceChangeRequest{
		TypeName: "conn3x_file", PriorState: prior, PlannedState: planned, Config: config,
	})
	if resp.Diagnostics.HasErrors() {
		f.t.Fatalf("apply: %s", resp.Diagnostics.Err())
	}
	return resp.NewState
}

func (f *fileTest) read(prior cty.Value) cty.Value {
	f.t.Helper()
	resp := f.p.ReadResource(ctx, providers.ReadResourceRequest{TypeName: "conn3x_file", PriorState: prior})
	if resp.Diagnostics.HasErrors() {
		f.t.Fatalf("read: %s", resp.Diagnostics.Err())
	}
	return resp.NewState
}

func (f *fileTest) create(content string, extra map[string]cty.Value) cty.Value {
	attrs := map[string]cty.Value{"content": cty.StringVal(content)}
	for k, v := range extra {
		attrs[k] = v
	}
	cfg := f.config(attrs)
	null := cty.NullVal(cfg.Type())
	planned := f.plan(null, cfg).PlannedState
	return f.apply(null, planned, cfg)
}

func sum(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func TestSchemaHasFile(t *testing.T) {
	p, _ := New()
	schema := p.GetProviderSchema(ctx)
	s, ok := schema.ResourceTypes["conn3x_file"]
	if !ok {
		t.Fatal("conn3x_file missing from schema")
	}
	if err := s.Block.InternalValidate(); err != nil {
		t.Fatalf("invalid schema: %v", err)
	}
}

func TestPlanCreateFillsDefaults(t *testing.T) {
	f := newFileTest(t)
	cfg := f.config(map[string]cty.Value{"content": cty.StringVal("hello\n")})
	planned := f.plan(cty.NullVal(cfg.Type()), cfg).PlannedState
	if got := planned.GetAttr("mode"); !got.RawEquals(cty.StringVal("0644")) {
		t.Errorf("mode = %#v", got)
	}
	if got := planned.GetAttr("on_remove"); !got.RawEquals(cty.StringVal("forget")) {
		t.Errorf("on_remove = %#v", got)
	}
	if got := planned.GetAttr("sha256"); !got.RawEquals(cty.StringVal(sum("hello\n"))) {
		t.Errorf("sha256 = %#v", got)
	}
	if _, err := os.Stat(f.path); !os.IsNotExist(err) {
		t.Fatal("plan wrote to the host")
	}
}

func TestApplyThenReadRoundTrip(t *testing.T) {
	f := newFileTest(t)
	state := f.create("hello\n", nil)
	got, err := os.ReadFile(f.path)
	if err != nil || string(got) != "hello\n" {
		t.Fatalf("file content %q, %v", got, err)
	}
	read := f.read(state)
	if !read.RawEquals(state) {
		t.Fatalf("read changed state:\n%#v\nwant\n%#v", read, state)
	}
}

func TestReadDetectsDrift(t *testing.T) {
	f := newFileTest(t)
	state := f.create("hello\n", nil)
	if err := os.WriteFile(f.path, []byte("hacked\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	read := f.read(state)
	if got := read.GetAttr("content").AsString(); got != "hacked\n" {
		t.Fatalf("content after drift = %q", got)
	}
	cfg := f.config(map[string]cty.Value{"content": cty.StringVal("hello\n")})
	planned := f.plan(read, cfg).PlannedState
	if planned.GetAttr("content").AsString() != "hello\n" || planned.GetAttr("sha256").AsString() != sum("hello\n") {
		t.Fatalf("drift not planned back: %#v", planned)
	}
}

func TestReadMissingFileIsNull(t *testing.T) {
	f := newFileTest(t)
	state := f.create("x", nil)
	_ = os.Remove(f.path)
	if read := f.read(state); !read.IsNull() {
		t.Fatalf("read of a deleted file = %#v, want null", read)
	}
}

func TestDeleteForgetsByDefault(t *testing.T) {
	f := newFileTest(t)
	state := f.create("keep me", nil)
	newState := f.apply(state, cty.NullVal(state.Type()), cty.NullVal(state.Type()))
	if !newState.IsNull() {
		t.Fatal("destroy returned a non-null state")
	}
	if _, err := os.Stat(f.path); err != nil {
		t.Fatalf("file removed although on_remove defaults to forget: %v", err)
	}
}

func TestDeleteWithOnRemoveDelete(t *testing.T) {
	f := newFileTest(t)
	state := f.create("bye", map[string]cty.Value{"on_remove": cty.StringVal("delete")})
	f.apply(state, cty.NullVal(state.Type()), cty.NullVal(state.Type()))
	if _, err := os.Stat(f.path); !os.IsNotExist(err) {
		t.Fatal("file still exists with on_remove = delete")
	}
}

func TestPathChangeRequiresReplace(t *testing.T) {
	f := newFileTest(t)
	state := f.create("x", nil)
	f.path = filepath.Join(f.server.Dir, "other")
	cfg := f.config(map[string]cty.Value{"content": cty.StringVal("x")})
	resp := f.plan(state, cfg)
	found := false
	for _, p := range resp.RequiresReplace {
		if step, ok := p[0].(cty.GetAttrStep); ok && len(p) == 1 && step.Name == "path" {
			found = true
		}
	}
	if !found {
		t.Fatalf("RequiresReplace = %#v, want path", resp.RequiresReplace)
	}
}

func TestValidateRejectsBadInput(t *testing.T) {
	f := newFileTest(t)
	for name, attrs := range map[string]map[string]cty.Value{
		"on_remove": {"content": cty.StringVal("x"), "on_remove": cty.StringVal("purge")},
		"mode":      {"content": cty.StringVal("x"), "mode": cty.StringVal("rw-r--r--")},
		"path":      {"content": cty.StringVal("x"), "path": cty.StringVal("relative/motd")},
	} {
		resp := f.p.ValidateResourceConfig(ctx, providers.ValidateResourceConfigRequest{TypeName: "conn3x_file", Config: f.config(attrs)})
		if !resp.Diagnostics.HasErrors() {
			t.Errorf("%s: invalid value accepted", name)
		}
	}
}

func TestUnknownHostKeyIsAClearError(t *testing.T) {
	f := newFileTest(t)
	empty := filepath.Join(t.TempDir(), "known_hosts")
	_ = os.WriteFile(empty, nil, 0o600)
	vals := f.conn.AsValueMap()
	vals["known_hosts_file"] = cty.StringVal(empty)
	f.conn = cty.ObjectVal(vals)
	cfg := f.config(map[string]cty.Value{"content": cty.StringVal("x")})
	null := cty.NullVal(cfg.Type())
	planned := f.plan(null, cfg).PlannedState
	resp := f.p.ApplyResourceChange(ctx, providers.ApplyResourceChangeRequest{TypeName: "conn3x_file", PriorState: null, PlannedState: planned, Config: cfg})
	if !resp.Diagnostics.HasErrors() {
		t.Fatal("apply succeeded with an unknown host key")
	}
	msg := resp.Diagnostics.Err().Error()
	if !strings.Contains(msg, f.server.Host) || !strings.Contains(msg, "known_hosts") {
		t.Fatalf("error does not name the host and file: %s", msg)
	}
}
