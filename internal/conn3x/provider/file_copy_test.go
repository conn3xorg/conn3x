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

// A file step with source_path copies a file already on the host, plans
// clean once the copy matches, and plans a change when either file
// changes, with neither file's content in the plan or state (#1349).
func TestFileSourcePath(t *testing.T) {
	f := newFileTest(t)
	src := filepath.Join(f.server.Dir, "motd.sample")
	cfg := f.config(map[string]cty.Value{"source_path": cty.StringVal(src), "mode": cty.StringVal("0640"), "backup": cty.True, "validate": cty.StringVal("grep -q welcome %s")})
	null := cty.NullVal(cfg.Type())

	// Missing at plan is "will copy": an earlier step may make it.
	planned := f.plan(null, cfg).PlannedState
	if planned.GetAttr("sha256").IsKnown() || !planned.GetAttr("content").IsNull() {
		t.Fatalf("plan before the source exists: %#v", planned)
	}
	resp := f.p.ApplyResourceChange(ctx, providers.ApplyResourceChangeRequest{TypeName: "conn3x_file", PriorState: null, PlannedState: planned, Config: cfg})
	if err := resp.Diagnostics.Err(); err == nil || !strings.Contains(err.Error(), "source_path "+src+" doesn't exist on the host") {
		t.Fatalf("apply with the source missing: %v", err)
	}

	write := func(p, s string) {
		t.Helper()
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(src, "welcome\n")
	state := f.apply(null, planned, cfg)
	if got, _ := os.ReadFile(f.path); string(got) != "welcome\n" {
		t.Fatalf("copy = %q", got)
	}
	if !state.GetAttr("content").IsNull() || state.GetAttr("sha256").AsString() != sum("welcome\n") || state.GetAttr("source_sha256").AsString() != sum("welcome\n") || state.GetAttr("mode").AsString() != "0640" {
		t.Fatalf("state after apply: %#v", state)
	}

	read := f.read(state)
	if p := f.plan(read, cfg).PlannedState; !p.RawEquals(read) {
		t.Fatalf("second plan isn't clean:\n%#v\nwant\n%#v", p, read)
	}

	// A hand edit of the copy, then a change to the source, each plan a copy.
	write(f.path, "edited\n")
	if p := f.plan(f.read(state), cfg).PlannedState; p.GetAttr("sha256").IsKnown() {
		t.Fatalf("a hand edit planned no change: %#v", p)
	}
	write(f.path, "welcome\n")
	write(src, "welcome v2\n")
	read = f.read(state)
	planned = f.plan(read, cfg).PlannedState
	if planned.GetAttr("sha256").IsKnown() {
		t.Fatalf("a source change planned no change: %#v", planned)
	}
	state = f.apply(read, planned, cfg)
	if got, _ := os.ReadFile(f.path); string(got) != "welcome v2\n" || state.GetAttr("sha256").AsString() != sum("welcome v2\n") {
		t.Fatalf("after copying the new source: %q, %#v", got, state)
	}
	if b := state.GetAttr("backup_file"); b.IsNull() {
		t.Fatal("backup made no copy")
	} else if got, _ := os.ReadFile(b.AsString()); string(got) != "welcome\n" {
		t.Fatalf("backup = %q", got)
	}
	// validate still checks the copy before it goes in.
	write(src, "bad\n")
	read = f.read(state)
	planned = f.plan(read, cfg).PlannedState
	if err := f.applyErr(read, planned, cfg); !strings.Contains(err.Error(), "validate rejected") {
		t.Fatalf("validate: %v", err)
	}
	write(src, "welcome v2\n")
	state = read

	// A source that goes away plans a copy, and apply names it.
	if err := os.Remove(src); err != nil {
		t.Fatal(err)
	}
	read = f.read(state)
	if !read.GetAttr("source_sha256").IsNull() {
		t.Fatalf("source_sha256 with the source gone: %#v", read)
	}
	if p := f.plan(read, cfg).PlannedState; p.GetAttr("sha256").IsKnown() {
		t.Fatalf("a missing source planned no change: %#v", p)
	}
}

func TestFileSourcePathValidate(t *testing.T) {
	f := newFileTest(t)
	for name, tc := range map[string]struct {
		attrs map[string]cty.Value
		want  string
	}{
		"with content":    {map[string]cty.Value{"content": cty.StringVal("x"), "source_path": cty.StringVal("/etc/a")}, "set exactly one of content, content_wo and source_path"},
		"with content_wo": {map[string]cty.Value{"content_wo": cty.StringVal("x"), "source_path": cty.StringVal("/etc/a")}, "set exactly one of content, content_wo and source_path"},
		"none":            {map[string]cty.Value{}, "set exactly one of content, content_wo and source_path"},
		"relative":        {map[string]cty.Value{"source_path": cty.StringVal("etc/a")}, `source_path "etc/a" must be absolute`},
		"with absent":     {map[string]cty.Value{"state": cty.StringVal("absent"), "source_path": cty.StringVal("/etc/a")}, `source_path can't be set with state = "absent"`},
	} {
		t.Run(name, func(t *testing.T) {
			diags := validateFile(f.config(tc.attrs))
			if !diags.HasErrors() || !strings.Contains(diags.Err().Error(), tc.want) {
				t.Fatalf("got %v, want an error containing %q", diags.Err(), tc.want)
			}
		})
	}
	for _, attrs := range []map[string]cty.Value{
		{"source_path": cty.StringVal("/etc/a"), "backup": cty.True, "validate": cty.StringVal("test -s %s")},
		{"source_path": cty.UnknownVal(cty.String)},
	} {
		if diags := validateFile(f.config(attrs)); diags.HasErrors() {
			t.Errorf("%v refused: %v", attrs, diags.Err())
		}
	}
}
