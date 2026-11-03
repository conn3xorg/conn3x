// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"os"
	"strings"
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/providers"
)

func (f *fileTest) applyErr(prior, planned, config cty.Value) error {
	f.t.Helper()
	resp := f.p.ApplyResourceChange(ctx, providers.ApplyResourceChangeRequest{
		TypeName: "conn3x_file", PriorState: prior, PlannedState: planned, Config: config,
	})
	if !resp.Diagnostics.HasErrors() {
		f.t.Fatal("apply succeeded, want an error")
	}
	return resp.Diagnostics.Err()
}

func TestFileValidateConfig(t *testing.T) {
	f := newFileTest(t)
	for name, tc := range map[string]struct {
		attrs map[string]cty.Value
		want  string
	}{
		"missing placeholder": {map[string]cty.Value{"content": cty.StringVal("x"), "validate": cty.StringVal("visudo -c")}, "must contain %s"},
		"with absent":         {map[string]cty.Value{"state": cty.StringVal("absent"), "validate": cty.StringVal("visudo -cf %s")}, `validate can't be set with state = "absent"`},
	} {
		t.Run(name, func(t *testing.T) {
			diags := validateFile(f.config(tc.attrs))
			if !diags.HasErrors() || !strings.Contains(diags.Err().Error(), tc.want) {
				t.Fatalf("got %v, want an error containing %q", diags.Err(), tc.want)
			}
		})
	}
	if diags := validateFile(f.config(map[string]cty.Value{"content": cty.StringVal("x"), "validate": cty.StringVal("visudo -cf %s")})); diags.HasErrors() {
		t.Fatalf("a good validate was refused: %v", diags.Err())
	}
}

func TestFileValidateStaysOutOfPlanAndState(t *testing.T) {
	f := newFileTest(t)
	state := f.create("ok\n", nil)

	// Adding validate to a step whose file is already right changes nothing.
	cfg := f.config(map[string]cty.Value{"content": cty.StringVal("ok\n"), "validate": cty.StringVal("grep -qx ok %s")})
	read := f.read(state)
	planned := f.plan(read, cfg).PlannedState
	if !planned.RawEquals(read) {
		t.Fatalf("adding validate planned a change:\n%#v\nwant\n%#v", planned, read)
	}

	cfg = f.config(map[string]cty.Value{"content": cty.StringVal("ok\nok\n"), "validate": cty.StringVal("grep -qx ok %s")})
	planned = f.plan(read, cfg).PlannedState
	if !planned.GetAttr("validate").IsNull() {
		t.Fatal("validate reached the plan")
	}
	state = f.apply(read, planned, cfg)
	if !state.GetAttr("validate").IsNull() {
		t.Fatal("validate reached state")
	}
	if got, _ := os.ReadFile(f.path); string(got) != "ok\nok\n" {
		t.Fatalf("host file = %q", got)
	}
}

func TestFileValidateFailureKeepsFile(t *testing.T) {
	f := newFileTest(t)
	state := f.read(f.create("old\n", nil))
	cfg := f.config(map[string]cty.Value{"content": cty.StringVal("bad\n"), "validate": cty.StringVal("echo 'parse error near line 1' >&2; grep -qx ok %s")})
	err := f.applyErr(state, f.plan(state, cfg).PlannedState, cfg)
	if !strings.Contains(err.Error(), "parse error near line 1") || !strings.Contains(err.Error(), "left as it was") {
		t.Fatalf("error %q should say the file was kept and show the command's output", err)
	}
	if got, _ := os.ReadFile(f.path); string(got) != "old\n" {
		t.Fatalf("the original was replaced: %q", got)
	}
}

func TestFileValidateWriteOnlyHidesOutput(t *testing.T) {
	f := newWOTest(t)
	cfg := f.config(map[string]cty.Value{"content_wo": cty.StringVal("s3cret\n"), "validate": cty.StringVal("cat %s; exit 1")})
	null := cty.NullVal(cfg.Type())
	err := f.applyErr(null, f.plan(null, cfg).PlannedState, cfg)
	if strings.Contains(err.Error(), "s3cret") {
		t.Fatalf("the secret reached the error: %q", err)
	}
	if !strings.Contains(err.Error(), "write-only") {
		t.Fatalf("error %q should say why the output is hidden", err)
	}
	if _, statErr := os.Stat(f.path); !os.IsNotExist(statErr) {
		t.Fatal("the rejected file was written")
	}
}

func TestFileValidateSkippedWhenContentUnchanged(t *testing.T) {
	f := newFileTest(t)
	state := f.read(f.create("ok\n", nil))
	// A mode-only change leaves the content alone, so a validate that would
	// fail never runs.
	cfg := f.config(map[string]cty.Value{"content": cty.StringVal("ok\n"), "mode": cty.StringVal("0600"), "validate": cty.StringVal("false %s")})
	f.apply(state, f.plan(state, cfg).PlannedState, cfg)
	info, err := os.Stat(f.path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("mode not changed: %v, %v", info, err)
	}
}
