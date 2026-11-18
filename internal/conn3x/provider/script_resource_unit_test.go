// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/conn3x/modules/script"
	"github.com/opentofu/opentofu/internal/providers"
)

// kvProgram keeps a file's contents equal to args.value. With args.leak it
// also returns its args_wo in state, as a careless module might.
const kvProgram = `#!/bin/sh
in=$(cat)
f=$(printf '%s' "$in" | sed -n 's/.*"path":"\([^"]*\)".*/\1/p')
want=$(printf '%s' "$in" | sed -n 's/.*"args":{"path":"[^"]*","value":"\([^"]*\)".*/\1/p')
have=$(cat "$f" 2>/dev/null)
case "$in" in
*'"mode":"read"'*) printf '{"state":{"value":"%s"}}\n' "$have" ;;
*'"mode":"plan"'*) if [ "$have" = "$want" ]; then echo '{"in_sync":true,"changes":[]}'; else printf '{"in_sync":false,"changes":[{"path":"value","before":"%s","after":"%s"}]}\n' "$have" "$want"; fi ;;
*'"mode":"apply"'*)
  printf '%s' "$want" > "$f"
  case "$in" in *'"leak":true'*) tok=$(printf '%s' "$in" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p'); printf '{"state":{"value":"%s","token":"%s"},"changed":true}\n' "$want" "$tok" ;;
  *) printf '{"state":{"value":"%s"},"changed":true}\n' "$want" ;; esac ;;
*'"mode":"remove"'*) rm -f "$f"; echo '{}' ;;
esac
`

func TestScriptStep(t *testing.T) {
	ssh, dir := brShellHost(t)
	saved := script.Dir
	script.Dir = filepath.Join(dir, "modules")
	t.Cleanup(func() { script.Dir = saved })
	path := filepath.Join(dir, "app.env")
	cfg := func(value string, extra map[string]cty.Value) cty.Value {
		a := map[string]cty.Value{
			"program":     cty.StringVal(kvProgram),
			"interpreter": cty.ListVal([]cty.Value{cty.StringVal("sh")}),
			"args":        cty.StringVal(`{"path":"` + path + `","value":"` + value + `"}`),
			"args_wo":     cty.StringVal(`{"token":"s3cret-token"}`),
		}
		for k, v := range extra {
			a[k] = v
		}
		return eosStep("conn3x_script", a, ssh)
	}
	// What core proposes: the config with write-only values null.
	proposed := func(c cty.Value) cty.Value {
		return brWith(c, map[string]cty.Value{"args_wo": cty.NullVal(cty.String)})
	}
	p, _ := New()
	create := func(c cty.Value) (providers.PlanResourceChangeResponse, providers.ApplyResourceChangeResponse) {
		null := cty.NullVal(c.Type())
		plan := p.PlanResourceChange(ctx, providers.PlanResourceChangeRequest{TypeName: "conn3x_script", PriorState: null, ProposedNewState: proposed(c), Config: c})
		if plan.Diagnostics.HasErrors() {
			t.Fatalf("plan: %v", plan.Diagnostics.Err())
		}
		return plan, p.ApplyResourceChange(ctx, providers.ApplyResourceChangeRequest{TypeName: "conn3x_script", PriorState: null, PlannedState: plan.PlannedState, Config: c})
	}

	c := cfg("prod", nil)
	plan, apply := create(c)
	for _, name := range []string{"state", "changes"} {
		if plan.PlannedState.GetAttr(name).IsKnown() {
			t.Errorf("%s is known on create; apply sets it", name)
		}
	}
	if !plan.PlannedState.GetAttr("args_wo").IsNull() {
		t.Error("args_wo planned non-null")
	}
	if apply.Diagnostics.HasErrors() {
		t.Fatal(apply.Diagnostics.Err())
	}
	state := apply.NewState
	if b, _ := os.ReadFile(path); string(b) != "prod" {
		t.Fatalf("file %q", b)
	}
	if !state.GetAttr("args_wo").IsNull() || strings.Contains(state.GoString(), "s3cret") {
		t.Fatal("args_wo reached state")
	}

	// A re-read is in sync; a hand edit isn't, and shows the change.
	if read, err := unitRead("conn3x_script", state); err != nil || !read.GetAttr("in_sync").True() {
		t.Fatalf("re-read: %v, %v", read, err)
	}
	if err := os.WriteFile(path, []byte("dev"), 0o644); err != nil {
		t.Fatal(err)
	}
	read, err := unitRead("conn3x_script", state)
	if err != nil || read.GetAttr("in_sync").True() || !strings.Contains(read.GetAttr("changes").AsString(), `"before":"dev"`) {
		t.Fatalf("after an edit: %v, %v", read, err)
	}

	// Editing the program plans an update, through program_sha256.
	edited := brWith(c, map[string]cty.Value{"program": cty.StringVal(kvProgram + "# edited\n")})
	again := p.PlanResourceChange(ctx, providers.PlanResourceChangeRequest{TypeName: "conn3x_script", PriorState: state, ProposedNewState: proposed(edited), Config: edited})
	if again.PlannedState.GetAttr("in_sync").IsKnown() || again.PlannedState.GetAttr("program_sha256").RawEquals(state.GetAttr("program_sha256")) {
		t.Error("an edited program didn't plan an update")
	}

	// A program that returns its args_wo in state fails, and nothing is saved.
	_, leak := create(cfg("prod", map[string]cty.Value{"args": cty.StringVal(`{"path":"` + path + `","value":"prod","leak":true}`)}))
	if !leak.Diagnostics.HasErrors() || !strings.Contains(leak.Diagnostics.Err().Error(), "args_wo value") {
		t.Fatalf("a leaking program: %v", leak.Diagnostics.Err())
	}
	if !leak.NewState.IsNull() && strings.Contains(leak.NewState.GoString(), "s3cret") {
		t.Fatal("the leaked value was saved")
	}
}
