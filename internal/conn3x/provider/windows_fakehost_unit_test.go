// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/conn3x/modules/windows/ps"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh/sshtest"
	"github.com/opentofu/opentofu/internal/providers"
)

// winFakeHost is a Windows host as far as the provider can tell: an SSH
// server whose PowerShell stub answers each module script from a table, so
// the resources run end to end with no PowerShell anywhere.
type winFakeHost struct {
	t    *testing.T
	conn cty.Value // the ssh block that reaches it

	mu      sync.Mutex
	answers map[string]func(args map[string]any) (any, string)
	calls   []winCall
}

// winRaw is an answer given as the stub's whole result, such as text and rc
// for a user's script, rather than as its value.
type winRaw map[string]any

type winCall struct {
	script string
	args   map[string]any
}

func newWinFakeHost(t *testing.T) *winFakeHost {
	t.Helper()
	s := sshtest.New(t)
	h := &winFakeHost{t: t, answers: map[string]func(map[string]any) (any, string){}}
	s.SetExec(h.run)
	conn := objFor(winFileSchema(), nil).GetAttr("ssh").AsValueMap()
	conn["host"], conn["port"], conn["user"] = cty.StringVal(s.Host), cty.NumberIntVal(int64(s.Port)), cty.StringVal("Administrator")
	conn["private_key_file"], conn["known_hosts_file"] = cty.StringVal(s.KeyFile(t)), cty.StringVal(s.KnownHosts(t))
	h.conn = cty.ObjectVal(conn)
	return h
}

// on answers every run of script with value.
func (h *winFakeHost) on(script string, value any) {
	h.onFunc(script, func(map[string]any) (any, string) { return value, "" })
}

// fail has every run of script throw msg.
func (h *winFakeHost) fail(script, msg string) {
	h.onFunc(script, func(map[string]any) (any, string) { return nil, msg })
}

func (h *winFakeHost) onFunc(script string, f func(args map[string]any) (any, string)) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.answers[script] = f
}

// sent returns the args of every run of script, in order.
func (h *winFakeHost) sent(script string) []map[string]any {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []map[string]any
	for _, c := range h.calls {
		if c.script == script {
			out = append(out, c.args)
		}
	}
	return out
}

// applied lists the apply scripts that ran, in order.
func (h *winFakeHost) applied() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []string
	for _, c := range h.calls {
		if strings.HasPrefix(c.script, "apply_") {
			out = append(out, c.script)
		}
	}
	return out
}

func (h *winFakeHost) run(command string, stdin []byte) (string, int) {
	if command != ps.Command {
		h.t.Errorf("a Windows step ran %.60q, not the PowerShell stub", command)
		return "", 1
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(stdin)))
	var in struct {
		Script string         `json:"script"`
		Args   map[string]any `json:"args"`
	}
	if err == nil {
		err = json.Unmarshal(raw, &in)
	}
	if err != nil {
		h.t.Errorf("the stub got %q: %v", stdin, err)
		return "", 1
	}
	// A user's own script, from windows_powershell, goes by its text.
	name, ok := winScriptNames()[in.Script]
	if !ok {
		name = in.Script
	}
	h.mu.Lock()
	h.calls = append(h.calls, winCall{name, in.Args})
	answer := h.answers[name]
	h.mu.Unlock()
	out := map[string]any{"ok": true}
	if answer == nil {
		h.t.Errorf("nothing answers %s (%v)", name, in.Args)
		out = map[string]any{"ok": false, "error": "no answer for " + name}
	} else if v, msg := answer(in.Args); msg != "" {
		out = map[string]any{"ok": false, "error": msg}
	} else if raw, ok := v.(winRaw); ok {
		for k, x := range raw {
			out[k] = x
		}
	} else {
		out["value"] = v
	}
	b, _ := json.Marshal(out)
	return "conn3x-result:" + base64.StdEncoding.EncodeToString(b) + "\r\n", 0
}

// winScriptNames maps each module script, as the stub receives it, to its
// file name. It expands #include lines the way the windows package does.
var winScriptNames = sync.OnceValue(func() map[string]string {
	dir := filepath.Join("..", "modules", "windows")
	include := regexp.MustCompile(`(?m)^#include ([a-z]+)\r?$`)
	files, _ := filepath.Glob(filepath.Join(dir, "*.ps1"))
	names := map[string]string{}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			panic(err)
		}
		body := include.ReplaceAllStringFunc(string(b), func(line string) string {
			lib, err := os.ReadFile(filepath.Join(dir, "lib", include.FindStringSubmatch(line)[1]+".ps1"))
			if err != nil {
				panic(err)
			}
			return string(lib)
		})
		names[body] = filepath.Base(f)
	}
	return names
})

// step builds a typeName object reaching this host, with attrs set and
// everything else null.
func (h *winFakeHost) step(typeName string, attrs map[string]cty.Value) cty.Value {
	vals := objFor(resourceTypes[typeName].schema(), attrs).AsValueMap()
	vals["ssh"] = h.conn
	return cty.ObjectVal(vals)
}

// plan plans cfg over prior the way core does, carrying computed values over.
func (h *winFakeHost) plan(typeName string, prior, cfg cty.Value) providers.PlanResourceChangeResponse {
	h.t.Helper()
	proposed := cfg
	if !prior.IsNull() {
		vals := cfg.AsValueMap()
		for name, a := range resourceTypes[typeName].schema().Block.Attributes {
			if a.Computed && vals[name].IsNull() {
				vals[name] = prior.GetAttr(name)
			}
		}
		proposed = cty.ObjectVal(vals)
	}
	resp := resourceTypes[typeName].plan(providers.PlanResourceChangeRequest{PriorState: prior, ProposedNewState: proposed, Config: cfg})
	if resp.Diagnostics.HasErrors() {
		h.t.Fatalf("plan %s: %v", typeName, resp.Diagnostics.Err())
	}
	return resp
}

// create plans and applies cfg from nothing, and returns the new state.
func (h *winFakeHost) create(typeName string, cfg cty.Value) cty.Value {
	h.t.Helper()
	if d := resourceTypes[typeName].validate(cfg); d.HasErrors() {
		h.t.Fatalf("validate %s: %v", typeName, d.Err())
	}
	planned := h.plan(typeName, cty.NullVal(cfg.Type()), cfg).PlannedState
	resp := resourceTypes[typeName].apply(context.Background(), providers.ApplyResourceChangeRequest{TypeName: typeName, PriorState: cty.NullVal(cfg.Type()), PlannedState: planned, Config: cfg})
	if resp.Diagnostics.HasErrors() {
		h.t.Fatalf("apply %s: %v", typeName, resp.Diagnostics.Err())
	}
	return resp.NewState
}

// read refreshes state.
func (h *winFakeHost) read(typeName string, state cty.Value) providers.ReadResourceResponse {
	h.t.Helper()
	return resourceTypes[typeName].read(context.Background(), providers.ReadResourceRequest{TypeName: typeName, PriorState: state})
}

// update plans cfg over prior and applies it.
func (h *winFakeHost) update(typeName string, prior, cfg cty.Value) providers.ApplyResourceChangeResponse {
	h.t.Helper()
	planned := h.plan(typeName, prior, cfg).PlannedState
	return resourceTypes[typeName].apply(context.Background(), providers.ApplyResourceChangeRequest{TypeName: typeName, PriorState: prior, PlannedState: planned, Config: cfg})
}

// destroy applies the removal of state.
func (h *winFakeHost) destroy(typeName string, state cty.Value) providers.ApplyResourceChangeResponse {
	h.t.Helper()
	null := cty.NullVal(state.Type())
	return resourceTypes[typeName].apply(context.Background(), providers.ApplyResourceChangeRequest{TypeName: typeName, PriorState: state, PlannedState: null, Config: null})
}

// winSynced reports a state's in_sync, failing on anything but a known bool.
func winSynced(t *testing.T, state cty.Value) bool {
	t.Helper()
	v := state.GetAttr("in_sync")
	if v.IsNull() || !v.IsKnown() {
		t.Fatalf("in_sync = %#v", v)
	}
	return v.True()
}
