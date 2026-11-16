// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/providers"
)

// brURI is a conn3x_uri config with attrs, reaching ssh.
func brURI(attrs map[string]cty.Value, ssh map[string]cty.Value) cty.Value {
	return eosStep("conn3x_uri", attrs, ssh)
}

func TestURIValidates(t *testing.T) {
	ssh := map[string]cty.Value{}
	codes := func(n ...int64) cty.Value {
		var vs []cty.Value
		for _, c := range n {
			vs = append(vs, cty.NumberIntVal(c))
		}
		return cty.ListVal(vs)
	}
	for want, attrs := range map[string]map[string]cty.Value{
		"":                              {"url": cty.StringVal("https://lb.example/register"), "method": cty.StringVal("post"), "status_codes": codes(200, 201)},
		`method "FETCH" must be`:        {"url": cty.StringVal("https://lb.example/"), "method": cty.StringVal("FETCH")},
		"set body or body_wo, not both": {"url": cty.StringVal("https://lb.example/"), "body": cty.StringVal("a"), "body_wo": cty.StringVal("b")},
		"must start with http://":       {"url": cty.StringVal("ftp://lb.example/")},
		"holds a user or password":      {"url": cty.StringVal("https://u:p@lb.example/")},
		"status code 700 is out of":     {"url": cty.StringVal("https://lb.example/"), "status_codes": codes(700)},
	} {
		d := validateURI(brURI(attrs, ssh))
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
	// An unknown url waits for apply; a null config has nothing to check.
	if d := validateURI(brURI(map[string]cty.Value{"url": cty.UnknownVal(cty.String), "method": cty.UnknownVal(cty.String)}, ssh)); d.HasErrors() {
		t.Errorf("unknown url: %v", d.Err())
	}
	if d := validateURI(cty.NullVal(uriSchema().Block.ImpliedType())); d.HasErrors() {
		t.Errorf("null: %v", d.Err())
	}
}

// A create calls from the host, with headers_wo and body_wo sent but kept
// out of state; an update or a removal calls nothing.
func TestURICallsOnCreateOnly(t *testing.T) {
	var mu sync.Mutex
	var calls []*http.Request
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		calls, bodies = append(calls, r), append(bodies, string(b))
		mu.Unlock()
		if r.URL.Path == "/gone" {
			w.WriteHeader(http.StatusNotFound)
		}
		_, _ = io.WriteString(w, "registered")
	}))
	defer srv.Close()
	made := func() int {
		mu.Lock()
		defer mu.Unlock()
		return len(calls)
	}
	ssh := unitHost(t, (&unitScripts{}).answer)
	cfg := brURI(map[string]cty.Value{
		"url":        cty.StringVal(srv.URL + "/register"),
		"method":     cty.StringVal("put"),
		"headers":    cty.MapVal(map[string]cty.Value{"Content-Type": cty.StringVal("application/json"), "Host": cty.StringVal("lb.internal")}),
		"headers_wo": cty.MapVal(map[string]cty.Value{"Authorization": cty.StringVal("Bearer s3cret")}),
		"body_wo":    cty.StringVal(`{"host":"web1"}`),
	}, ssh)
	state, err := unitCreate(t, "conn3x_uri", cfg)
	if err != nil {
		t.Fatal(err)
	}
	if n := made(); n != 1 {
		t.Fatalf("%d calls", n)
	}
	mu.Lock()
	r, body := calls[0], bodies[0]
	mu.Unlock()
	if r.Method != "PUT" || r.Host != "lb.internal" || r.Header.Get("Authorization") != "Bearer s3cret" || r.Header.Get("Content-Type") != "application/json" || body != `{"host":"web1"}` {
		t.Errorf("sent %s %s %v %q", r.Method, r.Host, r.Header, body)
	}
	if s, _ := state.GetAttr("status").AsBigFloat().Int64(); s != 200 || state.GetAttr("response").AsString() != "registered" {
		t.Errorf("state status %v response %v", state.GetAttr("status"), state.GetAttr("response"))
	}
	if !state.GetAttr("headers_wo").IsNull() || !state.GetAttr("body_wo").IsNull() {
		t.Error("a write-only value reached state")
	}

	p, _ := New()
	// Same arguments: the plan keeps the last answer and replaces nothing.
	plan := p.PlanResourceChange(ctx, providers.PlanResourceChangeRequest{TypeName: "conn3x_uri", PriorState: state, ProposedNewState: brURI(map[string]cty.Value{"url": state.GetAttr("url"), "method": state.GetAttr("method"), "headers": state.GetAttr("headers")}, ssh), Config: cfg})
	if plan.Diagnostics.HasErrors() || len(plan.RequiresReplace) != 0 || !plan.PlannedState.GetAttr("status").RawEquals(state.GetAttr("status")) {
		t.Errorf("unchanged plan: replace %v, status %v, %v", plan.RequiresReplace, plan.PlannedState.GetAttr("status"), plan.Diagnostics.Err())
	}
	if resp := p.ApplyResourceChange(ctx, providers.ApplyResourceChangeRequest{TypeName: "conn3x_uri", PriorState: state, PlannedState: plan.PlannedState, Config: cfg}); resp.Diagnostics.HasErrors() {
		t.Fatal(resp.Diagnostics.Err())
	}
	// A new trigger replaces the step and forgets the answer until apply.
	moved := brURI(map[string]cty.Value{"url": state.GetAttr("url"), "method": state.GetAttr("method"), "headers": state.GetAttr("headers"), "triggers": cty.StringVal("v2")}, ssh)
	plan = p.PlanResourceChange(ctx, providers.PlanResourceChangeRequest{TypeName: "conn3x_uri", PriorState: state, ProposedNewState: moved, Config: moved})
	if len(plan.RequiresReplace) != 1 || plan.PlannedState.GetAttr("status").IsKnown() {
		t.Errorf("triggered plan: replace %v, status %v", plan.RequiresReplace, plan.PlannedState.GetAttr("status"))
	}
	// An unknown url gives an unknown id.
	unknown := brURI(map[string]cty.Value{"url": cty.UnknownVal(cty.String)}, ssh)
	if plan := p.PlanResourceChange(ctx, providers.PlanResourceChangeRequest{TypeName: "conn3x_uri", PriorState: cty.NullVal(unknown.Type()), ProposedNewState: unknown, Config: unknown}); plan.PlannedState.GetAttr("id").IsKnown() {
		t.Errorf("id %v with an unknown url", plan.PlannedState.GetAttr("id"))
	}
	if plan := planURI(providers.PlanResourceChangeRequest{PriorState: state, ProposedNewState: cty.NullVal(state.Type())}); !plan.PlannedState.IsNull() {
		t.Error("planned a removal as something")
	}
	if resp := p.ApplyResourceChange(ctx, providers.ApplyResourceChangeRequest{TypeName: "conn3x_uri", PriorState: state, PlannedState: cty.NullVal(state.Type())}); resp.Diagnostics.HasErrors() {
		t.Fatal(resp.Diagnostics.Err())
	}
	if n := made(); n != 1 {
		t.Errorf("%d calls after an update and a removal, want 1", n)
	}

	// An answer outside status_codes fails the apply.
	gone := brURI(map[string]cty.Value{"url": cty.StringVal(srv.URL + "/gone")}, ssh)
	if _, err := unitCreate(t, "conn3x_uri", gone); err == nil || !strings.Contains(err.Error(), "404") {
		t.Errorf("a 404: %v", err)
	}
	// And so does a login that can't be made.
	away := map[string]cty.Value{}
	for k, v := range ssh {
		away[k] = v
	}
	away["private_key_file"] = cty.StringVal(filepath.Join(t.TempDir(), "missing"))
	null := cty.NullVal(cfg.Type())
	if resp := p.ApplyResourceChange(ctx, providers.ApplyResourceChangeRequest{TypeName: "conn3x_uri", PriorState: null, PlannedState: brURI(map[string]cty.Value{"url": cty.StringVal(srv.URL)}, away), Config: cfg}); !resp.Diagnostics.HasErrors() {
		t.Error("called over a login with a missing key")
	}
}
