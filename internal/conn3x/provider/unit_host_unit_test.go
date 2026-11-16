// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"strings"
	"sync"
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh/sshtest"
	"github.com/opentofu/opentofu/internal/providers"
)

// unitHost is a host over SSH, without the agent, whose shell is answer:
// each script a step runs goes to it, unquoted, instead of to sh, so a test
// can answer for tools the machine running it doesn't have. It returns the
// ssh block's attributes, for eosStep.
func unitHost(t *testing.T, answer func(script string) (string, int)) map[string]cty.Value {
	t.Helper()
	s := sshtest.New(t)
	s.SetExec(func(cmd string, _ []byte) (string, int) {
		return answer(strings.ReplaceAll(cmd, `'\''`, "'"))
	})
	return map[string]cty.Value{
		"host":             cty.StringVal(s.Host),
		"port":             cty.NumberIntVal(int64(s.Port)),
		"user":             cty.StringVal("root"),
		"private_key_file": cty.StringVal(s.KeyFile(t)),
		"known_hosts_file": cty.StringVal(s.KnownHosts(t)),
		"agent":            cty.False,
	}
}

// unitScripts answers each script with the reply of the first key it
// contains. A script no key matches exits 0 silently.
type unitScripts struct {
	mu      sync.Mutex
	replies [][2]string // contains, reply; a reply starting "!" fails with the rest as its output
}

func (u *unitScripts) on(contains, reply string) *unitScripts {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.replies = append([][2]string{{contains, reply}}, u.replies...)
	return u
}

func (u *unitScripts) answer(script string) (string, int) {
	u.mu.Lock()
	defer u.mu.Unlock()
	for _, r := range u.replies {
		if strings.Contains(script, r[0]) {
			if msg, failed := strings.CutPrefix(r[1], "!"); failed {
				return msg, 1
			}
			return r[1], 0
		}
	}
	return "", 0
}

// unitCreate plans and applies typeName from nothing to cfg through the
// provider, and returns the new state.
func unitCreate(t *testing.T, typeName string, cfg cty.Value) (cty.Value, error) {
	t.Helper()
	p, _ := New()
	null := cty.NullVal(cfg.Type())
	plan := p.PlanResourceChange(ctx, providers.PlanResourceChangeRequest{TypeName: typeName, PriorState: null, ProposedNewState: cfg, Config: cfg})
	if plan.Diagnostics.HasErrors() {
		t.Fatalf("plan %s: %v", typeName, plan.Diagnostics.Err())
	}
	resp := p.ApplyResourceChange(ctx, providers.ApplyResourceChangeRequest{TypeName: typeName, PriorState: null, PlannedState: plan.PlannedState, Config: cfg})
	return resp.NewState, resp.Diagnostics.Err()
}

// unitRead refreshes state through the provider.
func unitRead(typeName string, state cty.Value) (cty.Value, error) {
	p, _ := New()
	resp := p.ReadResource(ctx, providers.ReadResourceRequest{TypeName: typeName, PriorState: state})
	return resp.NewState, resp.Diagnostics.Err()
}
