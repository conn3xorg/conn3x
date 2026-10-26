// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/providers"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

// withConnAttrs returns state with some of its ssh attributes replaced.
func withConnAttrs(state cty.Value, attrs map[string]cty.Value) cty.Value {
	conn := state.GetAttr("ssh").AsValueMap()
	for k, v := range attrs {
		conn[k] = v
	}
	vals := state.AsValueMap()
	vals["ssh"] = cty.ObjectVal(conn)
	return cty.ObjectVal(vals)
}

// closedPort is a local port nothing listens on.
func closedPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port
}

// Issue #130: sshd moved to the port the configuration now names, so the
// port in state no longer answers. The refresh keeps state and warns, and
// the plan goes on with the configured port.
func TestRefreshKeepsStateWhenHostDoesNotAnswer(t *testing.T) {
	f := newFileTest(t)
	state := withConnAttrs(f.create("hello\n", nil), map[string]cty.Value{"port": cty.NumberIntVal(int64(closedPort(t)))})

	start := time.Now()
	resp := f.p.ReadResource(ctx, providers.ReadResourceRequest{TypeName: "conn3x_file", PriorState: state})
	if took := time.Since(start); took > readWait+2*time.Second {
		t.Fatalf("refresh took %s", took)
	}
	if resp.Diagnostics.HasErrors() {
		t.Fatal(resp.Diagnostics.Err())
	}
	if !resp.NewState.RawEquals(state) {
		t.Fatal("refresh changed the state of a host it couldn't reach")
	}
	if len(resp.Diagnostics) != 1 || resp.Diagnostics[0].Severity() != tfdiags.Warning ||
		resp.Diagnostics[0].Description().Summary != UnreachableSummary {
		t.Fatalf("want one %q warning, got %v", UnreachableSummary, resp.Diagnostics)
	}

	// The host's other steps don't wait for it again.
	start = time.Now()
	f.p.ReadResource(ctx, providers.ReadResourceRequest{TypeName: "conn3x_file", PriorState: state})
	if took := time.Since(start); took > time.Second {
		t.Fatalf("second refresh waited %s", took)
	}
}

// A host that answers with the wrong key is not unreachable: that error
// still fails the refresh.
func TestRefreshStillFailsOnWrongHostKey(t *testing.T) {
	f := newFileTest(t)
	state := f.create("hello\n", nil)
	other := newFileTest(t)
	state = withConnAttrs(state, map[string]cty.Value{"known_hosts_file": other.conn.GetAttr("known_hosts_file")})
	resp := f.p.ReadResource(ctx, providers.ReadResourceRequest{TypeName: "conn3x_file", PriorState: state})
	if !resp.Diagnostics.HasErrors() {
		t.Fatal("a host key mismatch was not an error")
	}
	if !strings.Contains(resp.Diagnostics.Err().Error(), "host key") {
		t.Fatalf("unexpected error: %v", resp.Diagnostics.Err())
	}
}

// A path to a host through a jump host that's down says nothing about
// another path to the same address: that one is still read.
func TestRefreshUnreachableIsPerPath(t *testing.T) {
	f := newFileTest(t)
	direct := f.create("hello\n", nil)
	jumped := withConnAttrs(direct, map[string]cty.Value{
		"jump_hosts": cty.ListVal([]cty.Value{cty.StringVal(fmt.Sprintf("test@127.0.0.1:%d", closedPort(t)))}),
	})
	resp := f.p.ReadResource(ctx, providers.ReadResourceRequest{TypeName: "conn3x_file", PriorState: jumped})
	if len(resp.Diagnostics) != 1 || resp.Diagnostics[0].Description().Summary != UnreachableSummary {
		t.Fatalf("want an unreachable warning through the jump host, got %v", resp.Diagnostics)
	}
	if !strings.Contains(resp.Diagnostics[0].Description().Detail, "jump") {
		t.Fatalf("warning doesn't mention the jump host: %s", resp.Diagnostics[0].Description().Detail)
	}
	resp = f.p.ReadResource(ctx, providers.ReadResourceRequest{TypeName: "conn3x_file", PriorState: direct})
	if len(resp.Diagnostics) != 0 {
		t.Fatalf("the direct path was skipped: %v", resp.Diagnostics)
	}
}

// Cancelling a refresh is not a host being down, and doesn't mark it so.
func TestRefreshCancelledIsNotUnreachable(t *testing.T) {
	f := newFileTest(t)
	state := withConnAttrs(f.create("hello\n", nil), map[string]cty.Value{"port": cty.NumberIntVal(int64(closedPort(t)))})
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	resp := f.p.ReadResource(cancelled, providers.ReadResourceRequest{TypeName: "conn3x_file", PriorState: state})
	for _, d := range resp.Diagnostics {
		if d.Description().Summary == UnreachableSummary {
			t.Fatal("a cancelled refresh reported the host unreachable")
		}
	}
}
